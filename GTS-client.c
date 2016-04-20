#include "args.h"
#include "action.h"

int main(){
    //init gts_args
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_CLIENT;
    int length;
    int nonce_fd = open("/dev/urandom", O_RDONLY);
    
    init_gts_args(gts_args);
    set_GTS_header(gts_args);
    
    // init GTSc_tun
    gts_args->tun = tun_create(gts_args->intf);
     if (gts_args->tun < 0){
        printf("tun create failed!");
        return 1;
    }else{
        system(gts_args->shell_up);
    }
    // init UDP_sock
    struct sockaddr_in server_addr;
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    
    fd_set readset;
    while (1){
        printf("waiting data.....data length:");
        readset = init_select(gts_args);    //select udp_socket and tun
        
        bzero(gts_args->udp_buf, gts_args->mtu + gts_args->GTS_header_len);
        
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + gts_args->GTS_header_len, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
            write(gts_args->tun, gts_args->tun_buf, length - gts_args->GTS_header_len);
            printf("%dbyte\n",length);
        }
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->tun_buf, gts_args->mtu);
            read(nonce_fd, gts_args->udp_buf+8, gts_args->nonce_len);
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + gts_args->GTS_header_len, 0,
                  (struct sockaddr*)&gts_args->server_addr,
                  (socklen_t)sizeof(gts_args->server_addr));
            printf("%dbyte\n",length);
        }
    }
    
    close(gts_args->UDP_sock);
    close(nonce_fd);
    free(gts_args);
    return 0;
}