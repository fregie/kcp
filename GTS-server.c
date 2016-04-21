#include "args.h"
#include "action.h"
#include <signal.h>


static void sig_handler(int signo) {
    system("sh ./samples/server_down.sh");
    exit(0);
}

int main() {
    //init gts_args
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_SERVER;
    
    int length; //length of buffer recieved
    int nonce_fd = open("/dev/urandom", O_RDONLY);
    init_gts_args(gts_args);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    //init UDP_sock and GTSs_tun
    gts_args->UDP_sock = init_UDP_socket(gts_args->server,gts_args->port);
    gts_args->tun = tun_create(gts_args->intf);
    if (gts_args->tun < 0){
        printf("tun create failed!");
        return 1;
    }else{
        system(gts_args->shell_up);
    }
    fd_set readset;
    while (gts_args->ver == 1){
        printf("start listening.....\n");
        readset = init_select(gts_args);    //select udp_socket and tun
        
        bzero(gts_args->udp_buf, gts_args->mtu + gts_args->GTS_header_len);
        //recv data from client
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + gts_args->GTS_header_len, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
            write(gts_args->tun, gts_args->tun_buf, length - gts_args->GTS_header_len);
            printf("back:%dbyte\n",length);
        }
        // recv data from tun
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->tun_buf, gts_args->mtu);
            read(nonce_fd, gts_args->udp_buf + gts_args->ver_len + gts_args->token_len, gts_args->nonce_len);
 
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + gts_args->GTS_header_len, 0,
                  (struct sockaddr*)&gts_args->remote_addr,
                  (socklen_t)gts_args->remote_addr_len);
            printf("to:%dbyte\n",length);
        }
        
    }
    close(gts_args->UDP_sock);
    free(gts_args);
    return 0;
}