#include "args.h"
#include "action.h"

#include <signal.h>

static void sig_handler(int signo) {
    system("sh ./samples/client_down.sh");
    exit(0);
}

int check_header(char *token, unsigned char *buf, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    process_message(data_block, buf, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    if (data_block[0] != 1){
        printf("version check failed");
        return 1;
    }else if(strcmp(token, data_block+1) != 0){
        printf("unknow token");
        return 2;
    }else{
        return 0;
    }
}

int main(int argc, char **argv){
    //init gts_args
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_CLIENT;
    int length;
    int nonce_fd = open("/dev/urandom", O_RDONLY);
    
    if (-1 == init_gts_args(gts_args)){
        printf("init client failed!");
    }
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));
    generate_sub_keys(gts_args->header_key, key_sets);
    unsigned char* encrypted_header = encrypt_GTS_header(gts_args, key_sets);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
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
    while (gts_args->ver == 1){
        printf("waiting data.....data length:");
        readset = init_select(gts_args);    //select udp_socket and tun
        
        bzero(gts_args->udp_buf, gts_args->mtu + gts_args->GTS_header_len);
        
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + gts_args->GTS_header_len, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
                            
            // if (check_header(gts_args->token, gts_args->udp_buf, key_sets) != 0){
            //     continue;
            // }
            write(gts_args->tun, gts_args->tun_buf, length - gts_args->GTS_header_len);
            printf("%dbyte\n",length);
        }
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->tun_buf, gts_args->mtu);
            memcpy(gts_args->udp_buf, encrypted_header, gts_args->ver_len + gts_args->token_len);
            read(nonce_fd, gts_args->udp_buf + gts_args->ver_len + gts_args->token_len,gts_args->nonce_len);
                
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + gts_args->GTS_header_len, 0,
                  (struct sockaddr*)&gts_args->server_addr,
                  (socklen_t)sizeof(gts_args->server_addr));
            printf("%dbyte\n",length);
        }
    }
    
    close(gts_args->UDP_sock);
    close(nonce_fd);
    return 0;
}