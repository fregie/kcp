#include "args.h"
#include "action.h"

#include <signal.h>

static void sig_handler(int signo) {
    system("sh ./samples/client_down.sh");
    exit(0);
}

int check_header(char *token, unsigned char *buf, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    process_message(buf, data_block, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    if (data_block[0] != 1){
        errf("version check failed");
        free(data_block);
        return 1;
    }else if(strcmp(token, data_block+1) != 0){
        errf("unknow token");
        free(data_block);
        return 2;
    }else{
        free(data_block);
        return 0;
    }
}

char* header_key_parse(char *password, char *header_key){
    char *decode_header_key = b64_decode(header_key, 8);
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));
    generate_sub_keys(password, key_sets);
    process_message(decode_header_key, data_block, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    return data_block;
}

int main(int argc, char **argv){
    int ch;
    char *conf_file = NULL;
    char *header_key = NULL;
    while ((ch = getopt(argc, argv, "hc:")) != -1){
        switch (ch){
        case 'c':
            conf_file = strdup(optarg);
            break;
        case 'k':
            header_key = strdup(optarg);
        default:
            print_help();
            break;
        }
    }
    if (argc == 1 || conf_file == NULL){
        print_help();
        return EXIT_FAILURE;
    }
    //init gts_args
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_CLIENT;
    int length;
    printf("GTS-client start.....\n");
    if (-1 == init_gts_args(gts_args, conf_file)){
        printf("init client failed!");
        return EXIT_FAILURE;
    }
    if(init_log_file(gts_args->log_file) == -1){
        errf("init log_file failed!");
    }
    if (header_key != NULL){
        gts_args->header_key = header_key_parse(gts_args->password, header_key);
    }
    free(header_key);
    set_env(gts_args);
/*    pid_t pid = getpid();
    if (0 != write_pid_file(gts_args->pid_file, pid)) {
        return EXIT_FAILURE;
    }*/
    //make encrypted_header
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));
    generate_sub_keys(gts_args->header_key, key_sets);
    unsigned char* encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], key_sets);
    //init crypto
    if (0 != crypto_init()) {
        errf("GTS_crypto_init failed");
        return EXIT_FAILURE;
    }
    if (0 !=crypto_set_password(gts_args->password[0], strlen(gts_args->password[0]))) {
        errf("can not set password");
        return EXIT_FAILURE;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    // init GTSc_tun
    gts_args->tun = tun_create(gts_args->intf);
     if (gts_args->tun < 0){
        errf("tun create failed!");
        return EXIT_FAILURE;
    }else{
        system(gts_args->shell_up);
    }
    // init UDP_sock
    struct sockaddr_in server_addr;
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    
    fd_set readset;
    while (gts_args->ver == 1){
        readset = init_select(gts_args);    //select udp_socket and tun
        
        bzero(gts_args->udp_buf, gts_args->mtu + GTS_HEADER_LEN);
        bzero(gts_args->tun_buf, gts_args->mtu + GTS_HEADER_LEN);
        
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
                            
            if (check_header(gts_args->token[0], gts_args->udp_buf, key_sets) != 0){
                continue;
            }
            if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                    length - GTS_HEADER_LEN)){
                errf("dropping invalid packet, maybe wrong password");
            }
            write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
        }
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, gts_args->mtu);
            crypto_encrypt(gts_args->udp_buf, gts_args->tun_buf, length);
            memcpy(gts_args->udp_buf, encrypted_header, VER_LEN+TOKEN_LEN);
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + GTS_HEADER_LEN, 0,
                  (struct sockaddr*)&gts_args->server_addr,
                  (socklen_t)sizeof(gts_args->server_addr));
        }
    }
    
    close(gts_args->UDP_sock);
    return 0;
}