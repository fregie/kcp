#include "args.h"
#include "action.h"

#include <signal.h>

char *shell_down;
uint8_t stat_code = 0;
    /*
    return client status:
    0..........status OK
    1..........wrong token
    2..........wrong password
    3..........wrong header_key
    */

static void sig_handler(int signo) {
    if (access(shell_down, R_OK) == -1){
        errf("GTS down script can't find");
        exit(0);
    }
    system(shell_down);
    exit(0);
}
int check_header(char *token, unsigned char *buf, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    process_message(buf, data_block, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    // print_hex_memory(data_block, 8);
    if (data_block[0] != 1){
        stat_code = 3;
        errf("version check failed");
        free(data_block);
        return 1;
    }else if(memcmp(token, data_block+1, TOKEN_LEN) != 0){
        stat_code = 1;
        errf("unknow token");
        free(data_block);
        return 2;
    }else{
        free(data_block);
        return 0;
    }
}

unsigned char* header_key_parse(char *password, char *header_key){
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
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
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
        if (access(gts_args->shell_up, R_OK) == -1){
            errf("GTS up script can't find");
            return EXIT_FAILURE;
        }
        char *cmd = malloc(strlen(gts_args->shell_up) +8);
        sprintf(cmd, "sh %s", gts_args->shell_up);
        system(cmd);
    }
    // init UDP_sock
    struct sockaddr_in server_addr;
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    gts_args->IPC_sock = init_IPC_socket();
    
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
            if (gts_args->udp_buf[0] == 78){
                stat_code = gts_args->udp_buf[1];
                continue;
            }
                            
            if (check_header(gts_args->token[0], gts_args->udp_buf, key_sets) != 0){
                continue;
            }
            if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                    length - GTS_HEADER_LEN)){
                stat_code = 2;
                errf("dropping invalid packet, maybe wrong password");
            }
            write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
            stat_code = 0;
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
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
            char rx_buf[500];
            struct sockaddr_un pmapi_addr;
            int len = sizeof(pmapi_addr);
            int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0, (struct sockaddr*)&pmapi_addr, &len);
            char *act;
            cJSON *json;
            json = cJSON_Parse(rx_buf);
            if(!json){
                errf("request parse failed");
                continue;
            }
            act = strdup(cJSON_GetObjectItem(json,"act")->valuestring);
            if (strcmp(act,"show_stat") == 0){
                char *msg = malloc(20);
                sprintf(msg, "{\"stat\":%d}", stat_code);
                sendto(gts_args->IPC_sock, msg, strlen(msg),0, (struct sockaddr*)&pmapi_addr, len);
                free(msg);
            }else{
                errf("unknow act");
                continue;
            }
        }
    }
    
    close(gts_args->UDP_sock);
    return 0;
}