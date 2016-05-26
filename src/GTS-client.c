#include "args.h"
#include "action.h"

#include <signal.h>

//time debug ------------------------
clock_t select_time = 0;
clock_t up_time = 0;
clock_t down_time = 0;
clock_t header_time = 0;
clock_t hash_time = 0;
clock_t crypt_time = 0;
clock_t nat_time = 0;

clock_t start_time = 0;
clock_t end_time = 0;
//------------------------------------

static char *shell_down = NULL;
static uint8_t stat_code = STAT_OK;
    /*
    return client status:
    0..........status OK
    1..........wrong token
    2..........wrong password
    3..........wrong header_key
    */

static void sig_handler(int signo) {
    errf("\nup time: %d\ndown time: %d\ncrypt time: %d",
         up_time/1000, down_time/1000, crypt_time/1000);
    system(shell_down);
    exit(0);
}

int check_header(char *token, unsigned char *buf, DES_key_schedule* ks){
    DES_ecb_encrypt((const_DES_cblock*)buf, (DES_cblock*)buf, ks, DES_DECRYPT);
    // print_hex_memory(data_block, 8);
    if (buf[0] != 1){
        stat_code = HEADER_KEY_ERR;
        errf("version check failed");
        return 1;
    }else if(memcmp(token, buf+1, TOKEN_LEN) != 0){
        stat_code = TOKEN_ERR;
        errf("unknow token");
        return 2;
    }else{
        return 0;
    }
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
    free(header_key);
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
    set_env(gts_args); //set environment variable
    //make encrypted_header
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    unsigned char* encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], &ks);
    
    //init crypto
    if (0 != crypto_init()) {
        errf("GTS_crypto_init failed");
        return EXIT_FAILURE;
    }
    if (gts_args->encrypt == 1){
        if (0 !=crypto_set_password(gts_args->password[0], strlen(gts_args->password[0]))) {
            errf("can not set password");
            return EXIT_FAILURE;
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // init GTSc_tun
    gts_args->tun = tun_create(gts_args->intf);
     if (gts_args->tun < 0){
        errf("tun create failed!");
        return EXIT_FAILURE;
    }else{
        char *cmd = malloc(strlen(gts_args->shell_up) +8);
        sprintf(cmd, "sh %s", gts_args->shell_up);
        system(cmd);
    }
    // init UDP_sock
    struct sockaddr_in server_addr;
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    gts_args->IPC_sock = init_IPC_socket();
    
    fd_set readset;
    //start working!
    while (1){
        readset = init_select(gts_args);    //select udp_socket and tun
        
        // bzero(gts_args->udp_buf, gts_args->mtu + GTS_HEADER_LEN);
        // bzero(gts_args->tun_buf, gts_args->mtu + GTS_HEADER_LEN);
        //recv from server and write to tun
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            down_time -= clock();
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
            if (gts_args->udp_buf[0] == ERR_FLAG){
                stat_code = gts_args->udp_buf[1];
                if (stat_code == TOKEN_ERR){
                    errf("token error");
                }else if(stat_code == PASSWORD_ERR){
                    errf("password error");
                }else if(stat_code == HEADER_KEY_ERR){
                    errf("header key error");
                }
                continue;
            }
                            
            if (check_header(gts_args->token[0], gts_args->udp_buf, &ks) != 0){
                continue;
            }
            if(gts_args->encrypt == 1){
                if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                        length - GTS_HEADER_LEN)){
                    stat_code = PASSWORD_ERR;
                    errf("dropping invalid packet, maybe wrong password");
                    continue;
                }
                write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
            }else{
                write(gts_args->tun, gts_args->udp_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
            }
            stat_code = STAT_OK;
            down_time += clock();
        }
        //read from tun and send to server
        if (FD_ISSET(gts_args->tun, &readset)){
            up_time -= clock();
            length = read(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, gts_args->mtu);
            if (gts_args->encrypt == 1){
                crypt_time -= clock();
                crypto_encrypt(gts_args->udp_buf, gts_args->tun_buf, length);
                crypt_time += clock();
                memcpy(gts_args->udp_buf, encrypted_header, VER_LEN+TOKEN_LEN);
                sendto(gts_args->UDP_sock, gts_args->udp_buf,
                    length + GTS_HEADER_LEN, 0,
                    (struct sockaddr*)&gts_args->server_addr,
                    (socklen_t)sizeof(gts_args->server_addr));
            }else{
                memcpy(gts_args->tun_buf, encrypted_header, VER_LEN+TOKEN_LEN);
                crypt_time -= clock();
                sendto(gts_args->UDP_sock, gts_args->tun_buf,
                    length + GTS_HEADER_LEN, 0,
                    (struct sockaddr*)&gts_args->server_addr,
                    (socklen_t)sizeof(gts_args->server_addr));
                crypt_time += clock();
            }
            up_time += clock();
        }
        //recv from unix domain socket 
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
            char rx_buf[MAX_IPC_LEN];
            // bzero(rx_buf, MAX_IPC_LEN);
            struct sockaddr_un pmapi_addr;
            int len = sizeof(pmapi_addr);
            int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0,
                                   (struct sockaddr*)&pmapi_addr, (socklen_t *)&len);
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
                if (snprintf(msg, 20,"{\"stat\":%d}", stat_code) > 20){
                    errf("msg too long");
                } 
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