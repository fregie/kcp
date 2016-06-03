#include "args.h"
#include "action.h"

#include <signal.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MAX_IPC_LEN 20
#define RANDOM_MSG_LEN 32

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
static unsigned char key[32];
static stat_code = FLAG_OK;

static void sig_handler(int signo) {
    /*errf("\nup time: %d\ndown time: %d\ncrypt time: %d",
         up_time/1000, down_time/1000, crypt_time/1000);*/
    system(shell_down);
    exit(0);
}

static int check_header(char *token, unsigned char* buf, DES_key_schedule* ks){
    DES_ecb_encrypt((const_DES_cblock*)buf, (DES_cblock*)buf, ks, DES_DECRYPT);
    if (buf[0] != GTS_VER){
        errf("version check failed");
        return 1;
    }else if(memcmp(token, buf + VER_LEN + FLAG_LEN, TOKEN_LEN) != 0){
        errf("unknow token");
        return 2;
    }else{
        return 0;
    }
}

static char * Base64Decode(char * input, int length){
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
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
    if (header_key != NULL){
        header_key = Base64Decode(header_key, HEADER_KEY_LEN);
        DES_key_schedule ks;
        DES_set_key_unchecked((const_DES_cblock*)gts_args->password[0], &ks);
        DES_ecb_encrypt((const_DES_cblock*)header_key,
                        (DES_cblock*)gts_args->header_key, &ks, DES_DECRYPT);
    }
    
    if(init_log_file(gts_args->log_file) == -1){
        errf("init log_file failed!");
    }
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
    set_env(gts_args); //set environment variable
    //make encrypted_header
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    unsigned char *encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], FLAG_MSG, &ks);
    unsigned char *syn_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], FLAG_SYN, &ks);
    //init crypto
    if (0 != crypto_init()) {
        errf("GTS_crypto_init failed");
        return EXIT_FAILURE;
    }
    if (gts_args->encrypt == 1){
        if (crypto_generichash(key, sizeof key, (unsigned char *)gts_args->password[0],
                               strlen(gts_args->password[0]), NULL, 0) != 0){
            errf("can't set password");
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
        free(cmd);
    }
    // init UDP_sock
    struct sockaddr_in server_addr;
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    gts_args->IPC_sock = init_IPC_socket();
    //for select
    fd_set readset;
    int max_fd;
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    
    gts_header_t *gts_header = gts_args->recv_buf;
    int crypt_len;
    time_t temp_time = time(NULL) - gts_args->beat_time;
    time_t last_recv_time = time(NULL);
    //start working!
    while (1){
        if (time(NULL) - temp_time >= gts_args->beat_time){
            temp_time += gts_args->beat_time;
            randombytes_buf(gts_args->recv_buf + GTS_HEADER_LEN, RANDOM_MSG_LEN);
            memcpy(gts_args->recv_buf, syn_header, VER_LEN+FLAG_LEN+TOKEN_LEN);
            crypto_encrypt(gts_args->recv_buf, gts_args->recv_buf, RANDOM_MSG_LEN, key);
            if (sendto(gts_args->UDP_sock, gts_args->recv_buf,
                RANDOM_MSG_LEN + GTS_HEADER_LEN, 0,
                (struct sockaddr*)&gts_args->server_addr,
                (socklen_t)sizeof(gts_args->server_addr)) == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // do nothing
                } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                            errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                    // just log, do nothing
                    err("sendto");
                } else {
                    err("sendto");
                    // TODO rebuild socket
                    break;
                }
            }
        }
        max_fd = 0;
        struct timeval timeout;
        timeout.tv_sec = gts_args->beat_time;
        timeout.tv_usec = 0;
        FD_ZERO(&readset);
        FD_SET(gts_args->tun, &readset);
        FD_SET(gts_args->UDP_sock, &readset);
        FD_SET(gts_args->IPC_sock, &readset);
        max_fd = max(gts_args->tun, max_fd);
        max_fd = max(gts_args->UDP_sock, max_fd);
        max_fd = max(gts_args->IPC_sock, max_fd);
        if ( -1 == select(max_fd+1, &readset, NULL, NULL, &timeout)){
            errf("select failed");
            return EXIT_FAILURE;
        }
        
        //recv from server and write to tun
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            last_recv_time = time(NULL);
            length = recvfrom(gts_args->UDP_sock, gts_args->recv_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
            if (length == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // do nothing
                } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                            errno == EPERM || errno == EINTR) {
                    // just log, do nothing
                    err("recvfrom");
                } else {
                    err("recvfrom");
                    break;
                }
            }
            if (length == 0){
                continue;
            }
            DES_ecb_encrypt((const_DES_cblock*)gts_header, (DES_cblock*)gts_header, &ks, DES_DECRYPT);
            if (gts_header->ver != GTS_VER){
                continue;
            }
            if (gts_header->flag != FLAG_MSG){
                stat_code = gts_header->flag;
            }
            if (memcmp(gts_args->token[0], gts_header->token, TOKEN_LEN) != 0){
                errf("token err");
                continue;
            }
            if(gts_args->encrypt == 1) 
                crypt_len = length - GTS_HEADER_LEN;
            else
                crypt_len = ENCRYPT_LEN;
            if (-1 == crypto_decrypt(gts_args->recv_buf, gts_args->recv_buf,
                                        crypt_len, key)){
                errf("dropping invalid packet, maybe wrong password");
                continue;
            }
            if (write(gts_args->tun, gts_args->recv_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN) == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
                } else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
                // just log, do nothing
                err("write to tun");
                } else {
                err("write to tun");
                break;
                }
            }
        }
        //read from tun and send to server
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->recv_buf+GTS_HEADER_LEN, gts_args->mtu);
            if (stat_code != FLAG_OK || time(NULL) - last_recv_time >=3*gts_args->beat_time ){
                continue;
            }
            if (length == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
                } else if (errno == EPERM || errno == EINTR) {
                // just log, do nothing
                err("read from tun");
                } else {
                err("read from tun");
                break;
                }
            }
            if (gts_args->encrypt == 1){
                crypt_len = length;
            }else{
                crypt_len = ENCRYPT_LEN;
            }
            crypto_encrypt(gts_args->recv_buf, gts_args->recv_buf, crypt_len, key);
            memcpy(gts_args->recv_buf, encrypted_header, VER_LEN+FLAG_LEN+TOKEN_LEN);
            if (sendto(gts_args->UDP_sock, gts_args->recv_buf,
                length + GTS_HEADER_LEN, 0,
                (struct sockaddr*)&gts_args->server_addr,
                (socklen_t)sizeof(gts_args->server_addr)) == -1)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // do nothing
                    } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                                errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                        // just log, do nothing
                        err("sendto");
                    } else {
                        err("sendto");
                        // TODO rebuild socket
                        break;
                    }
                }
        }
        //recv from unix domain socket 
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
            char rx_buf[MAX_IPC_LEN];
            // bzero(rx_buf, MAX_IPC_LEN);
            struct sockaddr_un pmapi_addr;
            socklen_t len = sizeof(pmapi_addr);
            int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0,
                                   (struct sockaddr*)&pmapi_addr, (socklen_t *)&len);
            if (recvSize == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // do nothing
                } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                            errno == EPERM || errno == EINTR) {
                    // just log, do nothing
                    err("recvfrom");
                } else {
                    err("recvfrom");
                    break;
                }
            }
            char *act;
            cJSON *json;
            json = cJSON_Parse(rx_buf);
            if(!json){
                errf("request parse failed");
                continue;
            }
            act = cJSON_GetObjectItem(json,"act")->valuestring;
            if (strcmp(act,"show_stat") == 0){
                char *msg = malloc(MAX_IPC_LEN);
                if (snprintf(msg, MAX_IPC_LEN,"{\"stat\":%d}", stat_code) > MAX_IPC_LEN){
                    errf("msg too long");
                } 
                if (sendto(gts_args->IPC_sock, msg, strlen(msg),0, (struct sockaddr*)&pmapi_addr, len) == -1){
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // do nothing
                    } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                                errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                        // just log, do nothing
                        err("sendto");
                    } else {
                        err("sendto");
                        // TODO rebuild socket
                        break;
                    }
                }
                free(msg);
            }else{
                errf("unknow act");
                continue;
            }
            free(json);
        }
    }
    
    close(gts_args->UDP_sock);
    return 0;
}