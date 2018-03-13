#include "args.h"
#include "action.h"
#include "daemon.h"
#include "ikcp.h"
#include "hash.h"

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
clock_t decrypt_time = 0;
clock_t encrypt_time = 0;
clock_t nat_time = 0;
clock_t recv_time = 0;
clock_t write_time = 0;

clock_t start_time = 0;
clock_t end_time = 0;
//------------------------------------

static char *shell_down = NULL;
static char *ipc_file = NULL;
static unsigned char key[32];
static int stat_code = FLAG_OK;
static unsigned char *encrypted_header = NULL;
static unsigned char *syn_header = NULL;

static int udp_socket = 0;
static int encrypt = 0;
static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *GTS_ARGS){
    gts_args_t *gts_args = (gts_args_t*)GTS_ARGS;
    char send_buf[len+GTS_HEADER_LEN];
    if (encrypt == 1){
        crypto_encrypt((unsigned char*)send_buf, (unsigned char*)buf, len, key);
    }else{
        crypto_encrypt((unsigned char*)send_buf, (unsigned char*)buf, ENCRYPT_LEN, key);
        memcpy(send_buf+GTS_HEADER_LEN+ENCRYPT_LEN, buf+ENCRYPT_LEN, len-ENCRYPT_LEN);
    }
    memcpy(send_buf, encrypted_header, VER_LEN+FLAG_LEN+TOKEN_LEN);
    while (1){
        if (sendto(udp_socket, send_buf, len + GTS_HEADER_LEN, 0,
                (struct sockaddr*)&gts_args->server_addr,
                (socklen_t)sizeof(gts_args->server_addr)) == -1){
            if (errno == EAGAIN || errno == EWOULDBLOCK){
                continue;
            }else{
                errf("sendto error : %d", errno);
            }
            return -1;
        }
        break;
    }
    return 0;
}

static void sig_handler(int signo) {
    // errf("\nselect time: %ld\nup time: %ld\ndown time: %ld\nencrypt time: %ld\ndecrypt time: %ld\nheader time: %ld\nrecv time: %ld\nwrite time: %ld\n",
    //         select_time/1000, up_time/1000, down_time/1000, encrypt_time/1000, decrypt_time/1000, header_time/1000, recv_time/1000, write_time/1000);
    s_system(shell_down);
    unlink(ipc_file);
    exit(0);
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
    char *act = "none";
    while ((ch = getopt(argc, argv, "c:kd:v")) != -1){
        switch (ch){
        case 'c':
            conf_file = strdup(optarg);
            break;
        case 'k':
            header_key = strdup(optarg);
            break;
        case 'd':
            act = strdup(optarg);
            break;
        case 'v':
            printf("\nGTS-----------geewan transmit system\nversion: %s\n", GTS_RELEASE_VER);
            return 0;
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
    int length = 0;
    printf("GTS-client starting.....\n");
    if (-1 == init_gts_args(gts_args, conf_file)){
        printf("init client failed!");
        return EXIT_FAILURE;
    }

    if(strcmp(act, "start") == 0){
        if (0 != daemon_start(gts_args)) {
        errf("can not start daemon");
        return EXIT_FAILURE;
        }
    }
    if(strcmp(act, "stop") == 0){
        if (0 != daemon_stop(gts_args)) {
        errf("can not start daemon");
        return EXIT_FAILURE;
        }
        return 0;
    }
    if(strcmp(act, "restart") == 0){
        if (0 != daemon_stop(gts_args)) {
        errf("can not start daemon");
        return EXIT_FAILURE;
        }
        if (0 != daemon_start(gts_args)) {
        errf("can not start daemon");
        return EXIT_FAILURE;
        }
    }


    if(init_log_file(gts_args->log_file) == -1){
        errf("init log_file failed!");
    }
    if (header_key != NULL){
        header_key = Base64Decode(header_key, HEADER_KEY_LEN);
        DES_key_schedule ks;
        DES_set_key_unchecked((const_DES_cblock*)gts_args->password[0], &ks);
        DES_ecb_encrypt((const_DES_cblock*)header_key,
                        (DES_cblock*)gts_args->header_key, &ks, DES_DECRYPT);
    }
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
    set_env(gts_args); //set environment variable
    //make encrypted_header
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], FLAG_MSG, &ks);
    syn_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[0], FLAG_SYN, &ks);
    //init crypto
    if (0 != crypto_init()) {
        errf("GTS_crypto_init failed");
        return EXIT_FAILURE;
    }
    if (crypto_generichash(key, sizeof key, (unsigned char *)gts_args->password[0],
                            strlen(gts_args->password[0]), NULL, 0) != 0){
        errf("can't set password");
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
        char *cmd = malloc(strlen(gts_args->shell_up) +8);
        sprintf(cmd, "sh %s", gts_args->shell_up);
        s_system(cmd);
        free(cmd);
    }
    // init UDP_sock
    gts_args->UDP_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    udp_socket = gts_args->UDP_sock;
    ipc_file = gts_args->ipc_file;
    gts_args->IPC_sock = init_IPC_socket(ipc_file);
    encrypt = gts_args->encrypt;
    //for select
    fd_set readset;
    int max_fd;
    struct timeval timeout;
    //init kcp
    IUINT32 *conv = (IUINT32*)gts_args->token[0];
    ikcpcb *kcp = ikcp_create(*conv, (void*)gts_args);
    ikcp_setmtu(kcp, gts_args->mtu+IKCP_HEAD_LEN);
    kcp->output = kcp_output;
    int sndwnd, rcvwnd, nodelay, interval, resend, nc;
    decode_int32(&sndwnd, &gts_args->kcp_conf.sndwnd);
    decode_int32(&rcvwnd, &gts_args->kcp_conf.rcvwnd);
    decode_int32(&nodelay, &gts_args->kcp_conf.nodelay);
    decode_int32(&interval, &gts_args->kcp_conf.interval);
    decode_int32(&resend, &gts_args->kcp_conf.resend);
    decode_int32(&nc, &gts_args->kcp_conf.nc);
    ikcp_wndsize(kcp, sndwnd, rcvwnd);
    ikcp_nodelay(kcp, nodelay, interval, resend, nc);
    kcp->rx_minrto = 10;
    kcp->fastresend = 1;
    
    gts_header_t *gts_header = (gts_header_t*)gts_args->recv_buf;
    int crypt_len;
    time_t temp_time = time(NULL) - gts_args->beat_time;
    time_t last_recv_time = time(NULL);

    if (-1 == fcntl(gts_args->UDP_sock, F_SETFL, O_NONBLOCK)){
        errf("fcntl UDP_sock error!\n");
        return -1;
    }
    if (-1 == fcntl(gts_args->tun, F_SETFL, O_NONBLOCK)){
        errf("fcntl tun_fd error!\n");
        return -1;
    }
    //start working!
    while (1){
        if (time(NULL) - temp_time >= gts_args->beat_time){
            temp_time += gts_args->beat_time;
            memcpy(gts_args->recv_buf + GTS_HEADER_LEN, &gts_args->kcp_conf, KCP_CONF_LEN);
            memcpy(gts_args->recv_buf, syn_header, VER_LEN+FLAG_LEN+TOKEN_LEN);
            if (gts_args->encrypt == 1){
                crypt_len = KCP_CONF_LEN;
            }else{
                crypt_len = ENCRYPT_LEN;
            }
            crypto_encrypt(gts_args->recv_buf, gts_args->recv_buf+GTS_HEADER_LEN, crypt_len, key);
            while (1){
                if (sendto(gts_args->UDP_sock, gts_args->recv_buf,
                    RANDOM_MSG_LEN + GTS_HEADER_LEN, 0,
                    (struct sockaddr*)&gts_args->server_addr,
                    (socklen_t)sizeof(gts_args->server_addr)) == -1)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    } else {
                        errf("sendto: %d", errno);
                    }
                    return -1;
                }
                break;
            }
        }
        timeout.tv_sec = 0;
        timeout.tv_usec = KCP_UPDATE_INTERVAL * 1000;
        max_fd = 0;
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
        if (FD_ISSET(gts_args->UDP_sock, &readset)){while(1){
            last_recv_time = time(NULL);
            length = recvfrom(gts_args->UDP_sock, gts_args->recv_buf,
                            MAX_MTU_LEN, 0,
                            (struct sockaddr*)&gts_args->remote_addr,
                            (socklen_t*)&gts_args->remote_addr_len);
            if (length == -1){
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
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
                break;
            }
            DES_ecb_encrypt((const_DES_cblock*)gts_header, (DES_cblock*)gts_header, &ks, DES_DECRYPT);
            if (gts_header->ver != gts_args->ver){
                // continue;
            }
            if (memcmp(gts_args->token[0], gts_header->token, TOKEN_LEN) != 0){
                errf("token err");
                continue;
            }
            if (gts_header->flag != FLAG_MSG){
                stat_code = gts_header->flag;
                if (stat_code != FLAG_OK){
                    // errf("stat code : %d", stat_code);
                }
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
            if (gts_args->ver == GTS_VER_1){
                if (write(gts_args->tun, gts_args->recv_buf+GTS_HEADER_LEN, length-GTS_HEADER_LEN) == -1){
                    errf("failed to write to tun");
                    continue;
                }
                continue;
            }
            //------------------------- write in kcp -----------------------------------------------
            if (0 > ikcp_input(kcp, (char*)gts_args->recv_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                errf("ikcp input error");
                continue;
            }
            ikcp_update(kcp, iclock());
            while(1){
                length = ikcp_recv(kcp, (char*)gts_args->recv_buf, MAX_MTU_LEN);
                if (length == -1 || length == 0){
                    break;
                }
                if (length < -1){
                    errf("ikcp recv error: %d", length);
                    break;
                }
                if (write(gts_args->tun, gts_args->recv_buf, length) == -1){
                    errf("failed to write to tun");
                    continue;
                }
            }
            //--------------------------------------------------------------------------------------
        //read from tun and send to server
        }}else if (FD_ISSET(gts_args->tun, &readset)){while(1){
                length = read(gts_args->tun, gts_args->recv_buf, MAX_MTU_LEN-GTS_HEADER_LEN);
                if (time(NULL) - last_recv_time >=5*gts_args->beat_time ){
                    stat_code = FLAG_NO_RESPONSE;
                    errf("can't recv server response");
                    // continue;
                }
                if (length == -1 || length == 0){
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else if (errno == EPERM || errno == EINTR) {
                    // just log, do nothing
                    err("read from tun");
                    } else {
                    err("read from tun");
                    break;
                    }
                }
                if (gts_args->ver == GTS_VER_1){
                    kcp_output((char*)gts_args->recv_buf, length, NULL, (void*)gts_args);
                    continue;
                }
                if (0 > ikcp_send(kcp, (char*)gts_args->recv_buf, length)){
                    errf("kcp send error");
                    continue;
                }
                ikcp_update(kcp, iclock());
            }
        //recv from unix domain socket 
        }else if (FD_ISSET(gts_args->IPC_sock, &readset)){
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
        }else{
            ikcp_update(kcp, iclock());
        }
    }
    
    close(gts_args->UDP_sock);
    return 0;
}