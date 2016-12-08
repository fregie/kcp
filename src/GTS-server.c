#include "args.h"
#include "action.h"
#include "daemon.h"
#include "hash.h"
#include "ikcp.h"
#include <signal.h>
#include <sys/time.h>

#define MAX_IPC_LEN 500
#define ACT_OK "{\"status\":\"ok\"}"
#define ACT_FAILED "{\"status\":\"failed\"}"
#define CHECK_TIME 300

//time debug ------------------------
clock_t select_time = 0;
clock_t up_time = 0;
clock_t down_time = 0;
clock_t header_time = 0;
clock_t hash_time = 0;
clock_t crypt_time = 0;
clock_t nat_time = 0;
clock_t set_paswd_time = 0;

clock_t start_time = 0;
clock_t end_time = 0;
//------------------------------------

static char *shell_down = NULL;

static int UDP_socket;
static struct sockaddr_storage server_addr;

static void sig_handler(int signo) {
    /*errf("\nselect time: %d\nheader time: %d\nhash time: %d\ncrypt time: %d\npawd time: %d\nup time: %d\ndown time: %d",
          select_time/1000, header_time/1000, hash_time/1000, crypt_time/1000, set_paswd_time/1000, up_time/1000, down_time/1000);*/
    system(shell_down);
    unlink(IPC_FILE);
    exit(0);
}

static int send_flag_msg(uint8_t flag, gts_args_t *gts_args, DES_key_schedule ks,
                        int length, struct sockaddr_storage temp_remote_addr,  
                        socklen_t temp_remote_addrlen){
    memset(gts_args->recv_buf + VER_LEN, flag, FLAG_LEN);
    DES_ecb_encrypt((const_DES_cblock*)gts_args->recv_buf, (DES_cblock*)gts_args->recv_buf, &ks, DES_ENCRYPT);
    if ( -1 == sendto(gts_args->UDP_sock, gts_args->recv_buf,
                    length, 0, (struct sockaddr*)&temp_remote_addr,
                    (socklen_t)temp_remote_addrlen))
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
        } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                    errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
            err("sendto");
        } else {
            err("sendto");
            return -1;
        }
    }
    return 0;
}

static void check_date(hash_ctx_t *ctx){
    struct tm *pre_time;
    time_t t;
    t = time(NULL);
    pre_time = gmtime(&t);
    client_info_t *client;
    for(client = ctx->token_to_clients; client != NULL; client=client->hh1.next){
        if (client->expire == NULL)
            continue;
        if (pre_time->tm_year + 1900 > client->expire->tm_year){
            client->over_date = OVER_DATE;
            continue;
        }
        if (pre_time->tm_year + 1900 < client->expire->tm_year)
            continue;
        if (pre_time->tm_mon + 1 > client->expire->tm_mon){
            client->over_date = OVER_DATE;
            continue;
        }
        if (pre_time->tm_mon + 1 < client->expire->tm_mon)
            continue;
        if (pre_time->tm_mday > client->expire->tm_mday){
            client->over_date = OVER_DATE;
            continue;
        }
        if (pre_time->tm_mday < client->expire->tm_mday)
            continue;
        if (pre_time->tm_hour > client->expire->tm_hour){
            client->over_date = OVER_DATE;
            continue;
        }
        if (pre_time->tm_hour < client->expire->tm_hour)
            continue;
        if (pre_time->tm_min > client->expire->tm_min){
            client->over_date = OVER_DATE;
            continue;
        }
    }
}

static int udp_output(const char *buf, int len, ikcpcb *kcp, void *user){
    if (sendto(UDP_socket, buf, len, 0,(struct sockaddr*)&server_addr,
              (socklen_t)sizeof(server_addr)) == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // do nothing
            } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                        errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
                // just log, do nothing
                err("sendto");
            } else {
                err("sendto");
                return -1;
            }
        }
        return 0;
}

int main(int argc, char **argv) {
    int ch;
    char *conf_file = NULL;
    char *act = "none";
    while ((ch = getopt(argc, argv, "c:d:v")) != -1){
        switch (ch){
        case 'c':
            conf_file = strdup(optarg);
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
    /*init gts_args*/
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_SERVER;
    
    hash_ctx_t *hash_ctx;
    hash_ctx = malloc(sizeof(hash_ctx_t));
    int length; /*length of buffer recieved*/
    printf("GTS-server starting....\n");
    init_gts_args(gts_args, conf_file);
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
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
    set_env(gts_args);
    init_hash(hash_ctx, gts_args);
    
    /*init header_key*/
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    /*init UDP_sock and GTSs_tun*/
    gts_args->UDP_sock = init_UDP_socket(gts_args->server,gts_args->port);
    if (gts_args->UDP_sock == -1){
        return EXIT_FAILURE;
    }
    UDP_socket = gts_args->UDP_sock;
    gts_args->tun = tun_create(gts_args->intf);
    gts_args->IPC_sock = init_IPC_socket();

    //init kcp
    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);
    ikcpcb *kcp = ikcp_create(0x11223344, (void*)1);
    kcp->output = udp_output;
    ikcp_wndsize(kcp, 128, 128);
    ikcp_nodelay(kcp, 1, 10, 2, 1);
    kcp->rx_minrto = 10;
    kcp->fastresend = 1;

    if (gts_args->tun < 0){
        errf("tun create failed!");
        return EXIT_FAILURE;
    }else{
        char *cmd = malloc(strlen(gts_args->shell_up) +8);
        sprintf(cmd, "sh %s", gts_args->shell_up);
        system(cmd);
        free(cmd);
    }
    //get out interface name ,for traffic contrl
    FILE *stream = popen("ip route show 0/0 | sed -e 's/.* dev \\([^ ]*\\).*/\\1/'", "r" );
    if (fgets(gts_args->out_intf, MAX_INTF_LEN, stream) == NULL){
        errf("get out interface failed, traffic control may not work");
    }
    pclose(stream);
    char *temp =strchr(gts_args->out_intf, '\n');
    if ( temp!= NULL){
        *temp = 0;
    }
    fd_set readset;
    int max_fd;
    int crypt_len;
    gts_header_t *gts_header = (gts_header_t*)gts_args->recv_buf;
    time_t last_check_data = time(NULL) - CHECK_TIME;
    
    while (1){
        if (time(NULL) - last_check_data >= CHECK_TIME){
            check_date(hash_ctx);
        }
        //update timestamp
        gettimeofday(&curr_time, NULL);
        ikcp_update(kcp, (IUINT32)curr_time.tv_usec);

        max_fd = 0;
        FD_ZERO(&readset);
        FD_SET(gts_args->tun, &readset);
        FD_SET(gts_args->UDP_sock, &readset);
        FD_SET(gts_args->IPC_sock, &readset);
        max_fd = max(gts_args->tun, max_fd);
        max_fd = max(gts_args->UDP_sock, max_fd);
        max_fd = max(gts_args->IPC_sock, max_fd);
        if ( -1 == select(max_fd+1, &readset, NULL, NULL, NULL)){
            errf("select failed");
            return EXIT_FAILURE;
        }
        
        //recv data from client
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            struct sockaddr_storage temp_remote_addr;
            socklen_t temp_remote_addrlen = sizeof(temp_remote_addr);
            length = recvfrom(gts_args->UDP_sock, gts_args->recv_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr *)&temp_remote_addr,
                            &temp_remote_addrlen);
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

            ikcp_input(kcp, gts_args->recv_buf, length);
            length = ikcp_recv(kcp, gts_args->recv_buf, gts_args->mtu + GTS_HEADER_LEN);

            //decrypt header
            DES_ecb_encrypt((const_DES_cblock*)gts_args->recv_buf,
                            (DES_cblock*)gts_args->recv_buf, &ks, DES_DECRYPT);
            if (gts_header->ver != GTS_VER){
                continue;
            }
            client_info_t *client = NULL;
            
            HASH_FIND(hh1, hash_ctx->token_to_clients, gts_header->token, TOKEN_LEN, client);
            if(client == NULL){
                if (gts_header->flag == FLAG_SYN){
                    if (-1 == send_flag_msg(FLAG_TOKEN_ERR, gts_args, ks, length, temp_remote_addr, temp_remote_addrlen)){
                        break;
                    }
                }
                continue;
            }
            if(client->txquota <= 0 && client->txquota > UNLIMIT){
                if (gts_header->flag == FLAG_SYN){
                    if (-1 == send_flag_msg(FLAG_OVER_TXQUOTA, gts_args, ks, length, temp_remote_addr, temp_remote_addrlen)){
                        break;
                    }
                }
                continue;
            }
            if (client->over_date == OVER_DATE){
                if (gts_header->flag == FLAG_SYN){
                    if (-1 == send_flag_msg(FLAG_OVER_DATE, gts_args, ks, length, temp_remote_addr, temp_remote_addrlen)){
                        break;
                    }
                }
                continue;
            }
            //save source address
            client->source_addr.addrlen = temp_remote_addrlen;
            memcpy(&client->source_addr.addr, &temp_remote_addr, temp_remote_addrlen);
            
            if (gts_args->encrypt == 1){
                crypt_len = length - GTS_HEADER_LEN;
            }else{
                crypt_len = ENCRYPT_LEN;
            }
            if (-1 == crypto_decrypt(gts_args->recv_buf, gts_args->recv_buf,
                                    crypt_len, client->key)){
                if (gts_header->flag == FLAG_SYN){
                    if (-1 == send_flag_msg(FLAG_PASSWORD_ERR, gts_args, ks, length, temp_remote_addr, temp_remote_addrlen)){
                        break;
                    }
                }
                continue;
            }
            if (gts_header->flag == FLAG_SYN){
                if (-1 == send_flag_msg(FLAG_OK, gts_args, ks, length, temp_remote_addr, temp_remote_addrlen)){
                    break;
                }
                continue;
            }
            //------- make sure the package is not flag package ,then add txquota --------
            if (client->txquota > UNLIMIT){
                client->txquota -= (length - GTS_HEADER_LEN);
            }
            client->tx += (length - GTS_HEADER_LEN);
            // ---------------------------------------------------------------------------
            if (-1 == nat_fix_upstream(client, gts_args->recv_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                continue;
            }
            if (write(gts_args->tun, gts_args->recv_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN) == -1){
                errf("failed to write to tun");
                continue;
            }
        }
        // recv data from tun
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->recv_buf+GTS_HEADER_LEN, gts_args->mtu);
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
            client_info_t *client;
            client = nat_fix_downstream(hash_ctx, gts_args->recv_buf+GTS_HEADER_LEN, length);
            if (client == NULL){
                continue;
            }
            if (gts_args->encrypt ==1){
                crypt_len = length;
            }else{
                crypt_len = ENCRYPT_LEN;
            }
            if (client->source_addr.addrlen == NO_SOURCE_ADDR){
                errf("can't find source addr of client");
                // should continue here,comment to test id the problem caused by this
                continue;
            }
            crypto_encrypt(gts_args->recv_buf, gts_args->recv_buf, crypt_len, client->key);
            memcpy(gts_args->recv_buf, client->encrypted_header, VER_LEN+FLAG_LEN+TOKEN_LEN);
            if (client->txquota > UNLIMIT){
                client->txquota -= length;
            }
            client->rx += length;

            server_addr = client->source_addr.addr;
            ikcp_send(kcp, gts_args->recv_buf, length + GTS_HEADER_LEN);
            
            // if ( -1 == sendto(gts_args->UDP_sock, gts_args->recv_buf,
            //     length + GTS_HEADER_LEN, 0,
            //     (struct sockaddr*)&client->source_addr.addr,
            //     (socklen_t)client->source_addr.addrlen))
            // {
            //         if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //             // do nothing
            //         } else if (errno == ENETUNREACH || errno == ENETDOWN ||
            //                     errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
            //             // just log, do nothing
            //             err("sendto");
            //         } else {
            //             err("sendto");
            //             // TODO rebuild socket
            //             break;
            //         }
            // }
        }
        // recv data from IPC
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
                char rx_buf[MAX_IPC_LEN];
                bzero(rx_buf, MAX_IPC_LEN);
                struct sockaddr_un pmapi_addr;
                int len = sizeof(pmapi_addr);
                int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0,
                                        (struct sockaddr*)&pmapi_addr, (socklen_t *)&len);
                int r = api_request_parse(hash_ctx, rx_buf, gts_args);
                char *send_buf;
                if (r == -1){
                    errf("action failed!");
                    send_buf = strdup(ACT_FAILED);
                }else if(r == 0){
                    send_buf = strdup(ACT_OK);
                }else if(r == 1){
                    send_buf = generate_stat_info(hash_ctx);
                }
                sendto(gts_args->IPC_sock, send_buf, strlen(send_buf),0, (struct sockaddr*)&pmapi_addr, len);
                free(send_buf);
                check_date(hash_ctx);
        }
    }
    close(gts_args->UDP_sock);
    // free(gts_args);
    errf("exiting gts-ser");
    return 0;
}