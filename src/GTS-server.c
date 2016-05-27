#include "args.h"
#include "action.h"
#include "hash.h"
#include <signal.h>

#define MAX_IPC_LEN 200
#define ACT_OK "{\"status\":\"ok\"}"
#define ACT_FAILED "{\"status\":\"failed\"}"

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

unsigned char* err_msg(uint8_t err_code){
    unsigned char* err_msg = malloc(2);
    err_msg[0] = ERR_FLAG;
    err_msg[1] = err_code;
    return err_msg;
}

static void sig_handler(int signo) {
    errf("\nselect time: %d\nheader time: %d\nhash time: %d\ncrypt time: %d\npawd time: %d\nup time: %d\ndown time: %d",
          select_time/1000, header_time/1000, hash_time/1000, crypt_time/1000, set_paswd_time/1000, up_time/1000, down_time/1000);
    system(shell_down);
    unlink(IPC_FILE);
    exit(0);
}

int main(int argc, char **argv) {
    int ch;
    char *conf_file = NULL;
    while ((ch = getopt(argc, argv, "hc:")) != -1){
        switch (ch){
        case 'c':
            conf_file = strdup(optarg);
            break;
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
    printf("GTS-server start....\n");
    init_gts_args(gts_args, conf_file);
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
    gts_args->tun = tun_create(gts_args->intf);
    gts_args->IPC_sock = init_IPC_socket();

    if (gts_args->tun < 0){
        errf("tun create failed!");
        return EXIT_FAILURE;
    }else{
        char *cmd = malloc(strlen(gts_args->shell_up) +8);
        sprintf(cmd, "sh %s", gts_args->shell_up);
        system(cmd);
    }
    fd_set readset;
    
    while (1){
        select_time -= clock();
        readset = init_select(gts_args);    //select udp_socket and tun
        select_time += clock();
        
        bzero(gts_args->udp_buf, gts_args->mtu + GTS_HEADER_LEN);
        //recv data from client
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            up_time -= clock();
            struct sockaddr_storage temp_remote_addr;
            socklen_t temp_remote_addrlen = sizeof(temp_remote_addr);
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr *)&temp_remote_addr,
                            &temp_remote_addrlen);
            if (length == -1){
                errf("recv from client failed");
            }
            //decrypt header
            DES_ecb_encrypt((const_DES_cblock*)gts_args->udp_buf,
                            (DES_cblock*)gts_args->udp_buf, &ks, DES_DECRYPT);
            if (gts_args->udp_buf[0] != GTS_VER){
                errf("version check failed,drop!");
                unsigned char *msg = err_msg((uint8_t)HEADER_KEY_ERR);
                sendto(gts_args->UDP_sock, msg, 2,0,(struct sockaddr*)&temp_remote_addr,temp_remote_addrlen);
                free(msg);
                continue;
            }
            client_info_t *client = NULL;
            
            hash_time -= clock();
            HASH_FIND(hh1, hash_ctx->token_to_clients, gts_args->udp_buf+VER_LEN, TOKEN_LEN, client);
            if(client == NULL){
                errf("unknow token, drop!");
                unsigned char *msg = err_msg((uint8_t)TOKEN_ERR);
                sendto(gts_args->UDP_sock, msg, 2,0,(struct sockaddr*)&temp_remote_addr,temp_remote_addrlen);
                free(msg);
                continue;
            }
            //save source address
            client->tx += (length - GTS_HEADER_LEN);
            client->source_addr.addrlen = temp_remote_addrlen;
            memcpy(&client->source_addr.addr, &temp_remote_addr, temp_remote_addrlen);
            hash_time += clock();
            
            
            if (gts_args->encrypt == 1){
                crypt_time -= clock();
                if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                        length - GTS_HEADER_LEN, client->key)){
                    errf("dropping invalid packet, maybe wrong password");
                    unsigned char *msg = err_msg(PASSWORD_ERR);
                    sendto(gts_args->UDP_sock, msg, 2,0,(struct sockaddr*)&temp_remote_addr,temp_remote_addrlen);
                    free(msg);
                    continue;
                }
                crypt_time += clock();
                if (-1 == nat_fix_upstream(client, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                    continue;
                }
                if (write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN) == -1){
                    errf("failed to write to tun");
                    continue;
                }
            }else{
                if (-1 == nat_fix_upstream(client, gts_args->udp_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                    continue;
                }
                if (write(gts_args->tun, gts_args->udp_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN) == -1){
                    errf("failed to write to tun");
                    continue;
                }
            }
            up_time += clock();
        }
        // recv data from tun
        if (FD_ISSET(gts_args->tun, &readset)){
            down_time -= clock();
            length = read(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, gts_args->mtu);
            if (length == -1){
                errf("read from tun failed");
                continue;
            }
            client_info_t *client;
            client = nat_fix_downstream(hash_ctx, gts_args->tun_buf+GTS_HEADER_LEN, length);
            if (client == NULL){
                continue;
            }
            if (gts_args->encrypt ==1){
                crypto_encrypt(gts_args->udp_buf, gts_args->tun_buf, length, client->key);
                memcpy(gts_args->udp_buf, client->encrypted_header, VER_LEN+TOKEN_LEN);
                client->rx += length;
                if ( -1 == sendto(gts_args->UDP_sock, gts_args->udp_buf,
                    length + GTS_HEADER_LEN, 0,
                    (struct sockaddr*)&client->source_addr.addr,
                    (socklen_t)client->source_addr.addrlen))
                {
                    errf("send to client failed");
                    continue;
                }
            }else{
               memcpy(gts_args->tun_buf, client->encrypted_header, VER_LEN+TOKEN_LEN);
               client->rx += length;
               if ( -1 == sendto(gts_args->UDP_sock, gts_args->tun_buf,
                    length + GTS_HEADER_LEN, 0,
                    (struct sockaddr*)&client->source_addr.addr,
                    (socklen_t)client->source_addr.addrlen))
               {
                   errf("send to client failed");
                   continue;
               }
            }
            down_time += clock();
        }
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
                char rx_buf[MAX_IPC_LEN];
                bzero(rx_buf, MAX_IPC_LEN);
                struct sockaddr_un pmapi_addr;
                int len = sizeof(pmapi_addr);
                int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0,
                                        (struct sockaddr*)&pmapi_addr, (socklen_t *)&len);
                int r = api_request_parse(hash_ctx, rx_buf, gts_args);
                if (r == -1){
                    errf("action failed!");
                    sendto(gts_args->IPC_sock, ACT_FAILED, strlen(ACT_FAILED),0, 
                           (struct sockaddr*)&pmapi_addr, len);
                    continue;
                }else if(r == 0){
                    sendto(gts_args->IPC_sock, ACT_OK, strlen(ACT_OK),0,
                            (struct sockaddr*)&pmapi_addr, len);
                    continue;
                }else if(r == 1){
                    char *send_buf = generate_stat_info(hash_ctx);
                    sendto(gts_args->IPC_sock, send_buf, strlen(send_buf),0, (struct sockaddr*)&pmapi_addr, len);
                    free(send_buf);
                    continue;
                }
        }
    }
    close(gts_args->UDP_sock);
    free(gts_args);
    return 0;
}