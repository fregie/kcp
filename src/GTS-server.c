#include "args.h"
#include "action.h"
#include "hash.h"
#include <signal.h>

#define ACT_OK "{\"status\":\"ok\"}"
#define ACT_FAILED "{\"status\":\"failed\"}"

char *shell_down;

unsigned char* decrypt_header(unsigned char *buf, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    process_message(buf, data_block, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    return data_block;
}

static void sig_handler(int signo) {
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
    //init gts_args
    gts_args_t GTS_args;
    gts_args_t *gts_args = &GTS_args;
    bzero(gts_args, sizeof(gts_args_t));
    gts_args->mode = GTS_MODE_SERVER;
    
    hash_ctx_t *hash_ctx;
    hash_ctx = malloc(sizeof(hash_ctx_t));
    int length; //length of buffer recieved
    printf("GTS-server start....\n");
    init_gts_args(gts_args, conf_file);
    if(init_log_file(gts_args->log_file) == -1){
        errf("init log_file failed!");
    }
    shell_down = malloc(strlen(gts_args->shell_down)+ 8);
    sprintf(shell_down, "sh %s", gts_args->shell_down);
    set_env(gts_args);
/*    pid_t pid = getpid();
    if (0 != write_pid_file(gts_args->pid_file, pid)) {
        return EXIT_FAILURE;
    }*/
    init_hash(hash_ctx, gts_args);
    
    //init header_key
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));
    generate_sub_keys(gts_args->header_key, key_sets);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    //init UDP_sock and GTSs_tun
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
    while (gts_args->ver == 1){
        readset = init_select(gts_args);    //select udp_socket and tun
        
        bzero(gts_args->udp_buf, gts_args->mtu + GTS_HEADER_LEN);
        //recv data from client
        if (FD_ISSET(gts_args->UDP_sock, &readset)){
            struct sockaddr_storage temp_remote_addr;
            socklen_t temp_remote_addrlen = sizeof(temp_remote_addr);
            length = recvfrom(gts_args->UDP_sock, gts_args->udp_buf,
                            gts_args->mtu + GTS_HEADER_LEN, 0,
                            (struct sockaddr *)&temp_remote_addr,
                            &temp_remote_addrlen);
            //check version
            unsigned char* header = decrypt_header(gts_args->udp_buf, key_sets);
            if (header[0] != 1){
                errf("version check failed,drop!");
                free(header);
                continue;
            }
            client_info_t *client = NULL;
            HASH_FIND(hh1, hash_ctx->token_to_clients, header+VER_LEN, TOKEN_LEN, client);
            if(client == NULL){
                errf("unknow token, drop!");
                free(header);
                continue;
            }
            free(header);
            //save source address
            client->tx += (length - GTS_HEADER_LEN);
            client->source_addr.addrlen = temp_remote_addrlen;
            memcpy(&client->source_addr.addr, &temp_remote_addr, temp_remote_addrlen);
            
            if (0 !=crypto_set_password(client->password, strlen(client->password))) {
                errf("can not find password");
                continue;
            }
            if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                    length - GTS_HEADER_LEN)){
                errf("dropping invalid packet, maybe wrong password");
            }
            if (-1 == nat_fix_upstream(client, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                continue;
            }
            
            write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
        }
        // recv data from tun
        if (FD_ISSET(gts_args->tun, &readset)){
            length = read(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, gts_args->mtu);
            client_info_t *client;
            client = nat_fix_downstream(hash_ctx, gts_args->tun_buf+GTS_HEADER_LEN, length);
            if (client == NULL){
                continue;
            }
            if (0 !=crypto_set_password(client->password, strlen(client->password))) {
                errf("can not find password");
                continue;
            }
            crypto_encrypt(gts_args->udp_buf, gts_args->tun_buf, length);
            memcpy(gts_args->udp_buf, client->encrypted_header, VER_LEN+TOKEN_LEN);
            client->rx += length;
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + GTS_HEADER_LEN, 0,
                  (struct sockaddr*)&client->source_addr.addr,
                  (socklen_t)client->source_addr.addrlen);
        }
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
                char rx_buf[500];
                struct sockaddr_un pmapi_addr;
                int len = sizeof(pmapi_addr);
                int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0, (struct sockaddr*)&pmapi_addr, &len);
                int r = api_request_parse(hash_ctx, rx_buf, gts_args);
                if (r == -1){
                    errf("action failed!");
                    sendto(gts_args->IPC_sock, ACT_FAILED, strlen(ACT_FAILED),0, (struct sockaddr*)&pmapi_addr, len);
                    continue;
                }else if(r == 0){
                    sendto(gts_args->IPC_sock, ACT_OK, strlen(ACT_OK),0, (struct sockaddr*)&pmapi_addr, len);
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