#include "args.h"
#include "action.h"
#include "hash.h"
#include <signal.h>

unsigned char* decrypt_header(unsigned char *buf, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(9*sizeof(char));
    process_message(buf, data_block, key_sets, DECRYPTION_MODE);
    data_block[8] = 0;
    return data_block;
}

static void sig_handler(int signo) {
    system("sh ./samples/server_down.sh");
    unlink(IPC_FILE);
    exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2){
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
    
    init_gts_args(gts_args, argv[1]);
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
        printf("tun create failed!");
        return EXIT_FAILURE;
    }else{
        system(gts_args->shell_up);
    }
    fd_set readset;
    while (gts_args->ver == 1){
        printf("start listening.....\n");
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
                printf("version check failed,drop!");
                free(header);
                continue;
            }
            client_info_t *client = NULL;
            HASH_FIND(hh1, hash_ctx->token_to_clients, header+VER_LEN, TOKEN_LEN, client);
            if(client == NULL){
                printf("unknow token, drop!");
                free(header);
                continue;
            }
            free(header);
            //save source address
            client->source_addr.addrlen = temp_remote_addrlen;
            memcpy(&client->source_addr.addr, &temp_remote_addr, temp_remote_addrlen);
            
            if (0 !=crypto_set_password(client->password, strlen(client->password))) {
                printf("can not find password");
                continue;
            }
            if (-1 == crypto_decrypt(gts_args->tun_buf, gts_args->udp_buf,
                                    length - GTS_HEADER_LEN)){
                printf("dropping invalid packet, maybe wrong password");
            }
            if (-1 == nat_fix_upstream(client, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN)){
                continue;
            }
            
            write(gts_args->tun, gts_args->tun_buf+GTS_HEADER_LEN, length - GTS_HEADER_LEN);
            printf("back:%dbyte\n",length-32);
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
                printf("can not find password");
                continue;
            }
            crypto_encrypt(gts_args->udp_buf, gts_args->tun_buf, length);
            memcpy(gts_args->udp_buf, client->encrypted_header, VER_LEN+TOKEN_LEN);
            sendto(gts_args->UDP_sock, gts_args->udp_buf,
                  length + GTS_HEADER_LEN, 0,
                  (struct sockaddr*)&client->source_addr.addr,
                  (socklen_t)client->source_addr.addrlen);
            printf("to:%dbyte\n",length);
        }
        if (FD_ISSET(gts_args->IPC_sock, &readset)){
                char rx_buf[500];
                struct sockaddr_un pmapi_addr;
                int len = sizeof(pmapi_addr);
                int recvSize = recvfrom(gts_args->IPC_sock, rx_buf, sizeof(rx_buf), 0, (struct sockaddr*)&pmapi_addr, &len);
                printf("%s",rx_buf);
                if (api_request_parse(hash_ctx, rx_buf, gts_args) != 0){
                    printf("action failed!");
                    continue;
                }
        }
    }
    close(gts_args->UDP_sock);
    free(gts_args);
    return 0;
}