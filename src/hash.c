#include "hash.h"

int init_hash(hash_ctx_t *ctx, gts_args_t *gts_args){
    int i;
    bzero(ctx, sizeof(hash_ctx_t));
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    for (i = 0; i < gts_args->token_len; i++) {
        client_info_t *client = malloc(sizeof(client_info_t));
        bzero(client, sizeof(client_info_t));

        memcpy(client->token, gts_args->token[i], TOKEN_LEN);
        if (gts_args->encrypt == 1){
            crypto_generichash(client->key, sizeof client->key, 
                              (unsigned char *)gts_args->password[i],
                              strlen(gts_args->password[i]), NULL, 0);
        }
        client->encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[i], FLAG_MSG, &ks);
        // assign IP based on tun IP and user tokens
        // for example:
        //     tun IP is 10.7.0.1
        //     client IPs will be 10.7.0.2, 10.7.0.3, 10.7.0.4, etc
        client->output_tun_ip = htonl(gts_args->netip + i + 1);
        client->rx = 0;
        client->tx = 0;

        struct in_addr in;
        in.s_addr = client->output_tun_ip;
        
        // add to hash: ctx->token_to_clients[token] = client
        HASH_ADD(hh1, ctx->token_to_clients, token, TOKEN_LEN, client);

        // add to hash: ctx->ip_to_clients[output_tun_ip] = client
        HASH_ADD(hh2, ctx->ip_to_clients, output_tun_ip, 4, client);
    }
}