#include "hash.h"
#include "action.h"

int init_hash(hash_ctx_t *ctx, gts_args_t *gts_args,
              int (*output)(const char *buf, int len, struct IKCPCB *kcp, void *user)){
    int i;
    bzero(ctx, sizeof(hash_ctx_t));
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
    for (i = 0; i < gts_args->token_len; i++) {
        client_info_t *client = malloc(sizeof(client_info_t));
        bzero(client, sizeof(client_info_t));

        client->ver = GTS_VER;
        memcpy(client->token, gts_args->token[i], TOKEN_LEN);
        crypto_generichash(client->key, sizeof client->key, 
                            (unsigned char *)gts_args->password[i],
                            strlen(gts_args->password[i]), NULL, 0);
        client->encrypted_header = encrypt_GTS_header(&gts_args->ver, gts_args->token[i], FLAG_MSG, &ks);
        //version 1.x.x gts header
        uint8_t ver_1 = 1;
        client->v1_encrypted_header = encrypt_GTS_header(&ver_1, gts_args->token[i], FLAG_MSG, &ks);
        // assign IP based on tun IP and user tokens
        // for example:
        //     tun IP is 10.7.0.1
        //     client IPs will be 10.7.0.2, 10.7.0.3, 10.7.0.4, etc
        client->output_tun_ip = htonl(gts_args->netip + i + 1);
        client->source_addr.addrlen = NO_SOURCE_ADDR;
        client->rx = 0;
        client->tx = 0;
        client->txquota = UNLIMIT;
        client->expire = NULL;
        client->over_date = 0;

        IUINT32 *conv = (IUINT32*)client->token;
        client->kcp = ikcp_create(*conv, (void*)client);
        client->kcp->output = output;
        ikcp_setmtu(client->kcp, gts_args->mtu + IKCP_HEAD_LEN);
        ikcp_wndsize(client->kcp, KCP_DEFAULT_SNDWND, KCP_DEFAULT_RCVWND);
        // 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
        ikcp_nodelay(client->kcp, KCP_DEFAULT_NODELAY, KCP_DEFAULT_INTERVAL,
                                  KCP_DEFAULT_RESEND, KCP_DEFAULT_NC);
        client->kcp->rx_minrto = KCP_DEFAULT_MINRTO;
        client->kcp->fastresend = 1;
        
        // add to hash: ctx->token_to_clients[token] = client
        HASH_ADD(hh1, ctx->token_to_clients, token, TOKEN_LEN, client);

        // add to hash: ctx->ip_to_clients[output_tun_ip] = client
        HASH_ADD(hh2, ctx->ip_to_clients, output_tun_ip, 4, client);
    }
    return 0;
}