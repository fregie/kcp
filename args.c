#include "args.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int init_gts_args(gts_args_t *gts_args){
    
    gts_args->port = 6666;
    gts_args->server = strdup("127.0.0.1");
    
    if (gts_args->mode == GTS_MODE_SERVER){
        gts_args->shell_up = strdup("./samples/server_up.sh");
        gts_args->intf = strdup("GTSs_tun");
        
    }else if (gts_args->mode == GTS_MODE_CLIENT){
        gts_args->shell_up = strdup("./samples/client_up.sh");
        gts_args->intf = strdup("GTSc_tun");
        gts_args->server_addr.sin_family = AF_INET;
        gts_args->server_addr.sin_port = htons(gts_args->port);
        gts_args->server_addr.sin_addr.s_addr = inet_addr(gts_args->server);
    }else {
        printf("unknow mode");
    }
    gts_args->header_key = (unsigned char*) malloc(8*sizeof(char));
    gts_args->header_key = "ABCD1234";
    
    gts_args->GTS_header_len = 32;
    gts_args->ver_len = 1;
    gts_args->token_len = 7;
    gts_args->nonce_len = 8; 
    gts_args->auth_info_len = 16;
    gts_args->ver = 1;
    gts_args->token = "ABCDEFG";
    
    gts_args->mtu = TUN_MTU;
    
    gts_args->udp_buf = malloc(gts_args->mtu + gts_args->GTS_header_len);
    gts_args->tun_buf = gts_args->udp_buf + gts_args->GTS_header_len;
    

    gts_args->remote_addr_len = sizeof(gts_args->remote_addr);
    
    return 1;
}