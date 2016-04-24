#include "args.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int json_parse(gts_args_t *gts_args, char *filename){
    FILE *f;long len;char *data;
    f=fopen(filename,"rb");
    fseek(f,0,SEEK_END);
    len=ftell(f);
    fseek(f,0,SEEK_SET);
    data=(char*)malloc(len+1);
    fread(data,1,len,f);
    data[len]='\0';
    fclose(f);
    
    cJSON *json;
    cJSON *token_json;
    json=cJSON_Parse(data);
	if (!json){
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        return -1;
    }
    gts_args->server = strdup(cJSON_GetObjectItem(json,"server")->valuestring);
    gts_args->port = cJSON_GetObjectItem(json,"port")->valueint;
    gts_args->header_key = strdup(cJSON_GetObjectItem(json,"header key")->valuestring);
    gts_args->password = strdup(cJSON_GetObjectItem(json,"password")->valuestring);
    if (gts_args->mode == GTS_MODE_SERVER){
        gts_args->token = malloc(MAX_USER*sizeof(char*));
        token_json = cJSON_GetObjectItem(json,"token")->child;
        int i =0;
        while (token_json != 0){
            char *value = token_json->valuestring;
            int p = 0;
            gts_args->token[i] = malloc(TOKEN_LEN);
            while(*value && p < 7){
                unsigned int temp;
                int r = sscanf(value, "%2x", &temp);
                if (r > 0){
                    gts_args->token[i][p] = temp;
                    value += 2;
                    p++;
                } else {
                    break;
                }
            }
            i++;
            token_json = token_json->next;
        }
    }else if(gts_args->mode == GTS_MODE_CLIENT){
        gts_args->token = malloc(sizeof(char*));
        gts_args->token[0] = malloc(TOKEN_LEN);
        char *value = cJSON_GetObjectItem(json,"token")->valuestring;
        int p = 0;
        while(*value && p < 7){
                unsigned int temp;
                int r = sscanf(value, "%2x", &temp);
                if (r > 0){
                    gts_args->token[0][p] = temp;
                    value += 2;
                    p++;
                } else {
                    break;
                }
        }
        
    }
    
    return 0;
}

int init_gts_args(gts_args_t *gts_args){
    if (0 != json_parse(gts_args, "/home/fregie/GTS/samples/client.json")){
        printf("json parse failed");
        return -1;
    }
    // gts_args->port = 6666;
    // gts_args->server = strdup("192.168.77.1");
    
    if (gts_args->mode == GTS_MODE_SERVER){
        gts_args->shell_up = strdup("./samples/server_up.sh");
        gts_args->shell_down = strdup("./samples/server_down.sh");
        gts_args->intf = strdup("GTSs_tun");
        
    }else if (gts_args->mode == GTS_MODE_CLIENT){
        gts_args->shell_up = strdup("./samples/client_up.sh");
        gts_args->shell_down = 
        gts_args->intf = strdup("GTSc_tun");
        gts_args->server_addr.sin_family = AF_INET;
        gts_args->server_addr.sin_port = htons(gts_args->port);
        gts_args->server_addr.sin_addr.s_addr = inet_addr(gts_args->server);
    }else {
        printf("unknow mode");
        return -1;
    }
    // gts_args->header_key = strdup("1234ABCD");
    
    // gts_args->GTS_header_len = 32;
    // gts_args->ver_len = 1;
    // gts_args->token_len = 7;
    // gts_args->nonce_len = 8; 
    // gts_args->auth_info_len = 16;
    gts_args->ver = 1;
    // gts_args->token = "ABCDEFG";
    
    gts_args->mtu = TUN_MTU;
    
    gts_args->udp_buf = malloc(gts_args->mtu + GTS_HEADER_LEN);
    gts_args->tun_buf = malloc(gts_args->mtu + GTS_HEADER_LEN);
    
    gts_args->remote_addr_len = sizeof(gts_args->remote_addr);
    
    return 0;
}