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
    cJSON *password;
    json=cJSON_Parse(data);
	if (!json){
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        return -1;
    }
    if (cJSON_HasObjectItem(json,"server") == 1){
        gts_args->server = strdup(cJSON_GetObjectItem(json,"server")->valuestring);
    }else{
        printf("can't find server ip in config file\n");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"port") == 1){
        gts_args->port = cJSON_GetObjectItem(json,"port")->valueint;
    }else{
        printf("can't find port\n");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"header key") == 1){
        gts_args->header_key = strdup(cJSON_GetObjectItem(json,"header key")->valuestring);
    }else{
        printf("can't find header key\n");
        gts_args->header_key = strdup("fregieonly");
    }
    if (cJSON_HasObjectItem(json,"shell_up") == 1){
        gts_args->shell_up = strdup(cJSON_GetObjectItem(json,"shell_up")->valuestring);
    }else{
        printf("can't find shell_up");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"shell_down") == 1){
        gts_args->shell_down = strdup(cJSON_GetObjectItem(json,"shell_down")->valuestring);
    }else{
        printf("can't find shell_down");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"logfile") == 1){
        gts_args->log_file = strdup(cJSON_GetObjectItem(json,"logfile")->valuestring);
    }else{
        gts_args->log_file = strdup("/var/log/GTS-client.log");
    }
    if (cJSON_HasObjectItem(json,"intf") == 1){
        gts_args->intf =strdup(cJSON_GetObjectItem(json,"intf")->valuestring);
    }else{
        gts_args->intf = strdup("GTS_tun");
    }
    if (cJSON_HasObjectItem(json,"net") == 1){
        char *net = strdup(cJSON_GetObjectItem(json,"net")->valuestring);
        setenv("net", net, 1);
        char *p = strchr(net, '/');
        if (p) *p = 0;
        in_addr_t addr = inet_addr(net);
        gts_args->netip = ntohl((uint32_t)addr);
        free(net);
    }else{
        printf("can't find netip");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"mtu") == 1){
        gts_args->mtu = cJSON_GetObjectItem(json,"mtu")->valueint;
    }else{
        gts_args->mtu = TUN_MTU;
    }
    gts_args->pid_file = strdup(cJSON_GetObjectItem(json,"pidfile")->valuestring);
    if (cJSON_HasObjectItem(json,"password") == 1 && cJSON_HasObjectItem(json,"token") == 1){
        if (gts_args->mode == GTS_MODE_SERVER){
            if (cJSON_GetArraySize(cJSON_GetObjectItem(json,"password")) != cJSON_GetArraySize(cJSON_GetObjectItem(json,"token"))){
                printf("token numbers != password numbers\n");
                return -1;
            }
            //init password
            gts_args->password = malloc(MAX_USER*sizeof(char*));
            password = cJSON_GetObjectItem(json,"password")->child;
            int k = 0;
            while (password != 0){
                gts_args->password[k] = strdup(password->valuestring);
                password = password->next;
                k++;
            } 
            //init tokens
            gts_args->token = malloc(MAX_USER*sizeof(char*));
            token_json = cJSON_GetObjectItem(json,"token")->child;
            int i =0;
            gts_args->token_len = 0;
            while (token_json != 0){
                gts_args->token_len++;
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
            gts_args->password = malloc(sizeof(char*));
            if (cJSON_HasObjectItem(json,"password") == 1){
                gts_args->password[0] = strdup(cJSON_GetObjectItem(json,"password")->valuestring);
            }else{
                printf("can't find password\n");
                return -1;
            }
            gts_args->token = malloc(sizeof(char*));
            gts_args->token[0] = malloc(TOKEN_LEN);
            char *value;
            if (cJSON_HasObjectItem(json,"token") == 1){
                value = cJSON_GetObjectItem(json,"token")->valuestring;
            }else{
                printf("can't find token\n");
                return -1;
            }
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
    }
    
    return 0;
}

int init_gts_args(gts_args_t *gts_args,char *conf_file){
    if (0 != json_parse(gts_args, conf_file)){
        printf("json parse failed");
        return -1;
    }
    // gts_args->port = 6666;
    // gts_args->server = strdup("192.168.77.1");
    
    if (gts_args->mode == GTS_MODE_SERVER){
        
    }else if (gts_args->mode == GTS_MODE_CLIENT){
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
    
    
    
    gts_args->udp_buf = malloc(gts_args->mtu + GTS_HEADER_LEN);
    gts_args->tun_buf = malloc(gts_args->mtu + GTS_HEADER_LEN);
    
    gts_args->remote_addr_len = sizeof(gts_args->remote_addr);
    
    return 0;
}