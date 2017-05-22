#include "args.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef IWORDS_BIG_ENDIAN
    #ifdef _BIG_ENDIAN_
        #if _BIG_ENDIAN_
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MISPEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #define IWORDS_BIG_ENDIAN  0
    #endif
#endif

int json_parse(gts_args_t *gts_args, char *filename){
    FILE *f;long len;char *data;
    f=fopen(filename,"rb");
    fseek(f,0,SEEK_END);
    len=ftell(f);
    fseek(f,0,SEEK_SET);
    data=(char*)malloc(len+1);
    if(0 > fread(data,1,len,f)){
        return -1;
    }
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
    if (cJSON_HasObjectItem(json,"server") == 1 && cJSON_GetObjectItem(json,"server")->type == cJSON_String){
        gts_args->server = cJSON_GetObjectItem(json,"server")->valuestring;
    }else{
        printf("can't find server ip in config file\n");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"port") == 1 && cJSON_GetObjectItem(json,"port")->type == cJSON_Number){
        gts_args->port = cJSON_GetObjectItem(json,"port")->valueint;
    }else{
        printf("can't find port\n");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"header_key") == 1 && cJSON_GetObjectItem(json,"header_key")->type == cJSON_String){
        gts_args->header_key = cJSON_GetObjectItem(json,"header_key")->valuestring;
    }else{
        printf("no header key mode\n");
        gts_args->header_key = strdup("fregieonly");
    }
    if (cJSON_HasObjectItem(json,"encrypt") == 1 && cJSON_GetObjectItem(json,"encrypt")->type == cJSON_Number){
        gts_args->encrypt = cJSON_GetObjectItem(json,"encrypt")->valueint;
        if(gts_args->encrypt != 0){
            gts_args->encrypt = 1;
            printf("encrypt: yes\n");
        }else{
            printf("encrypt: no\n");
        }
    }else{
        gts_args->encrypt = 0;
        printf("encrypt: no\n");
    }
    if (gts_args->mode == GTS_MODE_CLIENT){
        if (cJSON_HasObjectItem(json,"ver") == 1 && cJSON_GetObjectItem(json,"ver")->type == cJSON_Number){
            gts_args->ver = cJSON_GetObjectItem(json,"ver")->valueint;
        }else{
            gts_args->ver = GTS_VER_1;
        }
    }else{
        gts_args->ver = GTS_VER;
    }
    if (cJSON_HasObjectItem(json,"beat_time") == 1 && cJSON_GetObjectItem(json,"beat_time")->type == cJSON_Number){
        gts_args->beat_time = cJSON_GetObjectItem(json,"beat_time")->valueint;
        printf("beat time: %ds\n", gts_args->beat_time);
    }else{
        gts_args->beat_time = 20;
        printf("no beat time found,default beat time: 20s\n");
    }
    if (cJSON_HasObjectItem(json,"shell_up") == 1  && cJSON_GetObjectItem(json,"shell_up")->type == cJSON_String){
        gts_args->shell_up = cJSON_GetObjectItem(json,"shell_up")->valuestring;
        if (access(gts_args->shell_up, R_OK) == -1){
            errf("GTS up script can't find");
            return -1;
        }
    }else{
        if (gts_args->mode == GTS_MODE_CLIENT){
            gts_args->shell_up = strdup("/etc/gts/client_up.sh");
        }else{
            gts_args->shell_up = strdup("/etc/gts/server_up.sh");
        }
        if (access(gts_args->shell_up, R_OK) == -1){
            errf("GTS up script can't find");
            return -1;
        }
    }
    if (cJSON_HasObjectItem(json,"shell_down") == 1  && cJSON_GetObjectItem(json,"shell_down")->type == cJSON_String){
        gts_args->shell_down = cJSON_GetObjectItem(json,"shell_down")->valuestring;
        if (access(gts_args->shell_down, R_OK) == -1){
            errf("GTS down script can't find");
            return -1;
        }
    }else{
        if (gts_args->mode == GTS_MODE_CLIENT){
            gts_args->shell_down = strdup("/etc/gts/client_down.sh");
        }else{
            gts_args->shell_down = strdup("/etc/gts/server_down.sh");
        }
        if (access(gts_args->shell_down, R_OK) == -1){
            errf("GTS down script can't find");
            return -1;
        }
    }
    if (cJSON_HasObjectItem(json,"logfile") == 1 && cJSON_GetObjectItem(json,"logfile")->type == cJSON_String){
        gts_args->log_file = cJSON_GetObjectItem(json,"logfile")->valuestring;
    }else{
        gts_args->log_file = strdup("/var/log/GTS-client.log");
    }
    if (cJSON_HasObjectItem(json,"pidfile") == 1 && cJSON_GetObjectItem(json,"pidfile")->type == cJSON_String){
        gts_args->pid_file = cJSON_GetObjectItem(json,"pidfile")->valuestring;
    }else{
        gts_args->pid_file = strdup("/var/run/gts.pid");
    }
    if (cJSON_HasObjectItem(json,"ipcfile") == 1 && cJSON_GetObjectItem(json,"ipcfile")->type == cJSON_String){
        gts_args->ipc_file = cJSON_GetObjectItem(json,"ipcfile")->valuestring;
    }else{
        gts_args->ipc_file = strdup("/tmp/GTS.sock");
    }
    if (cJSON_HasObjectItem(json,"intf") == 1 && cJSON_GetObjectItem(json,"intf")->type == cJSON_String){
        gts_args->intf = cJSON_GetObjectItem(json,"intf")->valuestring;
    }else{
        gts_args->intf = strdup("GTS_tun");
    }
    if (cJSON_HasObjectItem(json,"net") == 1 && cJSON_GetObjectItem(json,"net")->type == cJSON_String){
        char *net = cJSON_GetObjectItem(json,"net")->valuestring;
        setenv("net", net, 1);
        char *p = strchr(net, '/');
        if (p == NULL){
            errf("can't parse net'");
            return -1;
        }else{
            *p = 0;
        }
        in_addr_t addr = inet_addr(net);
        if (addr == INADDR_NONE){
            errf("can't parse net");
            return -1;
        }
        gts_args->netip = ntohl((uint32_t)addr);
        free(net);
    }else{
        char *net = strdup("10.1.0.2/24");
        setenv("net", net, 1);
        char *p = strchr(net, '/');
        if (p) *p = 0;
        in_addr_t addr = inet_addr(net);
        gts_args->netip = ntohl((uint32_t)addr);
        free(net);
    }
    if (cJSON_HasObjectItem(json,"mtu") == 1 && cJSON_GetObjectItem(json,"mtu")->type == cJSON_Number){
        gts_args->mtu = cJSON_GetObjectItem(json,"mtu")->valueint;
    }else{
        gts_args->mtu = TUN_MTU;
    }
    if (cJSON_HasObjectItem(json,"out_intf") == 1 && cJSON_GetObjectItem(json,"out_intf")->type == cJSON_String){
         gts_args->out_intf = cJSON_GetObjectItem(json,"out_intf")->valuestring;
    }else{
        if (gts_args->mode == GTS_MODE_SERVER){
            //get out interface name ,for traffic contrl
            gts_args->out_intf = malloc(MAX_INTF_LEN);
            FILE *stream = popen("ip route show 0/0 | sed -e 's/.* dev \\([^ ]*\\).*/\\1/'", "r" );
            if (fgets(gts_args->out_intf, MAX_INTF_LEN, stream) == NULL){
                printf("get out interface failed, traffic control may not work");
            }
            pclose(stream);
            char *temp =strchr(gts_args->out_intf, '\n');
            if ( temp!= NULL) {*temp = 0;}
            printf("output interface dev: %s\n", gts_args->out_intf);
        }
    }
    if (gts_args->mode == GTS_MODE_CLIENT){
        if (cJSON_HasObjectItem(json,"kcp_sndwnd") == 1 && cJSON_GetObjectItem(json,"kcp_sndwnd")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.sndwnd, cJSON_GetObjectItem(json,"kcp_sndwnd")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.sndwnd, KCP_DEFAULT_SNDWND);

        if (cJSON_HasObjectItem(json,"kcp_rcvwnd") == 1 && cJSON_GetObjectItem(json,"kcp_rcvwnd")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.rcvwnd, cJSON_GetObjectItem(json,"kcp_rcvwnd")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.rcvwnd, KCP_DEFAULT_RCVWND);

        if (cJSON_HasObjectItem(json,"kcp_nodelay") == 1 && cJSON_GetObjectItem(json,"kcp_nodelay")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.nodelay, cJSON_GetObjectItem(json,"kcp_nodelay")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.nodelay, KCP_DEFAULT_NODELAY);

        if (cJSON_HasObjectItem(json,"kcp_interval") == 1 && cJSON_GetObjectItem(json,"kcp_interval")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.interval, cJSON_GetObjectItem(json,"kcp_interval")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.interval, KCP_DEFAULT_INTERVAL);

        if (cJSON_HasObjectItem(json,"kcp_resend") == 1 && cJSON_GetObjectItem(json,"kcp_resend")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.resend, cJSON_GetObjectItem(json,"kcp_resend")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.resend, KCP_DEFAULT_RESEND);

        if (cJSON_HasObjectItem(json,"kcp_nc") == 1 && cJSON_GetObjectItem(json,"kcp_nc")->type == cJSON_Number)
            encode_int32(&gts_args->kcp_conf.nc, cJSON_GetObjectItem(json,"kcp_nc")->valueint);
        else
            encode_int32(&gts_args->kcp_conf.nc, KCP_DEFAULT_NC);
    }
    if (cJSON_HasObjectItem(json,"token") == 1){
        if (gts_args->mode == GTS_MODE_SERVER){
            if (cJSON_GetObjectItem(json,"token")->type != cJSON_Array || cJSON_GetObjectItem(json,"password")->type != cJSON_Array){
                printf("token and password of server must be an array");
                return -1;
            }
            if (cJSON_GetArraySize(cJSON_GetObjectItem(json,"password")) != cJSON_GetArraySize(cJSON_GetObjectItem(json,"token"))){
                printf("token numbers != password numbers\n");
                return -1;
            }
            //init password
            gts_args->password = malloc(MAX_USER*sizeof(char*));
            password = cJSON_GetObjectItem(json,"password")->child;
            int k = 0;
            while (password != 0){
                gts_args->password[k] = password->valuestring;
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
                while(*value && p < TOKEN_LEN){
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
            if (cJSON_GetObjectItem(json,"token")->type != cJSON_String || cJSON_GetObjectItem(json,"password")->type != cJSON_String){
                printf("token and password of client must string");
                return -1;
            }
            //init password
            gts_args->password = malloc(sizeof(char*));
            if (cJSON_HasObjectItem(json,"password") == 1){
                gts_args->password[0] = cJSON_GetObjectItem(json,"password")->valuestring;
            }else{
                printf("can't find password\n");
                return -1;
            }
            // init token
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
            while(*value && p < TOKEN_LEN){
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
    if (access(conf_file, F_OK) != 0){
        printf("cant't find file %s \n", conf_file);
        return -1;
    }
    if (0 != json_parse(gts_args, conf_file)){
        return -1;
    }
    
    if (gts_args->mode == GTS_MODE_SERVER){
        
    }else if (gts_args->mode == GTS_MODE_CLIENT){
        gts_args->server_addr.sin_family = AF_INET;
        gts_args->server_addr.sin_port = htons(gts_args->port);
        gts_args->server_addr.sin_addr.s_addr = inet_addr(gts_args->server);
    }else {
        printf("unknow mode");
        return -1;
    }
    gts_args->recv_buf = malloc(MAX_MTU_LEN);
    
    gts_args->remote_addr_len = sizeof(gts_args->remote_addr);
    
    return 0;
}

void encode_int32(int *dst, int src){
#if IWORDS_BIG_ENDIAN
	*(unsigned char*)(dst + 0) = (unsigned char)((src >>  0) & 0xff);
	*(unsigned char*)(dst + 1) = (unsigned char)((src >>  8) & 0xff);
	*(unsigned char*)(dst + 2) = (unsigned char)((src >> 16) & 0xff);
	*(unsigned char*)(dst + 3) = (unsigned char)((src >> 24) & 0xff);
#else
	*dst = src;
#endif
}

void decode_int32(int *dst, int *src){
#if IWORDS_BIG_ENDIAN
	*dst = *(const unsigned char*)(src + 3);
	*dst = *(const unsigned char*)(src + 2) + (*dst << 8);
	*dst = *(const unsigned char*)(src + 1) + (*dst << 8);
	*dst = *(const unsigned char*)(src + 0) + (*dst << 8);
#else 
	*dst = *src;
#endif
}