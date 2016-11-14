#include "action.h"


#define PID_BUF_SIZE 32
#define DATA_LEN 20


static const char *help_message =
"\n"
"usage:     GTS-server -c config_file [-d start/stop/restart]\n"
"           GTS-client -c config_file [-d start/stop/restart] [-k header_key]\n"
"\n"
"example:   sudo GTS-server -c /etc/GTS/server.json -d start\n"
"           sudo GTS-client -c /etc/GTS/client.json\n"
"\n"
"header_key of client is not necessary(if not provide here, it must be provided in config_file)\n"
"header_key here must be 8 Byte encryped by des then encode by base 64\n\n"
"\n"
"GTS-----geewan transmit system\n\n";

void print_help(){
  printf("%s",help_message);
}

int tun_create(const char *dev){
  struct ifreq ifr;
  int fd, e;
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    errf("can not open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if(*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if ((e = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0){
    errf("ioctl[TUNSETIFF]");
    errf("can not setup tun device: %s \nplease run with root!", dev);
    close(fd);
    return -1;
  }
  // strcpy(dev, ifr.ifr_name);
  return fd;
}

int init_UDP_socket(char* server_address, uint16_t server_port){
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1){
        errf("Create socket failed:");
    }
    if (-1 == bind(sock, (struct sockaddr*)&addr, sizeof(addr))){
        errf("Server bind failed:");
        return -1;
    }
    
    return sock;
}

int init_IPC_socket(){
    int pmmanager_fd, ret;
    socklen_t len;
    struct sockaddr_un pmmanager_addr, pmapi_addr;
    
    //create pmmanager socket fd
    pmmanager_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if(pmmanager_fd == -1){
    errf("cannot create pmmanager fd.");
    }

    unlink(IPC_FILE);
    memset(&pmmanager_addr, 0, sizeof(pmmanager_addr));
    pmmanager_addr.sun_family = AF_UNIX;
    strncpy(pmmanager_addr.sun_path, IPC_FILE, sizeof(pmmanager_addr.sun_path)-1);

    //bind pmmanager_fd to pmmanager_addr
    ret = bind(pmmanager_fd, (struct sockaddr*)&pmmanager_addr, sizeof(pmmanager_addr));
    if(ret == -1){
    errf("can not bind pmmanager_addr");
    }
    
    int recvBufSize;
    len = sizeof(recvBufSize);
    ret = getsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, &len);
    if(ret ==-1){
        errf("getsocket error.");
    }
    recvBufSize = 512*1024;
    ret = setsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, len);
    if(ret == -1){
        errf("setsockopt error.");
    }
    ret = getsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, &len);
    if(ret ==-1){
        errf("getsocket error.");
    }
    return pmmanager_fd;
}

unsigned char* encrypt_GTS_header(uint8_t *ver, char *token, uint8_t flag, DES_key_schedule* ks){
    unsigned char* data_block = malloc(8*sizeof(char));
    unsigned char* encrypted_header = malloc(8*sizeof(char));
    memcpy(data_block, ver,VER_LEN);
    memset(data_block + VER_LEN, flag, FLAG_LEN);
    memcpy(data_block + VER_LEN + FLAG_LEN, token, TOKEN_LEN);
    DES_ecb_encrypt((const_DES_cblock*)data_block, (DES_cblock*)encrypted_header, ks, DES_ENCRYPT);
    free(data_block);
    return (unsigned char*)encrypted_header;
}

int api_request_parse(hash_ctx_t *ctx, char *data, gts_args_t *gts_args){
    char *act;
    cJSON *json;
    json = cJSON_Parse(data);
    if(!json){
        errf("request parse failed");
        return -1;
    }
    if (cJSON_HasObjectItem(json,"act") == 1 && cJSON_GetObjectItem(json,"act")->type == cJSON_String){
        act = cJSON_GetObjectItem(json,"act")->valuestring;
    }else{
        errf("no act");
        cJSON_Delete(json);
        return -1;
    }
    if (strcmp(act,"add_user") == 0){
        client_info_t *client = malloc(sizeof(client_info_t));
        client_info_t *temp_client = NULL;
        bzero(client, sizeof(client_info_t));
        if (cJSON_HasObjectItem(json,"token") == 1){
            char *token = cJSON_GetObjectItem(json,"token")->valuestring;
            int p = 0;
            while (p < TOKEN_LEN){
                unsigned int temp;
                int r = sscanf(token, "%2x", &temp);
                if(r > 0){
                    client->token[p] = temp;
                    token += 2;
                    p++;
                }else{
                    break;
                }
            }
        }else{
            errf("no token");
            free(client);
            cJSON_Delete(json);
            return -1;
        }
        HASH_FIND(hh1, ctx->token_to_clients, client->token, TOKEN_LEN, temp_client);
        if (temp_client != NULL){
            errf("add user failed,token already exsist");
            free(client);
            cJSON_Delete(json);
            return -1;
        }
        if (cJSON_HasObjectItem(json,"password") != 1){
            errf("no password");
            free(client);
            cJSON_Delete(json);
            return -1;
        }
        char* password = cJSON_GetObjectItem(json,"password")->valuestring;
        crypto_generichash(client->key, sizeof client->key, 
                            (unsigned char *)password,
                            strlen(password), NULL, 0);
        DES_key_schedule ks;
        DES_set_key_unchecked((const_DES_cblock*)gts_args->header_key, &ks);
        client->encrypted_header = encrypt_GTS_header(&gts_args->ver, client->token, FLAG_MSG, &ks);
        client->rx = 0;
        client->tx = 0;
        client->over_date = 0;
        if (cJSON_HasObjectItem(json,"txquota") == 1 && cJSON_GetObjectItem(json,"txquota")->type == cJSON_Number){
            client->txquota = cJSON_GetObjectItem(json,"txquota")->valueint;
            if (client->txquota == -1){
                client->txquota = UNLIMIT;
            }else{
                client->txquota = client->txquota * 1024;
            }
        }else{
            client->txquota = UNLIMIT;
        }
        if (cJSON_HasObjectItem(json,"expire") == 1){
            char* data = cJSON_GetObjectItem(json,"expire")->valuestring;
            client->expire = malloc(sizeof(struct tm));
            char *p = strchr(data, '/');
            *p = 0; 
            p++;
            client->expire->tm_year = atol(data);
            data = p;
            p = strchr(data, '/');
            *p = 0;
            p++;
            client->expire->tm_mon = atol(data);
            data = p;
            p = strchr(data, ' ');
            *p = 0;
            p++;
            client->expire->tm_mday = atol(data);
            data = p;
            p = strchr(data, ':');
            *p = 0;
            p++;
            client->expire->tm_hour = atol(data);
            data = p;
            p = strchr(data, ':');
            *p = 0;
            p++;
            client->expire->tm_min = atol(data);
            data = p;
            client->expire->tm_sec = atol(data);
        }else{
            client->expire = NULL;
        }
        int i;
        for (i = 0;i < MAX_USER;i++){
            uint32_t temp_ip = htonl(gts_args->netip + i +1);
            temp_client = NULL;
            HASH_FIND(hh2, ctx->ip_to_clients, &temp_ip, 4,temp_client);
            if(temp_client == NULL){
                client->output_tun_ip = temp_ip;
                break;
            }
        }
        client->source_addr.addrlen = NO_SOURCE_ADDR;
        if(client == NULL){
            errf("add user failed!,may be too many user");
            free(client);
            cJSON_Delete(json);
            return -1;
        }
        HASH_ADD(hh1, ctx->token_to_clients, token, TOKEN_LEN, client);
        HASH_ADD(hh2, ctx->ip_to_clients, output_tun_ip, 4, client);
        cJSON_Delete(json);
        return 0;
    }else if(strcmp(act,"del_user") == 0){
        char *token = cJSON_GetObjectItem(json,"token")->valuestring;
        char real_token[TOKEN_LEN];
        int p = 0;
        while (p < 7){
            unsigned int temp;
            int r = sscanf(token, "%2x", &temp);
            if(r > 0){
                real_token[p] = temp;
                token += 2;
                p++;
            }else{
                break;
            }
        }
        client_info_t *client;
        HASH_FIND(hh1, ctx->token_to_clients, real_token, TOKEN_LEN, client);
        if(client == NULL){
            errf("can't find token from hash table");
            return -1;
        }
        errf("outout ip: %u", client->output_tun_ip);
        HASH_DELETE(hh1,ctx->token_to_clients, client);
        HASH_DELETE(hh2,ctx->ip_to_clients, client);
        free(client);
    }else if(strcmp(act,"show_stat") == 0){
        cJSON_Delete(json);
        return 1;
    }else{
        errf("unknow act cmd");
        cJSON_Delete(json);
        return -1;
    }
    cJSON_Delete(json);
    return 0;
}

char* generate_stat_info(hash_ctx_t *ctx){
    char *output;
    cJSON *root,*info;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddItemToObject(root, "stat", info = cJSON_CreateArray());
    client_info_t *client;
    char *print_token = malloc(TOKEN_LEN*2+1);
    char *print_data = malloc(DATA_LEN);
    for(client = ctx->token_to_clients; client != NULL; client=client->hh1.next){
        cJSON *user;
        cJSON_AddItemToArray(info, user = cJSON_CreateObject());
        sprintf(print_token, "%02x%02x%02x%02x%02x%02x",(uint8_t)client->token[0],
                (uint8_t)client->token[1], (uint8_t)client->token[2],(uint8_t)client->token[3],
                (uint8_t)client->token[4], (uint8_t)client->token[5]);
        cJSON_AddStringToObject(user, "token", print_token);
        if (client->txquota <= UNLIMIT){
            cJSON_AddNumberToObject(user, "txquota", -1);
        }else{
            cJSON_AddNumberToObject(user, "txquota", client->txquota/1024);
        }
        if (client->expire != NULL){
            sprintf(print_data, "%d/%d/%d %d:%d:%d", 
                    client->expire->tm_year, client->expire->tm_mon,
                    client->expire->tm_mday, client->expire->tm_hour, 
                    client->expire->tm_min, client->expire->tm_sec);
            cJSON_AddStringToObject(user, "expire", print_data);
        }
        cJSON_AddNumberToObject(user, "tx", client->tx);
        cJSON_AddNumberToObject(user, "rx", client->rx);
    }
    output = cJSON_Print(root);
    cJSON_Delete(root);
    free(print_token);
    free(print_data);
    return output;
}

int init_log_file(char *filename){
    // then rediret stdout & stderr
    fclose(stdin);
    FILE *fp;
    fp = freopen(filename, "a", stdout);
    if (fp == NULL) {
        err("freopen");
        return -1;
    }
    fp = freopen(filename, "a", stderr);
    if (fp == NULL) {
        err("freopen");
        return -1;
    }

    return 0;
}

int write_pid_file(char *filename, pid_t pid) {
    char buf[PID_BUF_SIZE];
    int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        errf("can not open %s", filename);
        err("open");
        return -1;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        err("fcntl");
        return -1;
    }

    flags |= FD_CLOEXEC;
    if (-1 == fcntl(fd, F_SETFD, flags))
        err("fcntl");

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (-1 == fcntl(fd, F_SETLK, &fl)) {
        ssize_t n = read(fd, buf, PID_BUF_SIZE - 1);
        if (n > 0) {
        buf[n] = 0;
        errf("already started at pid %ld", atol(buf));
        } else {
        errf("already started");
        }
        close(fd);
        return -1;
    }
    if (-1 == ftruncate(fd, 0)) {
        err("ftruncate");
        return -1;
    }
    snprintf(buf, PID_BUF_SIZE, "%ld\n", (long)getpid());

    if (write(fd, buf, strlen(buf)) != strlen(buf)) {
        err("write");
        return -1;
    }
    return 0;
}

int set_env(gts_args_t *gts_args){
    if (-1 == setenv("server", gts_args->server, 1)) {
        err("setenv");
    }
    if (-1 == setenv("intf", gts_args->intf, 1)) {
        err("setenv");
    }
    char *mtu = malloc(10);
    sprintf(mtu, "%d",(int)gts_args->mtu);
    if (-1 == setenv("mtu", mtu, 1)){
        err("setenv");
    }
    if (-1 == setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1)){
        err("setenv");
    }
    return 0;
}
