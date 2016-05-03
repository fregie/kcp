#include "action.h"

//define unix domain socket path


static const char *help_message =
"usage: GTS-server config_file\n"
"       GTS-client config_file\n"
"example:GTS-server /etc/GTS/server.json\n"
"        GTS-client /etc/GTS/client.json\n"
"GTS-----geewan transmit system\n";

void print_help(){
  printf("%s",help_message);
}

int tun_create(const char *dev){
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    printf("can not open /dev/net/tun");
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
    printf("ioctl[TUNSETIFF]");
    printf("can not setup tun device: %s", dev);
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
        perror("Create socket failed:");
        exit(1);
    }
    if (-1 == bind(sock, (struct sockaddr*)&addr, sizeof(addr))){
        perror("Server bind failed:");
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
    perror("cannot create pmmanager fd.");
    }

    unlink(IPC_FILE);
    memset(&pmmanager_addr, 0, sizeof(pmmanager_addr));
    pmmanager_addr.sun_family = AF_UNIX;
    strncpy(pmmanager_addr.sun_path, IPC_FILE, sizeof(pmmanager_addr.sun_path)-1);

    //bind pmmanager_fd to pmmanager_addr
    ret = bind(pmmanager_fd, (struct sockaddr*)&pmmanager_addr, sizeof(pmmanager_addr));
    if(ret == -1){
    perror("can not bind pmmanager_addr");
    }
    
    int recvBufSize;
    len = sizeof(recvBufSize);
    ret = getsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, &len);
    if(ret ==-1){
        perror("getsocket error.");
    }
    // printf("Before setsockopt, SO_RCVBUF-%d\n",recvBufSize); 
    recvBufSize = 512*1024;
    ret = setsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, len);
    if(ret == -1){
        perror("setsockopt error.");
    }
    ret = getsockopt(pmmanager_fd, SOL_SOCKET, SO_RCVBUF, &recvBufSize, &len);
    if(ret ==-1){
        perror("getsocket error.");
    }
    // printf("Set recv buf successful, SO_RCVBUF-%d\n",recvBufSize); 
    // printf("==============wait for msg from pmapi====================\n");
    return pmmanager_fd;
}

int max(int a, int b) {
  return a > b ? a : b;
}

fd_set init_select(gts_args_t *gts_args){
    fd_set readset;
    int max_fd = 0;
    FD_ZERO(&readset);
    FD_SET(gts_args->tun, &readset);
    FD_SET(gts_args->UDP_sock, &readset);
    if(gts_args->mode == GTS_MODE_SERVER){
      FD_SET(gts_args->IPC_sock, &readset);
    }
    max_fd = max(gts_args->tun, max_fd);
    max_fd = max(gts_args->UDP_sock, max_fd);
    if(gts_args->mode == GTS_MODE_SERVER){
      max_fd = max(gts_args->IPC_sock, max_fd);
    }
    select(max_fd+1, &readset, NULL, NULL, NULL);
    return readset;
}

unsigned char* encrypt_GTS_header(uint8_t *ver, char *token, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
    unsigned char* encrypted_header = (unsigned char*) malloc(8*sizeof(char));
    memcpy(data_block, ver,VER_LEN);
    memcpy(data_block + VER_LEN, token, TOKEN_LEN);
    process_message(data_block, encrypted_header, key_sets, ENCRYPTION_MODE);
    free(data_block);
    return encrypted_header;
}

int api_request_parse(hash_ctx_t *ctx, char *data, gts_args_t *gts_args){
    char *act;
    cJSON *json;
    json = cJSON_Parse(data);
    if(!json){
        printf("request parse failed");
        return -1;
    }
    act = strdup(cJSON_GetObjectItem(json,"act")->valuestring);
    if (strcmp(act,"add_user") == 0){
        client_info_t *client = malloc(sizeof(client_info_t));
        bzero(client, sizeof(client_info_t));
        memcpy(client->token, strdup(cJSON_GetObjectItem(json,"token")->valuestring), TOKEN_LEN);
        client->password = strdup(cJSON_GetObjectItem(json,"password")->valuestring);
        key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));
        generate_sub_keys(gts_args->header_key, key_sets);
        client->encrypted_header = encrypt_GTS_header(&gts_args->ver, client->token, key_sets);
        free(key_sets);
        int i;
        for (i = 0;i <255;i++){
            uint32_t temp_ip = htonl(gts_args->netip + i +1);
            client_info_t *temp_client = NULL;
            HASH_FIND(hh2, ctx->ip_to_clients, &temp_ip, 4,temp_client);
            if(temp_client == NULL){
                client->output_tun_ip = temp_ip;
                break;
            }
        }
        if(client == NULL){
            printf("add user failed!,may be too many user");
            return -1;
        }
        HASH_ADD(hh1, ctx->token_to_clients, token, TOKEN_LEN, client);
        HASH_ADD(hh2, ctx->ip_to_clients, output_tun_ip, 4, client);
        return 0;
    }else if(strcmp(act,"del_user") == 0){
        char *token = strdup(cJSON_GetObjectItem(json,"token")->valuestring);
        client_info_t *client = malloc(sizeof(client_info_t));
        HASH_FIND(hh1, ctx->token_to_clients, token, TOKEN_LEN, client);
        HASH_DELETE(hh1,ctx->token_to_clients, client);
        HASH_DELETE(hh2,ctx->ip_to_clients, client);
    }else if(strcmp(act,"show_stat") == 0){
        return 0;
    }else{
        printf("unknow cmd act");
        return -1;
    }
    free(json);
}