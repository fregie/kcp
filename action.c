#include "action.h"


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

int max(int a, int b) {
  return a > b ? a : b;
}

fd_set init_select(gts_args_t *gts_args){
    fd_set readset;
    int max_fd = 0;
    FD_ZERO(&readset);
    FD_SET(gts_args->tun, &readset);
    FD_SET(gts_args->UDP_sock, &readset);
    max_fd = max(gts_args->tun, max_fd);
    max_fd = max(gts_args->UDP_sock, max_fd);
    select(max_fd, &readset, NULL, NULL, NULL);
    return readset; 
}


unsigned char* encrypt_GTS_header(gts_args_t *gts_args, key_set* key_sets){
    unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
    unsigned char* encrypted_header = (unsigned char*) malloc(8*sizeof(char));
    memcpy(data_block, &gts_args->ver,1);
    memcpy(data_block+gts_args->ver_len, gts_args->token, 7);
    process_message(data_block, encrypted_header, key_sets, ENCRYPTION_MODE);
    return encrypted_header;
}

void decrypt_GTS_header(gts_args_t *gts_args){
    
}