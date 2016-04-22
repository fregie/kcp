#ifndef _ARGS_H_
#define _ARGS_H_

#include "des.h"
#include "cJSON.h"
#include "log.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/select.h>

#define UDP_MTU 1500
#define TUN_MTU 1432  // 1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 32 (GTS header)

typedef enum{
    GTS_MODE_SERVER = 1,
    GTS_MODE_CLIENT = 2
} gts_mode;



typedef struct{
  gts_mode mode;
  uint16_t port;
  char *server;
  char *password;
  char *shell_up;
  char *shell_down;
  char *intf;
  int mtu;
  // declare fds
  int tun;
  int UDP_sock;
  //declare buffers
  unsigned char *tun_buf;
  unsigned char *udp_buf;
  //declare client_addr
  struct sockaddr_in server_addr;
  struct sockaddr_in remote_addr;
  socklen_t remote_addr_len;
  
  unsigned char *header_key;
  //GTS header
  size_t GTS_header_len;
  size_t ver_len;
  size_t token_len;
  size_t nonce_len;
  size_t auth_info_len;
  uint8_t ver;
  char *token;
  char *nonce;
  char *auth_info;
} gts_args_t;

int init_gts_args(gts_args_t *gts_args);

#endif