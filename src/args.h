#ifndef _ARGS_H_
#define _ARGS_H_

#include "des.h"
#include "cJSON.h"
#include "log.h"
#include "crypto.h"
#include "b64.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sodium.h>

#define IPC_FILE "/tmp/GTS.sock"
#define MAX_USER 20
#define TUN_MTU 1432  // 1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 32 (GTS header)
#define GTS_HEADER_LEN 32
#define VER_LEN 1
#define TOKEN_LEN 7
#define NONCE_LEN 8
#define AUTH_INFO_LEN 16

typedef enum{
    GTS_MODE_SERVER = 1,
    GTS_MODE_CLIENT = 2
} gts_mode;



typedef struct{
  gts_mode mode;
  uint16_t port;
  char *server;
  char **password;
  char *shell_up;
  char *shell_down;
  char *intf;
  int mtu;
  // declare fds
  int tun;
  int UDP_sock;
  int IPC_sock;
  //declare buffers
  unsigned char *tun_buf;
  unsigned char *udp_buf;
  //declare client_addr
  struct sockaddr_in server_addr;
  struct sockaddr_in remote_addr;
  socklen_t remote_addr_len;
  
  unsigned char *header_key;
  uint8_t ver;
  char **token;
  size_t token_len;
  char *nonce;
  char *auth_info;
  
  uint32_t netip;
  
  char *log_file;
  char *pid_file;
} gts_args_t;

int init_gts_args(gts_args_t *gts_args, char *conf_file);

#endif