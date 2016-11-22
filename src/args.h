#ifndef _ARGS_H_
#define _ARGS_H_

#include "cJSON.h"
#include "log.h"
#include "crypto.h"

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
#include <openssl/des.h>
#include <time.h>

#define MAX_USER 255

#define GTS_VER 1
#define GTS_RELEASE_VER "1.0.0"

#define IPC_FILE "/tmp/GTS.sock"
#define TUN_MTU 1432  // 1492 (Ethernet) - 20 (IPv4, or 40 for IPv6) - 8 (UDP) - 32 (GTS header)
#define GTS_HEADER_LEN 32
#define VER_LEN 1
#define FLAG_LEN 1
#define TOKEN_LEN 6
#define NONCE_LEN 8
#define AUTH_INFO_LEN 16
#define HEADER_KEY_LEN 8

#define ENCRYPT_LEN 16 //if not set encrypt, will encrypt 16 bytes for checking password

#define FLAG_MSG 0
#define FLAG_SYN 1
#define FLAG_OK  2
#define FLAG_HEADER_KEY_ERR 3
#define FLAG_TOKEN_ERR 4
#define FLAG_PASSWORD_ERR 5
#define FLAG_OVER_TXQUOTA 6
#define FLAG_OVER_DATE 7
#define FLAG_NO_RESPONSE 8

/*               GTS_header 32bytes
0        8        16                              63
+--------+--------+-------------------------------+
|   ver  |  flag  |             token             |
+-------------------------------------------------+
|                     nonce                       |
+-------------------------------------------------+
|                   auth info                     |
|                                                 |
+-------------------------------------------------+
*/

typedef struct{
  uint8_t ver;
  uint8_t flag;
  char token[6];
  char nonce[8];
  char auth_info[16];
} gts_header_t;

typedef enum{
    GTS_MODE_SERVER = 1,
    GTS_MODE_CLIENT = 2
} gts_mode;

#define MAX_INTF_LEN 30
typedef struct{
  gts_mode mode;
  int encrypt;
  int beat_time;
  uint16_t port;
  char *server;
  char **password;
  char *shell_up;
  char *shell_down;
  char *intf;
  char *out_intf;
  int mtu;
  // declare fds
  int tun;
  int UDP_sock;
  int IPC_sock;
  //declare buffers
  unsigned char *recv_buf;
  //declare client_addr
  struct sockaddr_in server_addr;
  struct sockaddr_in remote_addr;
  socklen_t remote_addr_len;
  
  char *header_key;
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