#ifndef HASH_H
#define HASH_H

#include "args.h"
#include "uthash.h"

#define UNLIMIT -10000
#define OVER_DATE 1
#define NO_SOURCE_ADDR -1

typedef struct {
  struct sockaddr_storage addr;
  socklen_t addrlen;
} addr_info_t;

typedef struct {
  int id;
  char token[TOKEN_LEN];
  unsigned char key[32];
  unsigned char* encrypted_header;
  // source address of UDP
  addr_info_t source_addr;
  // input tun IP
  uint32_t input_tun_ip;
  // output tun IP
  uint32_t output_tun_ip;
  int64_t rx;
  int64_t tx;
  int64_t txquota;
  struct tm *expire;
  int over_date;

  UT_hash_handle hh1;
  UT_hash_handle hh2;
} client_info_t;

typedef struct {
  /* clients map
     key: token */
  client_info_t *token_to_clients;

  /* clients map
     TODO: use index instead of hash
     key: IP */
  client_info_t *ip_to_clients;
} hash_ctx_t;

int init_hash(hash_ctx_t *ctx, gts_args_t *gts_args);

#endif