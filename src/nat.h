#ifndef NAT_H
#define NAT_H

#include "hash.h"

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
   RFC791
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct {
  uint8_t ver;
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t saddr;
  uint32_t daddr;
} ipv4_hdr_t;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint32_t not_interested;
  uint16_t checksum;
  uint16_t upt;
} tcp_hdr_t;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
} udp_hdr_t;

/* UDP -> TUN NAT
   buf starts from payload
*/
int nat_fix_upstream(client_info_t *client, unsigned char *buf, size_t buflen);

/* TUN -> UDP NAT 
   buf starts from payload
*/
client_info_t* nat_fix_downstream(hash_ctx_t *hash_ctx, unsigned char *buf, size_t buflen);

#endif