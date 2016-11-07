#include "nat.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include "portable_endian.h"
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ADD_CHECKSUM_32(acc, u32){ \
    acc += (u32) & 0xffff; \
    acc += (u32) >> 16; \
}

#define SUB_CHECKSUM_32(acc, u32){ \
    acc -= (u32) & 0xffff; \
    acc -= (u32) >> 16; \
}

// acc is the changes (+ old - new)
// cksum is the checksum to adjust
#define ADJUST_CHECKSUM(acc, cksum) { \
  int _acc = acc; \
  _acc += (cksum); \
  if (_acc < 0) { \
    _acc = -_acc; \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) ~_acc; \
  } else { \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) _acc; \
  } \
}

int nat_fix_upstream(client_info_t *client, unsigned char *buf, size_t buflen){
    uint8_t iphdr_len;
    if (buflen < 20){
        errf("nat: ip packet too short");
        return -1;
    }
    ipv4_hdr_t *iphdr = (ipv4_hdr_t *)buf;
    if ((iphdr->ver & 0xf0) != 0x40) {
        // check header, currently IPv4 only
        // bypass IPv6
        return -1;
    }
    iphdr_len = (iphdr->ver & 0x0f) * 4;
    int32_t acc = 0;
    // save tun input ip to client
    client->input_tun_ip = iphdr->saddr;
    
    iphdr->saddr = client->output_tun_ip;
    ADD_CHECKSUM_32(acc, client->input_tun_ip);
    SUB_CHECKSUM_32(acc, iphdr->saddr)
    ADJUST_CHECKSUM(acc, iphdr->checksum);
    
    if (0 == (iphdr->frag & htons(0x1fff))){
        void *ip_payload = buf + iphdr_len;
        if(iphdr->proto == IPPROTO_TCP){
            if (buflen < iphdr_len + 20) {
                errf("nat: tcp packet too short");
                return -1;
            }
            tcp_hdr_t *tcphdr = ip_payload;
            ADJUST_CHECKSUM(acc, tcphdr->checksum);
        }else if(iphdr->proto == IPPROTO_UDP){
            if (buflen < iphdr_len + 8) {
                errf("nat: udp packet too short");
                return -1;
            }
            udp_hdr_t *udphdr = ip_payload;
            ADJUST_CHECKSUM(acc, udphdr->checksum);
        }
    }
    return 0;
}

client_info_t* nat_fix_downstream(hash_ctx_t *hash_ctx, unsigned char *buf, size_t buflen){
    uint8_t iphdr_len;
    if (buflen < 20){
        errf("nat:ip packet too short");
        return NULL;
    }
    ipv4_hdr_t *iphdr = (ipv4_hdr_t *)buf;
    if ((iphdr->ver & 0xf0) != 0x40){
        // check header, currently IPv4 only
        // bypass IPv6
        return NULL;
    }
    iphdr_len = (iphdr->ver & 0x0f) * 4;
    
    client_info_t *client = NULL;
    HASH_FIND(hh2, hash_ctx->ip_to_clients, &iphdr->daddr, 4, client);
    if (client == NULL) {
        // errf("nat: client not found for given user ip");
        return NULL;
    }
    int32_t acc = 0;
    ADD_CHECKSUM_32(acc, iphdr->daddr);
    SUB_CHECKSUM_32(acc, client->input_tun_ip);
    iphdr->daddr = client->input_tun_ip;
    ADJUST_CHECKSUM(acc, iphdr->checksum);
    
    if (0 == (iphdr->frag & htons(0x1fff))){
        // only adjust tcp & udp when frag offset == 0
        void *ip_payload = buf + iphdr_len;
        if (iphdr->proto == IPPROTO_TCP) {
            if (buflen < iphdr_len + 20) {
            errf("nat: tcp packet too short");
            return NULL;
            }
            tcp_hdr_t *tcphdr = ip_payload;
            ADJUST_CHECKSUM(acc, tcphdr->checksum);
        }else if(iphdr->proto == IPPROTO_UDP){
            if (buflen < iphdr_len + 8){
                errf("nat: udp packet too short");
                return NULL;
            }
            udp_hdr_t *udphdr = ip_payload;
            ADJUST_CHECKSUM(acc, udphdr->checksum);
        }
    }
    return client;
}