#ifndef CRYPTO_H
#define CRYPTO_H

/* call once after start */
int crypto_init();

// TODO use a struct to hold context instead
/* call when password changed */
int crypto_set_password(const char *password,
                        unsigned long long password_len);

int crypto_encrypt(unsigned char *c, unsigned char *m,
                   unsigned long long mlen, unsigned char *key);

int crypto_decrypt(unsigned char *m, unsigned char *c,
                   unsigned long long clen, unsigned char *key);

#define SHADOWVPN_KEY_LEN 32

/*
   buffer layout

   [SALSA20_RESERVED 8] [NONCE 8] [MAC 16] [OPTIONAL USERTOKEN 8] [PAYLOAD MTU]

   Buffer total size:
   SHADOWVPN_ZERO_BYTES + USERTOKEN + MTU

   TUN reads & writes at:
   SHADOWVPN_ZERO_BYTES + USERTOKEN

   UDP packet sendto & recvfrom at:
   SHADOWVPN_PACKET_OFFSET = SALSA20_RESERVED

   Plain text starts from in buffer:
   SHADOWVPN_ZERO_BYTES    = SALSA20_RESERVED + NONCE + MAC

   Plain text starts from in UDP packet:
   SHADOWVPN_OVERHEAD_LEN  = NONCE + MAC

*/

#define SHADOWVPN_ZERO_BYTES 32
#define SHADOWVPN_OVERHEAD_LEN 24
#define SHADOWVPN_PACKET_OFFSET 8
#define SHADOWVPN_USERTOKEN_LEN 8

#endif
