#include <sodium.h>
#include "crypto_secretbox_salsa208poly1305.h"

int crypto_secretbox_salsa208poly1305(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  if (mlen < 0) return -1;
  crypto_stream_salsa208_xor(c+32,m,mlen,n,k);
  crypto_onetimeauth_poly1305(c + 16,c + 32,mlen,k);
  return 0;
}

int crypto_secretbox_salsa208poly1305_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  // unsigned char subkey[32];
  if (clen < 32) return -1;
  // crypto_stream_salsa208(subkey,32,n,k);
  if (crypto_onetimeauth_poly1305_verify(c + 16,c + 32,clen - 32,k) != 0) return -1;
  crypto_stream_salsa208_xor(m+32,c+32,clen-32,n,k);
  return 0;
}
