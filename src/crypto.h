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

#endif
