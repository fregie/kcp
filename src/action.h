#ifndef _ACTION_H_
#define _ACTION_H_

#include "args.h"
#include "hash.h"

#include <signal.h>
#include <errno.h>
#include <sys/stat.h>

#define max(a, b) (a)>(b)?(a):(b);

void print_help();
int tun_create(const char *dev);
int init_UDP_socket(char* server_address, uint16_t server_port);
int init_IPC_socket();
unsigned char* encrypt_GTS_header(uint8_t *ver, char *token, DES_key_schedule* ks); //encrypt ver and token
int api_request_parse(hash_ctx_t *ctx,char *data, gts_args_t *gts_args);
char* generate_stat_info(hash_ctx_t *ctx);
int init_log_file(char *filename);
int write_pid_file(char *filename, pid_t pid);
int set_env(gts_args_t *gts_args);

#endif