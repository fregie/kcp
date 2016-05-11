#ifndef _ACTION_H_
#define _ACTION_H_

#include "args.h"
#include "des.h"
#include "hash.h"

#include <signal.h>
#include <errno.h>
#include <sys/stat.h>

void print_help();
int tun_create(const char *dev);
int init_UDP_socket(char* server_address, uint16_t server_port);
int init_IPC_socket();
int max(int a, int b);
fd_set init_select(gts_args_t *gts_args);
unsigned char* encrypt_GTS_header(uint8_t *ver, char *token, key_set* key_sets); //encrypt ver and token
int api_request_parse(hash_ctx_t *ctx,char *data, gts_args_t *gts_args);
char* generate_stat_info(hash_ctx_t *ctx);
int init_log_file(char *filename);
int write_pid_file(char *filename, pid_t pid);
int set_env(gts_args_t *gts_args);

#endif