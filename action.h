#pragma once
#include "args.h"
#include "des.h"

int tun_create(const char *dev);
int init_UDP_socket(char* server_address, uint16_t server_port);
int max(int a, int b);
fd_set init_select(gts_args_t *gts_args);
void set_GTS_header(gts_args_t *gts_args); //encrypt ver and token and set them in header