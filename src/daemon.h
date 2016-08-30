#ifndef DAEMON_H
#define DAEMON_H

#include "args.h"

/*
   return 0 if success and in child, will also redirect stdout and stderr
   not return if master
   return non-zero if error
*/
int daemon_start(const gts_args_t *gts_args);

/*
   return 0 if success
   return non-zero if error
*/
int daemon_stop(const gts_args_t *gts_args);

#endif