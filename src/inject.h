#ifndef __INJECT_H__
#define __INJECT_H__

#include "common.h"
#include "file.h"
#include "mem.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>


#define mypid_default (mypid_t){ 0, NULL }

typedef struct mypid {
	pid_t number;
	char *str;
} mypid_t;


void ptrace_inject(const char *sc, size_t len, mypid_t pid, int nonsave);


#endif
