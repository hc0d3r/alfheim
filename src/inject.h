#ifndef __INJECT_H__
#define __INJECT_H__

#include "common.h"
#include "file.h"
#include "mem.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>

#define wordsize sizeof(long)

#if __x86_64__
	#define IP RIP
#else
	#define IP EIP
#endif

#define mypid_default (mypid_t){ 0, NULL }

typedef struct mypid {
	pid_t number;
	char *str;
} mypid_t;


void ps_inject(const char *sc, size_t len, mypid_t pid, int save, int use_ptrace);


#endif
