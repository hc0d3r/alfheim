#ifndef __INJECT_H__
#define __INJECT_H__

#include "common.h"
#include "file.h"
#include "mem.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define wordsize sizeof(long)

#if defined (__x86_64__) || defined (__i386__)
	#include <sys/reg.h>
	#define BREAKPOINT "\xcc"
	#define BREAKPOINT_LEN 1
#endif

#ifdef __x86_64__
	#define IP RIP
#elif __i386__
	#define IP EIP
#elif __arm__
	#define IP 15 /* PC register */
	#define BREAKPOINT "\xe7\xf0\x01\xf0"
	#define BREAKPOINT_LEN 4
#else
	#error unsupported architeture
#endif

#define mypid_default (mypid_t){ 0, NULL }

typedef struct mypid {
	pid_t number;
	char *str;
} mypid_t;


void ps_inject(const char *sc, size_t len, mypid_t pid, int save, int use_ptrace);


#endif
