#ifndef __PS_INJECT__
#define __PS_INJECT__

#include "inject.h"

#define inject_options_default (inject_options_t){ NULL, NULL, 1, 0, mypid_default }

typedef struct inject_options {
	char *filename;
	char *shellcode;
	int restore;
	int use_ptrace;
	mypid_t target_pid;
} inject_options_t;


void parser_args(int *argc, char ***argv, inject_options_t *opt);
void banner(void);
void help(void);
int inject_code(inject_options_t *opts);

#endif
