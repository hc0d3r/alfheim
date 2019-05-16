#ifndef __PS_INJECT__
#define __PS_INJECT__

#include "inject.h"

#define inject_options_default (inject_options_t){ NULL, NULL, ps_inject_default }

typedef struct inject_options {
    char *filename;
    char *shellcode;
    ps_inject_t options;
} inject_options_t;


void parser_args(int argc, char **argv, inject_options_t *opt);
void banner(void);
void help(void);
int inject_code(inject_options_t *opts);

#endif
