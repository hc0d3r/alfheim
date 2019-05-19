#ifndef __PS_INJECT__
#define __PS_INJECT__

#include "inject.h"

#define default_options (options_t){ NULL, NULL, default_inject }

typedef struct {
    char *filename;
    char *shellcode;
    inject_t options;
} options_t;

void parser_args(int argc, char **argv, options_t *opt);
void banner(void);
void help(void);
int inject_code(options_t *opts);

#endif
