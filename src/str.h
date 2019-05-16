#ifndef __STR_H__
#define __STR_H__

#include "common.h"
#include "mem.h"
#include <ctype.h>
#include <limits.h>

#define bytecode_string_default (bytecode_string_t){ NULL, 0 }

typedef struct bytecode_string {
    char *ptr;
    size_t len;
} bytecode_string_t;


void str2bytecode(const char *shellcode, bytecode_string_t *code);

#endif
