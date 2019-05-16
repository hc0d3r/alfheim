#ifndef __STR_H__
#define __STR_H__

#include "common.h"
#include "mem.h"
#include <ctype.h>
#include <limits.h>

typedef struct {
    char *ptr;
    size_t len;
} dynptr_t;

void str2bytecode(const char *shellcode, dynptr_t *code);

#endif
