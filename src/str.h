#ifndef __STR_H__
#define __STR_H__

#include <stddef.h>

typedef struct {
    char *ptr;
    size_t len;
} dynptr_t;

void str2bytecode(const char *shellcode, size_t len, dynptr_t *code);

#endif
