#ifndef __MEM_H__
#define __MEM_H__

#include "common.h"
#include "file.h"
#include <sys/mman.h>

#define maped_file_default (maped_file_t){ NULL, 0, 0 };

typedef struct maped_file {
    char *ptr;
    off_t size;
    int fd;
} maped_file_t;

void memorymap(const char *filename, maped_file_t *mfile);
void memorymapfree(maped_file_t *mfile);
void *xmalloc(size_t size);


#endif
