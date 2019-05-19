#include <sys/mman.h>
#include <stdlib.h>
#include "mem.h"
#include "file.h"

enum {
    map_mmap,
    map_heap
};

int mapfile(const char *filename, map_t *out){
    int fd, serr, ret = 1;
    char buf[1024];
    ssize_t n;

    fd = open(filename, O_RDONLY);
    if(fd == -1)
        goto end;

    out->size = getfdsize(fd);
    out->ptr = mmap(NULL, (size_t)out->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(out->ptr == MAP_FAILED){
        out->ptr = NULL;
        out->size = 0;

        while((n = read(fd, buf, sizeof(buf))) > 0){
            out->ptr = realloc(out->ptr, n+out->size);
            if(out->ptr == NULL){
                break;
            }

            memcpy(out->ptr+out->size, buf, n);
            out->size += (size_t)n;
        }

        out->type = map_heap;
    } else {
        out->type = map_mmap;
    }

    if(out->ptr){
        ret = 0;
    }

    /* save errno to error reporting */
    serr = errno;
    close(fd);
    errno = serr;

    end:
    return ret;
}

void freemap(map_t *map){
    if(map->type == map_mmap)
        munmap(map->ptr, map->size);

    else if(map->type == map_heap)
        free(map->ptr);
}

void *xmalloc(size_t size){
    void *ptr = malloc(size);

    if(ptr == NULL){
        bad("malloc failed | %s\n", strerror(errno));
        exit(1);
    }

    return ptr;
}
