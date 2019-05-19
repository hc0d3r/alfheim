#ifndef __MEM_H__
#define __MEM_H__

typedef struct {
    char *ptr;
    off_t size;
    int type;
} map_t;

int mapfile(const char *filename, map_t *out);
void freemap(map_t *map);
void *xmalloc(size_t size);

#endif
