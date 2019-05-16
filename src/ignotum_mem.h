#ifndef __IGNOTUM_MEM_H__
#define __IGNOTUM_MEM_H__

#include <sys/types.h>
#include <stddef.h>

ssize_t ignotum_mem_write(pid_t pid, const void *buf, size_t n, off_t addr);
ssize_t ignotum_mem_read(pid_t pid, void *buf, size_t n, off_t addr);

#endif
