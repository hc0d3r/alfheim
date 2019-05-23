#ifndef __REMOTE_WRITE_H__
#define __REMOTE_WRITE_H__

#include <sys/types.h>
#include <stddef.h>

void remote_write(pid_t pid, const char *sc, size_t len, long addr);

#endif
