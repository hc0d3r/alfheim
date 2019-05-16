#ifndef __IGNOTUM_PTRACE_H__
#define __IGNOTUM_PTRACE_H__

#include <sys/types.h>
#include <stddef.h>

ssize_t ignotum_ptrace_write(pid_t pid, const void *buf, size_t n, long addr);
ssize_t ignotum_ptrace_read(pid_t pid, void *buf, size_t n, long addr);

#endif
