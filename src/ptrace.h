#ifndef __PTRACE_H__
#define __PTRACE_H__

#include <sys/types.h>

void ptrace_attach(pid_t pid);
long getreg(pid_t pid, int reg);
long setreg(pid_t pid, int reg, long ip);

#endif
