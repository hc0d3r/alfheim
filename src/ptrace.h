#ifndef __PTRACE_H__
#define __PTRACE_H__

#include <sys/types.h>

void ptrace_attach(pid_t pid);
long ptrace_getreg(pid_t pid, int reg);
long ptrace_setreg(pid_t pid, int reg, long ip);
long ptrace_getregs(pid_t pid, void *regs);
long ptrace_setregs(pid_t pid, const void *regs);

#endif
