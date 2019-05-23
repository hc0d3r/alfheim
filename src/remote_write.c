#include "remote_write.h"
#include "common.h"
#include "ptrace.h"
#include "inject.h"


void remote_write(pid_t pid, const char *sc, size_t len, long addr){
    ssize_t n;

    info("attaching process %d\n", pid);
    ptrace_attach(pid);
    good("process attached\n");

    info("writing shellcode at address 0x%lx ...\n", addr);
    n = memwrite(pid, sc, len, addr);
    info("%zd byte(s) written of %zu\n", n, len);

    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, pid, NULL, 0);
}
