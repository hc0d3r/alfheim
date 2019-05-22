#include <sys/wait.h>

#include "inject.h"
#include "common.h"
#include "mem.h"
#include "ptrace.h"

writecb memwrite = ignotum_mem_write;
readcb memread = ignotum_mem_read;

void wait_breakpoint(pid_t pid, long addr);

void inject(const char *sc, size_t len, inject_t *options){
    char *backup = NULL;
    long ip, bp;
    regs_t old_regs;

    ssize_t n;

    info("attaching process %d\n", options->pid);
    ptrace_attach(options->pid);
    good("process attached\n");

    ptrace(PTRACE_GETREGS, options->pid, NULL, &old_regs);

    ip = old_regs.instruction_point;

    /* skip system call, e.g, select, poll, nanosleep */
    #if defined (__x86_64__) || defined (__i386__)
        setreg(options->pid, ORIG_SYSNR, -1);
    #else
        ip += 4;
        setreg(options->pid, IP, ip);
    #endif

    if(options->restore){
        backup = xmalloc(len+BREAKPOINT_LEN);
        info("backup previously instructions ...\n");
        n = memread(options->pid, backup, len+BREAKPOINT_LEN, ip);
        info("%zd byte(s) read of %zu\n", n, len+BREAKPOINT_LEN);
    }

    info("writing shellcode at address 0x%lx ...\n", ip);
    n = memwrite(options->pid, sc, len, ip);
    info("%zd byte(s) written of %zu\n", n, len);

    good("shellcode inject !!!\n");

    if(options->restore){
        bp = ip+len;
        info("setting a breakpoint at 0x%lx ...\n", bp);
        if(memwrite(options->pid, BREAKPOINT, BREAKPOINT_LEN, bp) == BREAKPOINT_LEN){
            good("breakpoint set\n");
        } else {
            bad("failed to write breakpoint\n");
        }

        info("executing shellcode ...\n");

        wait_breakpoint(options->pid, bp);

        info("restoring memory instructions\n");
        if((size_t)memwrite(options->pid, backup, len+BREAKPOINT_LEN, ip) == len+BREAKPOINT_LEN){
            good("memory restored\n");
        } else {
            bad("failed to restore the memory\n");
        }

        free(backup);

        if(!options->restore_ip){
            #if defined(__x86_64__) || defined(__i386__)
                setreg(options->pid, IP, bp);
                info("setting instruction point to 0x%lx\n", bp);
            #endif
        } else {
            ptrace(PTRACE_SETREGS, options->pid, NULL, &old_regs);
        }

    }

    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, options->pid, NULL, 0);
}

void wait_breakpoint(pid_t pid, long addr){
    int status, sig = 0;
    long ip = 0;

    while(1){
        ptrace(PTRACE_CONT, pid, NULL, sig);
        if(waitpid(pid, &status, 0) == -1)
            break;

        sig = 0;
        if(WIFEXITED(status)){
            bad("program exit with code: %d\n", WEXITSTATUS(status));
            break;
        }

        if(WIFSIGNALED(status)){
            bad("program killed with signal: %d\n", WTERMSIG(status));
            break;
        }

        if(WIFSTOPPED(status)){
            ip = getreg(pid, IP);
            #if defined(__x86_64__) || defined(__i386__)
                ip--;
            #endif

            if(ip == addr){
                good("breakpoint reached !!!\n");
                break;
            } else {
                sig = WSTOPSIG(status);
                info("--- signal number: %d, at 0x%lx ---\n", sig, ip);
            }
        }
    }
}
