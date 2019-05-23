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
    long ip, bp, addr;
    regs_t regs;

    ssize_t n;
    pid_t pid;

    pid = options->pid;

    info("attaching process %d\n", pid);
    ptrace_attach(pid);
    good("process attached\n");

    ptrace_getregs(pid, &regs);

    ip = regs.instruction_point;
    if(options->address){
        addr = options->address;
    } else {
        addr = ip;
    }

    if(options->restore){
        backup = xmalloc(len+BREAKPOINT_LEN);
        info("backup previously instructions ...\n");
        n = memread(pid, backup, len+BREAKPOINT_LEN, addr);
        info("%zd byte(s) read of %zu\n", n, len+BREAKPOINT_LEN);
    }

    info("writing shellcode at address 0x%lx ...\n", addr);
    n = memwrite(pid, sc, len, addr);
    info("%zd byte(s) written of %zu\n", n, len);

    good("shellcode written !!!\n");

    /* skip system call, e.g, select, poll, nanosleep */
    #ifdef intel
        ptrace_setreg(pid, ORIG_SYSNR, -1);
        ptrace_setreg(pid, IP, addr);
    #else
        //ip += 4;
        ptrace_setreg(pid, IP, addr);
    #endif


    if(!options->restore)
        goto end;

    bp = addr+len;

    info("setting a breakpoint at 0x%lx ...\n", bp);
    if(memwrite(pid, BREAKPOINT, BREAKPOINT_LEN, bp) == BREAKPOINT_LEN){
        good("breakpoint set\n");
    } else {
        bad("failed to write breakpoint\n");
    }

    info("executing shellcode ...\n");
    wait_breakpoint(pid, bp);

    info("restoring memory instructions\n");
    if((size_t)memwrite(pid, backup, len+BREAKPOINT_LEN, addr) == len+BREAKPOINT_LEN){
        good("memory restored\n");
    } else {
        bad("failed to restore the memory\n");
    }

    free(backup);

    if(!options->restore_ip){
        #ifdef intel
            ptrace_setreg(pid, IP, bp);
            info("setting instruction point to 0x%lx\n", bp);
        #endif
    } else {
        ptrace_setregs(pid, &regs);
    }

    end:
    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, pid, NULL, 0);
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
            ip = ptrace_getreg(pid, IP);
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
