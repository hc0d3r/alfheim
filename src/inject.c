#include "inject.h"

writecb writecallback = ignotum_mem_write;
readcb readcallback = ignotum_mem_read;

void ptrace_attach(pid_t pid){
    int status;

    if( ptrace(PTRACE_ATTACH, pid, NULL, NULL) ==  - 1){
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

ssize_t ptrace_write(pid_t pid, const void *data, size_t len, long addr){
    size_t i;
    long word, old;
    int final_size;

    for(i=0; i<len; i+=wordsize){
        if((i+wordsize) > len){
            final_size = len-i;
            word = 0;

            memcpy(&word, data+i, final_size);
            old = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0L);
            old &= (unsigned long)-1 << (8*final_size);
            word |= old;
            ptrace(PTRACE_POKEDATA, pid, addr+i, word);

        } else {
            word = *(long *)(data+i);
            ptrace(PTRACE_POKEDATA, pid, addr+i, word);
        }
    }

    return 0;

}


ssize_t ptrace_read(pid_t pid, void *output, size_t n, long addr){
    size_t i;
    long bytes;


    for(i=0; i<n; i+=wordsize){
        bytes = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0L);
        if((i+wordsize) > n){
            memcpy((output+i), &bytes, n-i);
        } else {
            *(long *)(output+i) = bytes;
        }
    }

    return 0;

}

void ps_inject(const char *sc, size_t len, ps_inject_t *options){
    char *instructions_backup;
    long instruction_point;
    int status;

    info("Attaching process %d\n", options->pid);
    ptrace_attach(options->pid);
    good("process attached\n");

    instruction_point = getip(options->pid);

    if(options->restore){
        instructions_backup = xmalloc(len+BREAKPOINT_LEN);
        info("backup previously instructions\n");
        readcallback(options->pid, instructions_backup, len+BREAKPOINT_LEN, instruction_point);
    }

    info("writing shellcode on memory\n");
    writecallback(options->pid, sc, len, instruction_point);

    good("Shellcode inject !!!\n");

    if(options->restore){
        info("resuming application ...\n");
        writecallback(options->pid, BREAKPOINT, BREAKPOINT_LEN, instruction_point+len);

        ptrace(PTRACE_CONT, options->pid, NULL, 0);
        waitpid(options->pid, &status, 0);

        info("restoring memory instructions\n");
        writecallback(options->pid, instructions_backup, len+BREAKPOINT_LEN, instruction_point);

        xfree(instructions_backup);

        if(options->restore_ip){
            setip(options->pid, instruction_point);
        }

        #if defined(__x86_64__) || defined(__i386__)
        else {
            setip(options->pid, getip(options->pid)-BREAKPOINT_LEN);
        }
        #endif
    }

    info("detaching pid ...\n");
    ptrace(PTRACE_DETACH, options->pid, NULL, 0);


}
