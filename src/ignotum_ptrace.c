#include <sys/ptrace.h>
#include <string.h>
#include <errno.h>

#include "ignotum_ptrace.h"

#define wordsize sizeof(long)

ssize_t ignotum_ptrace_write(pid_t pid, const void *buf, size_t n, long addr){
    ssize_t ret;
    size_t nwrite = 0, pos = 0, len;

    long aligned, offset, bytes;

    if(n == 0){
        ret = 0;
        goto end;
    }

    if(addr & (wordsize-1)){
        aligned = addr & (long)(-wordsize);
        offset = addr - aligned;
        len = wordsize-offset;
        addr = aligned;
    } else {
        len = wordsize;
        offset = 0;
    }

    while(nwrite<n){
        nwrite += len;
        if(nwrite > n){
            len = n-(nwrite-len);
            nwrite = n;
        }

        if(len != wordsize){
            bytes = ptrace(PTRACE_PEEKDATA, pid, addr, 0L);
            if(errno)
                break;

            memcpy((char *)&bytes+offset, (char *)buf+pos, len);
            len = wordsize;
            offset = 0;
        } else {
            bytes = *(long *)((char *)buf+pos);
        }


        ptrace(PTRACE_POKEDATA, pid, addr, bytes);
        if(errno)
            break;

        pos = nwrite;
        addr += wordsize;
    }

    if(!pos){
        ret = -1;
    } else {
        ret = (ssize_t)pos;
    }


    end:
    return ret;
}

ssize_t ignotum_ptrace_read(pid_t pid, void *buf, size_t n, long addr){
    ssize_t ret;
    size_t nread = 0, pos = 0, len;

    long aligned, offset, bytes;

    if(n == 0){
        ret = 0;
        goto end;
    }

    if(addr & (wordsize-1)){
        aligned = addr & (long)(-wordsize);
        offset = addr - aligned;
        len = wordsize-offset;
        addr = aligned;
    } else {
        len = wordsize;
        offset = 0;
    }

    while(nread<n){
        bytes = ptrace(PTRACE_PEEKDATA, pid, addr, 0L);
        if(errno)
            break;

        nread += len;
        if(nread > n){
            len = n-(nread-len);
            nread = n;
        }

        if(len == wordsize){
            *(long *)(buf+pos) = bytes;
        } else {
            memcpy((char *)buf+pos, (char *)&bytes+offset, len);
            len = wordsize;
            offset = 0;
        }

        pos = nread;
        addr += wordsize;
    }

    if(!nread){
        ret = -1;
    } else {
        ret = (ssize_t)nread;
    }


    end:
    return ret;
}

