#include "file.h"

off_t getfdsize(int fd){
    struct stat buf;

    if( fstat(fd, &buf) == -1 ){
        bad("failed to get size | %s\n", strerror(errno));
        exit(1);
    }

    return buf.st_size;

}

int xopen(const char *filename, int mode){
    int ret = open(filename, mode);

    if(ret == -1){
        bad("failed to open file %s\n", strerror(errno));
        exit(1);
    }

    return ret;
}
