#ifndef __FILE_H__
#define __FILE_H__

#include "common.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

off_t getfdsize(int fd);
int xopen(const char *filename, int mode);

#endif
