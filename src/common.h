#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>


/* common macros */

#define CYAN  "\e[0;36m"
#define GREEN "\e[0;32m"
#define RED   "\e[0;31m"
#define RESET "\e[0m"

#define color_print(stdfile, color, x, ...) fprintf(stdfile, color RESET " " x , ##__VA_ARGS__)
#define good(x...) color_print(stdout, GREEN "(+)", x)
#define bad(x...)  color_print(stderr, RED   "(-)", x)
#define info(x...) color_print(stderr, CYAN  "(*)", x)

#endif
