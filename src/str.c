#include "str.h"

static char hex(char ch){
    if(ch >= '0' && ch <= '9')
        ch &= 0b1111;
    else
        ch = ch-'a'+10;

    return ch;
}

void str2bytecode(const char *str, dynptr_t *code){
    size_t j, i;

    for(i=0, j=0; str[i]; i++){
        if(isxdigit(str[i]) && isxdigit(str[i+1])){
            i++, j++;
        }
    }

    code->len = j;
    if(j){
        code->ptr = xmalloc(j);
        for(i=0, j=0; str[i]; i++){
            if(isxdigit(str[i]) && isxdigit(str[i+1])){
                code->ptr[j] = (hex(str[i]) << 4) | hex(str[i+1]);
                i++, j++;
            }
        }
    } else {
        code->ptr = NULL;
    }
}
