Inject shellcode on linux pid

##How use:
```
$ make
gcc -Wall -Wextra -O3 -c -o lib/file.o src/file.c
gcc -Wall -Wextra -O3 -c -o lib/str.o src/str.c
gcc -Wall -Wextra -O3 -c -o lib/mem.o src/mem.c
gcc -Wall -Wextra -O3 -c -o lib/inject.o src/inject.c
gcc -Wall -Wextra -O3 -c -o lib/main.o src/main.c
gcc -Wall -Wextra -O3 -o ps-inject lib/file.o lib/str.o lib/mem.o lib/inject.o lib/main.o
$ ./ps-inject
 ____    ____     __  __ _    __  ____  ___  ____ 
(  _ \  / ___)   (  )(  ( \ _(  )(  __)/ __)(_  _)
 ) __/_ \___ \ _  )( /    // \) \ ) _)( (__   )(  
(__) (_)(____/(_)(__)\_)__)\____/(____)\___) (__) 

Usage: ps-inject [OPTIONS] [PID]

   -f, --sc-file FILE       File contains shellcode bytes
   -s, --sc-string STRING   Shellcode string, e.g '\x90\x90\x90'
   -n, --no-restore         Not restore memory overwrited by shellcode
   -r, --restore-ip         Restore instruction point
   -p, --ptrace             Inject code using ptrace, instead of write in /proc/[pid]/mem


```


##Example:
[![asciicast](https://asciinema.org/a/82997.png)](https://asciinema.org/a/82997)
