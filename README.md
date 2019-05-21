# alfheim
a linux process hacker tool
--
supported architectures:

- [x] x86_64
- [x] x86
- [x] arm

## How use:
```
$ make
cc -Wall -Wextra -O3 -c -o lib/file.o src/file.c
cc -Wall -Wextra -O3 -c -o lib/str.o src/str.c
cc -Wall -Wextra -O3 -c -o lib/mem.o src/mem.c
cc -Wall -Wextra -O3 -c -o lib/inject.o src/inject.c
cc -Wall -Wextra -O3 -c -o lib/ignotum_ptrace.o src/ignotum_ptrace.c
cc -Wall -Wextra -O3 -c -o lib/ignotum_mem.o src/ignotum_mem.c
cc -Wall -Wextra -O3 -c -o lib/ptrace.o src/ptrace.c
cc -Wall -Wextra -O3 -c -o lib/main.o src/main.c
cc -Wall -Wextra -O3 -o alfheim lib/file.o lib/str.o lib/mem.o lib/inject.o lib/ignotum_ptrace.o lib/ignotum_mem.o lib/ptrace.o lib/main.o
$ ./alfheim
Usage: alfheim [OPTIONS] [PID]

   -f, --sc-file FILE       File contains shellcode bytes
   -s, --sc-string STRING   Shellcode string, e.g '\x90\x90\x90'
   -n, --no-restore         No restore memory overwrited by shellcode
   -N, --no-restore-ip      No restore instruction point
   -p, --ptrace             Inject code using ptrace, instead of write in /proc/[pid]/mem

```
