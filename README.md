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
$ ./alfheim -h
Usage: alfheim [OPTIONS] [PID]

Options:
  -s, --shellcode STRING   string with shellcode, e.g, '90 90 90',
                            '0x90, 0x90', '\x90\x90\x90'
  -f, --file FILE          file with shellcode
  -F, --format STRING      file format, bin or ascii (Default: bin)
  --address HEX-ADDR       write shellcode to specific address
                            (Default: current instruction point)

  -w, --write              write shellcode to address and exit
  --no-restore-memory      no restore memory after shellcode execution
  --no-restore-ip          no restore instruction point after shellcode execution

  --ptrace                 write/read the memory using ptrace instead of /proc/[pid]/mem

  -h, --help               display this help menu
```
