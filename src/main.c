#include <getopt.h>
#include <stdio.h>

#include "main.h"

#include "common.h"
#include "file.h"
#include "str.h"
#include "mem.h"
#include "inject.h"

void parser_args(int argc, char **argv, options_t *opt){
    static const struct option options[]={
        {"shellcode",         required_argument, NULL, 's'},
        {"file",              required_argument, NULL, 'f'},
        {"no-restore-memory", no_argument,       NULL,   0},
        {"no-restore-ip",     no_argument,       NULL,   0},
        {"ptrace",            no_argument,       NULL,   0},
        {NULL, 0, NULL, 0}
    };

    int index = 0, optc;
    const char *name;

    while((optc = getopt_long(argc, argv, "s:f:", options, &index)) != -1){
        switch(optc){
            case 0:
                name = options[index].name;
                if(!strcmp(name, "no-restore-memory")){
                    opt->options.restore = 0;
                }

                else if(!strcmp(name, "no-restore-ip")){
                    opt->options.restore_ip = 0;
                }

                else if(!strcmp(name, "ptrace")){
                    memwrite = ignotum_ptrace_write;
                    memread = ignotum_ptrace_read;
                }

                break;

            case 's':
                opt->shellcode = optarg;
                break;

            case 'f':
                opt->filename = optarg;
                break;

            case '?':
                exit(1);

            default:
                help();
        }
    }

    if(optind+1 != argc || (!opt->filename && !opt->shellcode)){
        help();
    }

    opt->options.pid = atoi(argv[optind]);
}

void help(void){
    static const char help_menu[]=
        "Usage: alfheim [OPTIONS] [PID]\n\n"
        "Options:\n"
        "  -s, --shellcode STRING   string with shellcode, e.g, '90 90 90',\n"
        "                            '0x90, 0x90', '\\x90\\x90\\x90'\n"
        "  -f, --file FILE          file with shellcode\n\n"

        "  --no-restore-memory      no restore memory after shellcode execution\n"
        "  --no-restore-ip          no restore instruction point after shellcode execution\n\n"

        "  --ptrace                 write/read the memory using ptrace instead of /proc/[pid]/mem";

    puts(help_menu);
    exit(0);
}

int inject_code(options_t *opts){
    map_t mfile;
    dynptr_t sc;

    if(opts->filename){
        info("checking file => %s\n", opts->filename);
        if(mapfile(opts->filename, &mfile)){
            bad("failed to map file (%s) : %s\n", opts->filename, strerror(errno));
            return 1;
        }

        if(mfile.size){
            inject(mfile.ptr, mfile.size, &(opts->options));
        } else {
            bad("empty file !!!\n");
        }

        freemap(&mfile);
    }

    if(opts->shellcode){
        info("checking shellcode string...\n");
        str2bytecode(opts->shellcode, &sc);

        if(sc.len){
            inject(sc.ptr, sc.len, &(opts->options));
        } else {
            bad("empty shellcode !!!\n");
        }

        free(sc.ptr);
    }

    return 0;
}

int main(int argc, char **argv){
    options_t options = default_options;

    parser_args(argc, argv, &options);

    return inject_code(&options);
}
