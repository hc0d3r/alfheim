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
        {"sc-file",           required_argument, NULL, 'f'},
        {"sc-string",         required_argument, NULL, 's'},
        {"no-restore",        no_argument,       NULL, 'n'},
        {"ptrace",            no_argument,       NULL, 'p'},
        {"no-restore-ip",        no_argument,       NULL, 'N'},
        {NULL, 0, NULL, 0}
    };

    int index = 0, optc;

    while((optc = getopt_long(argc, argv, "f:s:npN", options, &index)) != -1){
        switch(optc){
            case 'f':
                opt->filename = optarg;
                break;

            case 's':
                opt->shellcode = optarg;
                break;

            case 'n':
                opt->options.restore = 0;
                break;
            case 'p':
                memwrite = ignotum_ptrace_write;
                memread = ignotum_ptrace_read;
                break;
            case 'N':
                opt->options.restore_ip = 0;
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
        "   -f, --sc-file FILE       File contains shellcode bytes\n"
        "   -s, --sc-string STRING   Shellcode string, e.g '\\x90\\x90\\x90'\n"
        "   -n, --no-restore         No restore memory overwrited by shellcode\n"
        "   -N, --no-restore-ip      No restore instruction point\n"
        "   -p, --ptrace             Inject code using ptrace, instead of write in /proc/[pid]/mem\n";

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
