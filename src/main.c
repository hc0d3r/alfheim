#include <getopt.h>
#include <stdio.h>

#include "main.h"

#include "common.h"
#include "file.h"
#include "str.h"
#include "mem.h"
#include "inject.h"

void parser_args(int argc, char **argv, inject_options_t *opt){
    static const struct option options[]={
        {"sc-file",           required_argument, NULL, 'f'},
        {"sc-string",         required_argument, NULL, 's'},
        {"no-restore",        no_argument,       NULL, 'n'},
        {"ptrace",            no_argument,       NULL, 'p'},
        {"restore-ip",        no_argument,       NULL, 'r'},
        {NULL, 0, NULL, 0}
    };

    int index = 0, optc;

    while((optc = getopt_long(argc, argv, "f:s:npr", options, &index)) != -1){
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
                opt->options.use_ptrace = 1;
                break;
            case 'r':
                opt->options.restore_ip = 1;
                break;

            case '?':
                exit(1);

            default:
                help();
        }
    }

    if(optind+1 != argc){
        help();
    }

    opt->options.pid = atoi(argv[optind]);
}

void banner(void){
    static const char ascii_banner[]=
        " ____    ____     __  __ _    __  ____  ___  ____ \n"
        "(  _ \\  / ___)   (  )(  ( \\ _(  )(  __)/ __)(_  _)\n"
        " ) __/_ \\___ \\ _  )( /    // \\) \\ ) _)( (__   )(  \n"
        "(__) (_)(____/(_)(__)\\_)__)\\____/(____)\\___) (__) \n";

    puts(ascii_banner);

}

void help(void){
    static const char help_menu[]=
        "Usage: ps-inject [OPTIONS] [PID]\n\n"
        "   -f, --sc-file FILE       File contains shellcode bytes\n"
        "   -s, --sc-string STRING   Shellcode string, e.g '\\x90\\x90\\x90'\n"
        "   -n, --no-restore         Not restore memory overwrited by shellcode\n"
        "   -r, --restore-ip         Restore instruction point\n"
        "   -p, --ptrace             Inject code using ptrace, instead of write in /proc/[pid]/mem\n";

    puts(help_menu);
    exit(0);
}

int inject_code(inject_options_t *opts){
    maped_file_t maped_file = maped_file_default;
    dynptr_t sc;

    if(opts->options.use_ptrace){
        writecallback = ignotum_ptrace_write;
        readcallback = ignotum_ptrace_read;
    }

    if(opts->filename){
        info("checking file => %s\n", opts->filename);
        memorymap(opts->filename, &maped_file);
        ps_inject(maped_file.ptr, maped_file.size, &(opts->options));
        memorymapfree(&maped_file);
    }

    if(opts->shellcode){
        info("checking shellcode string...\n");
        str2bytecode(opts->shellcode, &sc);
        ps_inject(sc.ptr, sc.len, &(opts->options));
        free(sc.ptr);
    }

    return 0;
}

int main(int argc, char **argv){
    inject_options_t options = inject_options_default;

    banner();
    parser_args(argc, argv, &options);

    return inject_code(&options);
}
