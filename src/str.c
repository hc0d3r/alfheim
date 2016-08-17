#include "str.h"


int hexdigit(const char x){
	if ( (x >= 'a' && x <= 'f') || (x >= '0' && x <= '9') ){
		return 1;
	}
	else
		return 0;
}

char tohex(char x){
	if(x >= '0' && x <= '9')
		return x & 0b1111;

	if(x >= 'a' && x <= 'f')
		return x-'a'+10;

	return x;
}

/* string to pid_t(int) */
pid_t parser_pid(const char *strpid){
	pid_t ret = 0;
	char aux;
	int i;


	for(i=0; strpid[i]; i++){
		aux = strpid[i];

		if(aux < '0' || aux > '9'){
			bad("%s not is a valid pid number\n", strpid);
			exit(1);
		}


		if(ret > INT_MAX/10){
			bad("%s is too big ...\n", strpid);
			exit(1);
		}

		ret *= 10;
		aux &= 0b1111;

		if(ret > INT_MAX-aux){
			bad("%s is too big ...\n", strpid);
			exit(1);
		}

		ret += aux;

	}

	return ret;
}

void str2bytecode(const char *shellcode, bytecode_string_t *code){
	size_t sc_size = strlen(shellcode);
	int i = 0, j = 0;
	char aux;

	if(!sc_size || (sc_size & 3)) goto end;

	code->len = sc_size >> 2;
	code->ptr = xmalloc(code->len);


	while(shellcode[i]){
		aux = tolower(shellcode[i]);
		switch(i & 3){ // its equal to i%4
			case 0:
				if(aux != '\\') goto end;
				break;
			case 1:
				if(aux != 'x') goto end;
				break;
			case 2:
				if(!isxdigit(aux)) goto end;
				code->ptr[j] = tohex(aux) << 4;
				break;

			case 3:
				if(!isxdigit(aux)) goto end;
				code->ptr[j] |= tohex(aux);
				j++;
				break;
		}

		i++;
	}

	return;

	end:
		bad("'%s' not is a valide shellcode string\n", shellcode);
		exit(0);


}
