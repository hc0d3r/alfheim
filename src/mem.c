#include "mem.h"

void memorymap(const char *filename, maped_file_t *mfile){

	info("Opening file ...\n");
	mfile->fd = xopen(filename, O_RDONLY);
	good("file opened\n");


	info("getting file size ...\n");
	mfile->size = getfdsize(mfile->fd);
	good("file size: %zu\n", mfile->size);

	info("mapping file into memory ...\n");
	mfile->ptr = mmap(NULL, (size_t)mfile->size, PROT_READ, MAP_PRIVATE, mfile->fd, 0);

	if(mfile->ptr == MAP_FAILED){
		bad("mmap failed | %s\n", strerror(errno));
		exit(1);
	} else {
		good("file sucessfull mapped at address %p\n", mfile->ptr);
	}

}

void memorymapfree(maped_file_t *mfile){
	munmap(mfile->ptr, mfile->size);
	mfile->ptr = NULL;
	mfile->size = 0;

	close(mfile->fd);
	mfile->fd = 0;
}

void *xmalloc(size_t size){
	void *ptr = malloc(size);

	if(ptr == NULL){
		bad("malloc failed | %s\n", strerror(errno));
		exit(1);
	}

	return ptr;
}

void __safefree(void **pp){
	if(pp != NULL){
		free(*pp);
		*pp = NULL;
	}
}
