
```c
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	setreuid(1237, 1237);
	char* argv[] = { "-p", "-c", "whoami > flag", NULL };
	char* envp[] = { NULL };
	execve("/bin/bash", argv, envp);
	return 0;
}
```