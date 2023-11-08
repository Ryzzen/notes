
```c
//gcc -shared -fPIC -ldl hook.c -o hook.so 

#define _GNU_SOURCE 
#include <stdio.h> 
#include <dlfcn.h>

typedef int (*rand_t)(void);
rand_t libc_rand;

int rand(void) {
	if (!libc_rand)
		libc_rand = dlsym(RTLD_NEXT, "rand");
		return -1;
		//return libc_rand();
}
```

```bash
LD_PRELOAD=$PWD/preload_test.so ssh
```