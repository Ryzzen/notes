# Kernel symbols

If KALLSYMS is not enabled. It is by default, and then we need root permissions to read the file.
Useful to break on the target symbols from gdb.
```sh
cat /proc/kallsyms
```

# Get creds

```c
int commit_creds(struct cred *new);
struct cred* prepare_kernel_cred(struct task_struct* daemon);
commit_creds(prepare_kernel_cred(NULL));
```

# Returning to userspace

```C
	payload[off++] = iretd/q;
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

```
## Notes for 64 bits

x64 uses a separate stack taken from the IST (Interrupt Stack Table), wich means that we may not need an iretq at all, and use the normal execution flow of the highjacked interrupt, wich will return for us, given that our exploit doesn't broke the its stack in purpose.

# Exec code in kernel mode

- [ ] Overwrite fn() function pointer inside restart_block with malicious function
- [ ] Call syscall(SYS_restart_syscall) avec SYS_restart_syscall = 0, soit syscall(0)

# Protections

|Name	       | Description                                                                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------  |
|smep          | Supervisor Mode Execution Protection, when the processor is in ring 0 mode, executing user-space code will trigger a page fault. (called PXN in arm)                |
|smap          | Supervisor Mode Access Protection, same as smep but with userspace data, when the processor is in ring 0 mode, accessing user space data will trigger a page fault. |
|MMAP_MIN_ADDR | Blocks lowest memory addresses that mmap can map, preventing users from illegally allocating and accessing low-address data, like thread_info for instance.         |
|KASLR         | Kernel Address Space Layout Randomization, when enabled, allows the kernel image to be loaded anywhere in the VMALLOC area.                                         |


# Kernel stack

Code:
```c
union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};
```

Simple stack layout:
```txt
high addr
			_________________________
			|						|	<-- stack base
			|	Dev stack space		|
			| 	Grows down			|
			|						|	<-- stack pointer
			|						|
(4kb / 8kb)	|_______________________|
			|	Unused				|
			|						|
			|						|
			|_______________________|
			|						|
			|	struct thread_info	|	<-- current_thread_info
low addr
```