
## `__malloc_hook`/ `__free_hook` / `__realloc_hook`:

Located in a writable segment within the GLIBC. These pointers, defaulting to 0 but when set, result in instead of the default GLIBC malloc/realloc/free functionality being called the function pointed to the value being set within these hooks being called on an allocation/free.

## `__after_morecore_hook`:

The variable `__after_morecore_hook` points at a function that is called each time after `sbrk()` was asked for more memory.

## `__malloc_initialize_hook`:

The variable `__malloc_initialize_hook` points to a function that is called once when the malloc implementation is initialized. So overwriting it with an attacker controlled value would just be useful when malloc has never been called before.

## `__memalign_hook`:

When set and `aligned_alloc()`, `memalign()`, `posix_memalign()`, or `valloc()` are being 
invoked, these function pointed to by the address stored in this hook is being called instead

## `_dl_open_hook`:

When triggering an abort message in GLIBC, typically `backtrace_and_maps()` to print the stderr trace is called. When this happens, `__backtrace()` and within that code `init()` is called, where `__libc_dlopen()` and `__libc_dlsym()` are invoked. The gist is that IFF `_dl_open_hook` is not NULL_,_ `_dl_open_hook`⇾`dlopen_mode` and `_dl_open_hook`⇾`dlsym` will be called. So, the idea is to just overwrite \_dl_open_hook with an address an attacker controls where a fake vtable function table can be crafted

## Mitigations

These hooks have been a hell of helpful in past exploitation techniques, but due to them enabling numerous techniques showcased below, they have been removed in [GLIBC >= 2 .34](https://patchwork.sourceware.org/project/glibc/patch/20210713073845.504356-10-siddhesh@sourceware.org/?ref=0x434b.dev).