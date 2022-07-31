# waifu
> Honestly I just needed a name, I am almost out of time :skull:.
> Connect with nc litctf.live 31791
>
> Downloads
> [waifu.zip](https://drive.google.com/uc?export=download&id=1SVW7rWSdpu3cPYDyATw5a9pJJMH0umTS)

## Identifying the vulnerability
The program stores the flag on top of the stack and than uses `scanf` to read a string from the user, which is safe and not exploitable in this challenge. The dangerous part is line 27:
```c
printf(buf);
```
Using `printf` to print a user-supplied string leads to format string vulnerability - by supplying a string with printf-recognized formatters we can force the program to show arbitrary data present on the stack.

## Format string vulnerability theory
We know that the flag is stored on the stack and that there's an exploit that allows us to read arbitrary stack data. Since the flag is stored as a sequence of characters (and not as a pointer to a character) we can't use the "%s" formatter to read it - instead we'll use "%llx" which prints a quad-word (8 bytes long number) as a hexadecimal number.
We also need to know which quad-words in particular to read. Let's take a look at the calling convention used in x64 Linux [https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI). The first 6 arguments are stored in registers and the rest of the arguments are stored on the stack - so the top of the stack is the 7th argument. Since the first argument of `printf`, passed in rdi, is the format string, the top of the stack will be the 6th vararg.
Despite that we don't have to repeat "%llx" 5 times before reading meaningful data - we can use formatters in this form:
`"%n$llx"` (where n is an integer)
to immediately read nth argument. We'll therefore use "%6$llx", "%7$llx" and so on to read the flag.
There's one last thing we need to note: x64 architecture stores number in little-endian order (least significant byte first). This means that if the top of the stack contains the string "ABCDEFGH" and we try to read it using "%6$llx", we'll get "4847464544434241" (which is hex-encoded "HGFEDCBA"). This means that the most convenient way to read the flag will be to read the quad-words in backwards order, hex-decode them and then reverse the result to get the flag.
Armed with all this knowledge, we're finally ready to exploit the vulnerability.

## Crafting the exploit
Given that the max length of the input is 40 characters, we can only fit 3 formatters in the form "%n$llx" in one go. As it turns out, the flag is quite long and it won't be enough so we'll have to run the exploit twice, with different numbers. The following script written in Python with pwnlib handles this task and reads the whole flag:
```py
from binascii import unhexlify
from pwn import *

flag = b''

for ns in ((8, 7, 6), (10, 9)):
	payload = ''.join(f'%{i}$llx' for i in ns) # formatters in reverse order because of little-endianess

  p = remote('litctf.live', 31791)

	p.recvuntil(b'waifus?\n')
	p.sendline(payload.encode())
	p.recvuntil(b'say:\n')
	hexed = p.recvline().strip()
	flag += unhexlify(hexed)[::-1] # reversing the decoded part of flag before adding it to the buffer, because of little-endianess

print(flag)
```

## Flag
`LITCTF{fr0m_t3xt4r7.sh_uwaaaaaaaaaaaaaa}`
