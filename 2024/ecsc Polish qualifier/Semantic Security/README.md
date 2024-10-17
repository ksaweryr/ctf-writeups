# Semantic Security

> It's not cryptographically secure random, but I think it's good enough.
>
> `nc semantic.ecsc24.hack.cert.pl 5102`
>
> ```python
> import binascii
> import random
> 
> 
> def xor(*t):
>     from functools import reduce
>     from operator import xor
>     return [reduce(xor, x, 0) for x in zip(*t)]
> 
> 
> def main():
>     flag = open("flag.txt", 'rb').read()
>     while True:
>         print("1. Get ciphertext")
>         print("2. Exit")
>         choice = input(">").strip()
>         if choice == "1":
>             keystream = [random.randrange(0, 255) for _ in range(len(flag))]
>             random.shuffle(keystream)
>             print(binascii.hexlify(bytes(xor(flag, keystream))).decode())
>         elif choice == "2":
>             return
>         else:
>             print("WTF?")
> 
> 
> if __name__ == "__main__":
>     main()
> ```

## Solution
You know how in Python `random.randint(a, b)` returns an integer between `a` and `b` inclusive? Well, guess what - `random.randrange(a, b)` returns an integer between `a` (inclusive) and `b` (exclusive). Because of that no byte in the keystream will ever be 255 and hence no character of the flag will be xored with 255. The solution is just to collect plaintexts (under 3000 should be enough) until you've received 255 distinct values for each character - the one value you didn't receive is `character ^ 255`. The following script solves the challenge:

```python
from binascii import unhexlify
from pwn import *

io = remote('semantic.ecsc24.hack.cert.pl', 5102)


def get_ciphertext():
    io.sendlineafter(b'>', b'1')
    return unhexlify(io.recvline().strip().decode())


ct = get_ciphertext()
array = [set([x]) for x in ct]

cnt = 1
while any(len(x) < 255 for x in array):
    if cnt % 100 == 0:
        print(cnt)
    cnt += 1
    ct = get_ciphertext()
    for i, c in enumerate(ct):
        array[i].add(c)

flag_bytes = []

for x in array:
    flag_bytes.append(list(set(range(256)).difference(x))[0] ^ 0xff)

print(bytes(flag_bytes).decode())
```

## Flag
`ecsc24{I_hope_that_only_negligible_information_about_the_plaintext_can_be_extracted}`
