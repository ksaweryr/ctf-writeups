# SHA-CTR

> Why not make a stream cipher using SHA as keystream generator?
>
> `nc shactr.ecsc25.hack.cert.pl 5203`
>
> [example_flag.bmp](https://hack.cert.pl/files/example_flag-d7336f0da14038be1398a47a53b17e38dc35c214.bmp)
>
> **shactr.py**
> ```py
> import binascii
> import itertools
> import os
> 
> from hashlib import sha512
> 
> key = os.urandom(32)
> 
> 
> def xor(a: bytes, b: bytes) -> bytes:
>     return bytes([(aa ^ bb) for (aa, bb) in zip(a, b)])
> 
> 
> def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
>     res = []
>     block_size = 512 // 8
>     for i, block in enumerate(itertools.batched(data, block_size)):
>         counter = f"{i:010}".encode()
>         keystream = sha512(key + nonce + counter).digest()
>         res.append(xor(keystream, bytes(block)))
>     return b''.join(res)
> 
> 
> def get_ciphertext(nonce: bytes) -> bytes:
>     data = open("flag.bmp", 'rb').read()
>     return encrypt(key, nonce, data)
> 
> 
> def main():
>     for i in range(2):
>         nonce = binascii.unhexlify(input("nonce:"))
>         print(binascii.hexlify(get_ciphertext(nonce)).decode())
> 
> 
> if __name__ == '__main__':
>     main()
> ```

## Solution
The "keystream" is generated as `sha512(key + nonce + counter)` where `key` is unknown, `nonce` is provided by the user and `counter` is the number of the block represented as 10 digits. Given that the plaintext is a BMP file with a mostly white background, it's possible to recover a block of the keystream by xoring the 2nd block of the ciphertext with the 2nd block of the example flag (the metadata might change, but the background remains white, so the 1st block is skipped). This keystream block is `sha512(key + nonce + '0000000001')`. Setting the nonce to `''`, it's equivalent to `sha512(key + '0000000001')`. Now it's possible to perform a hash extension attack to calculate values of `sha512(key + '0000000001' + pad + counter)` for an arbitrary value of the counter (note that `pad` always stays the same). Now we simply ask for the encryption of the flag with nonce equal to `'0000000001' + pad` and decrypt it with the keystream calculated using hash extension:

```py
from ast import literal_eval
from pwn import *
import subprocess


def hexlify(s):
    return ''.join([f'{c:02x}' for c in s])


def hashpump(hash, to_append, crib):
    argv = [
        './HashPump-partialhash/hashpump',
        '-z',
        'SHA512',
        '-s',
        hash,
        '-d',
        crib,
        '-k',
        '32',
        '-a',
        to_append
    ]
    res = subprocess.check_output(argv).decode().split('\n')
    assert res[0].startswith('mask:')
    sig = res[1].split('sig: ')[1]
    inp = literal_eval(f'b"{res[2]}"')
    return (sig, inp)


with open('flag.bmp', 'rb') as f:
    pt = f.read()

io = process(['python3', 'shactr.py'])
io = remote('shactr.ecsc25.hack.cert.pl', 5203)

io.sendlineafter(b'nonce:', b'')
data1 = bytes.fromhex(io.recvline().decode())

known_block_idx = 1
start = known_block_idx * 64
end = known_block_idx * 64 + 64
known_block = xor(data1[start:end], pt[start:end])
block_count = len(data1) // 64

sigs = []
nonces = []

for i in range(block_count):
    sig, inp = hashpump(known_block.hex(), f'{i:010}', f'{known_block_idx:010}')
    nonce = inp[:-10]
    sigs.append(sig)
    nonces.append(nonce)

assert len(set(nonces)) == 1

io.sendlineafter(b'nonce:', hexlify(nonces[0]).encode())
data2 = bytes.fromhex(io.recvline().decode())
with open('output.bmp', 'wb') as f:
    f.write(xor(data2, bytes.fromhex(''.join(sigs))))
```

## Flag
`ecsc25{never_cross_the_streams}`
