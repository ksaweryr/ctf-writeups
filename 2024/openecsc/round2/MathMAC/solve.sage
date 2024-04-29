from itertools import count
from pwn import *

# io = process(['python3', 'mathmac.py'])
io = remote('mathmac.challs.open.ecsc2024.it', int(38013))
p = 8636821143825786083
F = GF(p)


def generate_token():
    io.sendlineafter(b'> ', b'1')
    [n, token] = io.recvline().strip().decode().split(',')
    return int(n), int(token)


tokens = []
a = None
b = None
c = None
s1 = None
s2 = None
s3 = None

for i in count(1):
    if i % 100 == 0:
        print(f'Trying {i}th option...')
    n, t1 = generate_token()
    for i, (k1, t2) in enumerate(tokens):
        for j, (k2, t3) in enumerate(tokens[:i]):
            if k2 & (k1 | n) == k2 and (k1 & n) & k2 == (k1 & n):
                a = k1
                b = k2
                c = n
                s1 = t2
                s2 = t3
                s3 = t1
                break
            elif k1 & (k2 | n) == k1 and (k2 & n) & k1 == (k2 & n):
                    a = k2
                    b = k1
                    c = n
                    s1 = t3
                    s2 = t2
                    s3 = t1
                    break
        else:
            continue
        break
    else:
        tokens.append((n, t1))
        continue
    break

e1 = F(s1).log(F(4))
e2 = F(s2).log(F(4))

log.info(f'Found a fitting set of numbers:\n{a = }, {s1 = }, {e1 = }\n{b = }, {s2 = }, {e2 = }\n{c = }, {s3 = }')

d = (a & ~b) | (c & (a | ~b))

log.info(f'Calculated {d = }')

s4 = (F(s3) ^ e1).nth_root(e2)

log.info(f'Forged signature for d: {s4 = }')

io.sendlineafter(b'> ', b'2')
io.sendline(f'{d},{s4}'.encode())

log.info(f'Flag: {io.recvline().strip().decode()}')
