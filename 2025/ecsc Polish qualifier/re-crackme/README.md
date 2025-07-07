# re-crackme

> download it harder, execute it better, debug it faster, solve it stronger
>
> [crackme](https://hack.cert.pl/files/crackme-e8ceb7df810541a9c69d697866335c4c2230cca3)

## Solution
Some simple constraints based on xoring parts of the flag. In principle, angr should've worked, but it didn't, so I rewrote the constraints to plain z3:

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from z3 import *


class Quad:
    def __init__(self, u, l):
        self.u = u
        self.l = l

    @property
    def full(self):
        return Concat(self.u, self.l)


fb = [Quad(BitVec(f'block_{i}_u', 32), BitVec(f'block_{i}_l', 32)) for i in range(0x40 // 8)]

s = Solver()

s.add(fb[0].l == bytes_to_long(b'ecsc'[::-1])) # reverse because AMD64 is little-endian
s.add(fb[0].u & 0xffffff == bytes_to_long(b'25{'[::-1]))

s.add(fb[0].full ^ fb[1].full == 0x56465f0f1f4e0a)
s.add(fb[2].full - fb[3].full == 0x44edf4edfb46ba00)
s.add(fb[4].full + fb[5].full == -0x6035271f31222c29)
s.add(fb[6].full ^ fb[7].full == 0xd73433748040f0c)

s.add(Concat(fb[2].l, fb[1].u) + Concat(fb[1].l, fb[0].u) == -0x2e1fa52123575761)
s.add(Concat(fb[3].l, fb[2].u) - Concat(fb[4].l, fb[3].u) == 0x4b70dfd44edf4ee)
s.add(Concat(fb[6].l, fb[5].u) + Concat(fb[5].l, fb[4].u) == -0x6931233160352720)

s.add(fb[0].l ^ fb[6].u == 0x135e0d0c)
s.add(fb[7].u ^ fb[7].l == 0x183d4c3b)
s.add(fb[2].u ^ fb[3].l == 0x184f1b0c)
s.add(fb[5].u ^ fb[6].l == 0x5f020b07)

assert s.check() == sat
m = s.model()

for b in fb:
    chunk = long_to_bytes(m[b.l].as_long())[::-1] + long_to_bytes(m[b.u].as_long())[::-1]
    print(chunk.decode(), end='')

print()
```

## Flag
`ecsc25{no-llms-no-techbros-just-reverse-engineering-in-peace^-^}`
