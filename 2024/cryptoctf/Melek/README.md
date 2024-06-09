# Melek
> ### Difficulty: Medium
>
> [Melek](https://cr.yp.toc.tf/tasks/melek_3d5767ca8e93c1a17bc853a4366472accb5e3c59.txz) is a secret sharing scheme that may be relatively straightforward to break - what are your thoughts on the best way to approach it?

## Solution
```py
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def encrypt(msg, nbit):
	m, p = bytes_to_long(msg), getPrime(nbit)
	assert m < p
	e, t = randint(1, p - 1), randint(1, nbit - 1)
	C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
	R.<x> = GF(p)[]
	f = R(0)
	for i in range(t): f += x**(t - i - 1) * C[i]
	P = [list(range(nbit))]
	shuffle(P)
	P = P[:t]
	PT = [(a, f(a)) for a in [randint(1, p - 1) for _ in range(t)]]
	return e, p, PT

nbit = 512
enc = encrypt(flag, nbit)
print(f'enc = {enc}')
```
The `encrypt` function creates a degree $t$ polynomial with the constant term being the secret and $t$ shares. This is just regular Shamir's secret sharing scheme and the secret can be recovered by interpolating the polynomial, e.g. using Lagrange's method, and evaluating it at $x = 0$.

However, the secret hidden in the polynomial is not the flag, rather a number $c$ s.t. $c \equiv m^e\ (mod\ p)$. Since $p$ is prime, from Euler's theorem it follows that: $m^{p - 1} \equiv m\ (mod\ p)$, therefore $c^{y} \equiv m\ (mod\ p)$ where $y \equiv e^{-1}\ (mod\ p - 1)$. However such $y$ does not exist, as both $e$ and $p - 1$ are even (and therefore not coprime). Fortunately 2 is the only common factor of $e$ and $p - 1$, so we can calculate $m^2 \equiv c^{z}\ (mod\ p)$ where $z \equiv (\frac{e}{2})^{-1}\ (mod\ p - 1)$ and then calculate the modular square root of $m^2\ (mod\ p)$. The whole solution can be implemented with just a few lines of SageMath code:
```py
from Crypto.Util.number import long_to_bytes

with open('output.txt', 'rt') as f:
    exec(f.read())

e, p, PT = enc

F = GF(p)
R = F['x']

poly = R.lagrange_polynomial(PT)
ct = poly.coefficients()[0]
m = (ct^(Zmod(p - 1)(e // 2)^-1)).sqrt()

print(long_to_bytes(int(m)).decode())
```

## Flag
`CCTF{SSS_iZ_4n_3fF!ciEn7_5ecr3T_ShArIn9_alGorItHm!}`