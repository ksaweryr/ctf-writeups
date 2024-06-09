# Honey
> ### Difficulty: Medium
>
> [Honey](https://cr.yp.toc.tf/tasks/honey_fadbdf04ae322e5a147ef6d10a0fe9bd35d7c5db.txz) is a concealed cryptographic algorithm designed to provide secure encryption for sensitive messages.

## Initial analysis
```py
#!/usr/bin/env python3

from Crypto.Util.number import *
from math import sqrt
from flag import flag

def gen_params(nbit):
	p, Q, R, S = getPrime(nbit), [], [], []
	d = int(sqrt(nbit << 1))
	for _ in range(d):
		Q.append(getRandomRange(1, p - 1))
		R.append(getRandomRange(0, p - 1))
		S.append(getRandomRange(0, p - 1))
	return p, Q, R, S

def encrypt(m, params):
	p, Q, R, S = params
	assert m < p
	d = int(sqrt(p.bit_length() << 1))
	C = []
	for _ in range(d):
		r, s = [getRandomNBitInteger(d) for _ in '01']
		c = Q[_] * m + r * R[_] + s * S[_]
		C.append(c % p)
	return C


nbit = 512
params = gen_params(512)
m = bytes_to_long(flag)
C = encrypt(m, params)
f = open('params_enc.txt', 'w')
f.write(f'p = {params[0]}\n')
f.write(f'Q = {params[1]}\n')
f.write(f'R = {params[2]}\n')
f.write(f'S = {params[3]}\n')
f.write(f'C = {C}')
f.close()
```
The calculates generates $d$ (32) numbers $C_i \equiv Q_im + R_i r_i + S_i s_i\ (mod\ p)$ where $p$ is a 512-bit prime, $C_i$, $Q_i$, $R_i$ and $S_i$ are known (the latter 3 are also known to be 512-bit), $m$ is the flag and $r_i$ and $s_i$ are 32-bit and unknown. This is an instance of the hidden number problem with 2 holes. A method to reduce this problem to an instance of hidden number problem or extended hidden number problem has been described in [[^1]]. Another papers that proved to be useful while solving this challenge are [[^2]] and [[^3]].

## Reducing HNP-2H to HNP
To perform this reduction, we'll follow theorem 3 from [[^1]]. Note that $N$ correpsonds to $p$, $\alpha_i$ to $Q_i$, $\rho_{i,1}$ to $R_i$, $\rho_{i,2}$ to $S_i$, $\beta_i$ to $C_i$, $x$ to $m$, and finally $k_{i,1}$ and $k_{i,2}$ to $r_i$ and $s_i$. Additionally, $\mu_1 = \mu_2 = 32$ and $B_{min} = p^{\frac{1}{2}}2^\frac{32 - 32}{2} = \sqrt{p}$.

First step is to calculate $\lambda_{i, B_{min}}$. For that, lemma 16 from [[^2]] can be used. $A$ is defined in theorem 3 of [[^1]] as $R_i^{-1}S_i$ and $B$ is $B_{min}$. The following SageMath code will calculate $\lambda$ given $A$, $B$ and $p$:
```py
def calculate_lambda(A, B, p):
    cf = (A/p).continued_fraction()
    lm = None
    for i in range(cf.length()):
        if cf.denominator(i) < B and B <= cf.denominator(i + 1):
            lm = cf.denominator(i)
            break
    assert lm is not None
    return lm
```

Now we can calculate the values of $\alpha''_i$ and $\beta''_i$ using formulas from theorem 3 of [[^1]] and store them in 2 lists for later use.

## Solving HNP
Now we can use definition 4.10 from [[^3]] to solve the hidden number problem. We'll use Kannan's embedding method. The numbers $a_i$ from this definition correspond to our $\beta''_i$, while $t_i$ correspond to $-\alpha''_i$. Note that the number $B$ in this definition is the upper bound on $k'_i$ from theorem 3 of [[^1]], that is $\sqrt{p}2^{34}$.

## Full script
The complete script with the solution is available in [solve.sage](./solve.sage)

## Flag
`CCTF{3X7eNdED_H!dD3n_nNm8eR_pR0Bl3m_iN_CCTF!!}`

[^1]: Hlaváč, M., Rosa, T. (2007). Extended Hidden Number Problem and Its Cryptanalytic Applications. In: Biham, E., Youssef, A.M. (eds) Selected Areas in Cryptography. SAC 2006. Lecture Notes in Computer Science, vol 4356. Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-540-74462-7_9
[^2]: Nguyen, Shparlinski The Insecurity of the Digital Signature Algorithm with Partially Known Nonces . J. Cryptology 15, 151–176 (2002). https://doi.org/10.1007/s00145-002-0021-3
[^3]: Joseph Surin, & Shaanan Cohney. (2023). A Gentle Tutorial for Lattice-Based Cryptanalysis. https://eprint.iacr.org/2023/032