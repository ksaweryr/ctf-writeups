# Melek
A [CryptoCTF 2024](https://ctftime.org/event/2210/) challenge about Shamir's secret sharing and Euler's theorem (as well as Fermat's little theorem).

## The Challenge
> [Melek](https://cr.yp.toc.tf/tasks/melek_3d5767ca8e93c1a17bc853a4366472accb5e3c59.txz) is a secret sharing scheme that may be relatively straightforward to break - what are your thoughts on the best way to approach it?
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

### What is given?
- e - an exponent (useful later)
- p - a 512-bit prime
- PT - t points on (t-1)-degree polynomial over integers modulo p
    - we want to find the constant term, which is equal to $m^e\ mod\ p$, where m is the flag

Let's open SageMath REPL and "import" this data:
```py
sage: exec(open('output.txt', 'rt').read())
sage: e, p, PT = enc
sage:
```

### Step 1 - recovering the constant term
How? Interpolate the polynomial!

#### Theorem - for a set of k+1 distinct points, there exists exactly one polynomial of degree k passing through all of them.
Proof?

$$
\begin{bmatrix}
1 & x_0 & x_0^2 & \ldots & x_0^k \\
1 & x_1 & x_1^2 & \ldots & x_1^k \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
1 & x_k & x_k^2 & \ldots & x_k^k
\end{bmatrix}
\cdot
\begin{bmatrix}
a_0 \\
a_1 \\
a_2 \\
\vdots \\
a_k
\end{bmatrix} = \begin{bmatrix}
y_0 \\
y_1 \\
y_2 \\
\vdots \\
y_k
\end{bmatrix}
$$

The matrix on the left side of the equation is a [Vandermonde matrix](https://en.wikipedia.org/wiki/Vandermonde_matrix). Its determinant is:

$$
det(A) = \prod_{0 \le i \lt j \le k} (x_j - x_i)
$$

As $x_i = x_j \iff i = j$, the determinant is not 0, so the matrix is invertible and there exists exactly one vector of $a_i$'s satisfying the equation.

Notice that this also holds if we consider a matrix of numbers over a finite field of size p (i.e. a matrix of integers mod p, where p is a prime; in that case we also consider the determinant to be mod p).

#### Lagrange interpolation
Consider a set S of k+1 points s.t. $S = \lbrace(x_0, y_0), (x_1, y_1), \ldots, (x_k, y_k)\rbrace$. Now for each of those points consider a function $l_i: \lbrace x \vert (x, y) \in S \rbrace \to \lbrace y \vert (x, y) \in S \rbrace \cup \lbrace 0 \rbrace$ such that:

$$
l_i(x) = \begin{cases}
y_i \quad \text{if } x \text{ = } x_i \\
0 \quad \text{otherwise}
\end{cases}
$$

How to enforce that $l_i(x) = 0 \text{ if } x \ne x_i$? Like this:

$$
l^\prime_i(x) = \prod_{0 \le j \le k,j \ne i}(x - x_j)
$$

Now how to additionally enforce that $l_i(x) = y_i \text{ if } x = x_i$? Multiply $l^\prime_i(x)$ by the multiplicative inverse of $l^\prime_i(x_i)$ and then additionally multiply it by $y_i$:

$$
l_i(x) = y_i(\prod_{0 \le j \le k,j \ne i}(x - x_j))(\prod_{0 \le j \le k,j \ne i}(x_i - x_j))^{-1}
$$

Notice that $l_i$ is a polynomial of degree k.

Now consider the following function:

$$
f(x) = \sum_{0 \le i \le k}l_i(x)
$$

Notice that this function is a sum of degree-k polynomials (so it is itself a degree-k polynomial) which passess through all k+1 points in S. But since there's only one such polynomial, this is **the** unique polynomial with this property.

This means that by interpolating the polynomial mod p using the points given in the challenge and evaluating it at x=0, we can recover the constant term. This is exactly how [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) works.

In SageMath, we can use a builtin method `lagrange_polynomial` to perform that interpolation:
```py
sage: F = GF(p) # F represents the field of integers mod p
sage: R = F['x'] # R represents the ring of univariate polynomials mod p
sage: poly = R.lagrange_polynomial(PT) # perform Lagrange interpolation
sage: ct = poly(0) # calculate the constant term of the polynomial
```

### Step 2 - calculating the e-th root of the constant term
Remember that the constant term of the polynomial we just recovered is $ct \equiv m^e\ mod\ p$. We need to find m, that is the e-th root mod p of that term. Good luck with that 🙂. Luckily, we have the [Euler's theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem):

#### Euler's theorem
For any coprime positive integers a and n (i.e. gcd(a, n) = 1), the following congruence holds:

$$
a^{\phi(n)} \equiv 1\ mod\ n
$$

where $\phi(n)$ is the [Euler's totient function](https://en.wikipedia.org/wiki/Euler%27s_totient_function).

Since p is prime, $\phi(p) = p - 1$. Therefore if we find a number y s.t. $y \equiv e^{-1}\ mod\ p$, that is $ey \equiv 1\ mod\ (p - 1)$, we can perform the following calculation to get m:

$$
ct^y \equiv (m^e)^y \equiv m^{ey} \equiv m^{n\phi(p) + 1} \equiv m^{n\phi(p)}m^1 \equiv m^1 \equiv m\ mod\ p
$$

Recall that a modular inverse of a mod n exists iff gcd(a, n) = 1. Unfortunately, in this case gcd(e, p - 1) = 2, so no y satisfying the above conditions exists. However, gcd(e/2, p - 1) = 1, so it is possible to find a z s.t. $z \equiv (\frac{e}{2})^{-1}\ mod\ (p - 1)$ and then calculate $m^2\ mod\ p$:

```py
sage: Z = Zmod(p - 1) # Z represents the ring of integerd mod (p - 1)
sage: half_of_e = Z(e // 2) # e/2 as an element of Z
sage: z = half_of_e^-1 # an integer z s.t. (e/2)*z ≡ 1 mod (p - 1)
sage: m_squared = ct^z # ct^z ≡ ((m^2)^(e/2))^z ≡ (m^2)^((e/2)z) ≡ m^2 mod p
```

### Step 2.5 - calculating the square root mod p
A square root of a mod n is defined as a number b s.t. $b^2 \equiv a\ mod\ n$. There are a few algorithms for calculating a modular square root, such as [Tonelli-Shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) or [Cipolla's algorithm](https://en.wikipedia.org/wiki/Cipolla%27s_algorithm). In SageMath, it is possible to calculate a square root of a number mod n by invoking the `.sqrt()` method on an object representing this number in the ring `Zmod(n)`. However, in our specific case we can do a different thing and exploit one more theorem: the [Fermat's little theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem):

#### Fermat's little theorem
For any prime p and any integer a, $a^p \equiv a\ mod\ p$.

From this it follows that $a^{p + 1} \equiv a^2\ mod\ p$. Now consider the case when $p + 1 \equiv 0\ mod\ 4$ (which is also the case with the prime p we get in this challenge); then:

$$
a^\frac{p + 1}{4} \equiv (a^{p + 1})^\frac{1}{4} \equiv (a^2)^\frac{1}{4} \equiv a^\frac{1}{2}\ mod\ p
$$

So if p is a prime s.t. $p + 1 \equiv 0\ mod\ 4$, we can calculate a square root mod p of an integer a by calculating $a^\frac{p + 1}{4}\ mod\ p$.

```py
sage: m = m_squared.sqrt() # method 1 (always works, assuming m is a quadratic residue)
sage: m = m_squared^((p + 1) // 4) # method 2 (works if we're working mod a prime p s.t. (p + 1) % 4 = 0)
```

### Step 3 - reading the flag
Just convert the integer to bytes object using [PyCryptodome](https://pypi.org/project/pycryptodome/)'s `long_to_bytes`:

```py
sage: from Crypto.Util.number import long_to_bytes
sage: long_to_bytes(int(m))
b'CCTF{SSS_iZ_4n_3fF!ciEn7_5ecr3T_ShArIn9_alGorItHm!}'
```

#### Note
It could be that you would get garbage from that - after there might be 2 distinct square roots of a mod p. If you got garbage for a square root b, try the other square root - $-b\ mod\ p$ (that is, p - b).
