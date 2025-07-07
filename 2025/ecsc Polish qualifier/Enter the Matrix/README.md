# Enter the Matrix

> N variables and just one equation? Gauss says this shouldn't be solvable! Right?
>
> [output.txt](https://hack.cert.pl/files/output-642aee3d6aa0e34fe6e3bae9f07b071176212e88.txt)
>
> **matrix.py**
> ```py
> import random
> from Crypto.Util.number import getPrime
> 
> 
> def main():
>     flag = open("flag.txt", "rb").read()
>     size = len(flag)
>     bits = 2048
>     p = getPrime(bits // 4)
>     q = getPrime(bits // 4)
>     n = p * q
>     coeffs = [random.randint(2 ** (bits - 1), 2 ** bits) for _ in range(size)]
>     res = [flag[i] * coeffs[i] for i in range(size)]
>     result = sum(res) % n
>     print(n)
>     print(coeffs)
>     print(result)
> 
> 
> main()
> ```

## Solution
Given are random values $c_1 \dots c_n$ and $r = \sum_{i = 0}^n x_ic_i$ where $x_1 \dots x_n$ are the bytes of the flag. This is a modular linear equation solvable with lattice reduction. The lattice to reduce is:

$$
\begin{bmatrix}
    c_1 & 1 & 0 & \dots & 0 & 0 \\
    c_2 & 0 & 1 & \dots & 0 & 0 \\
    \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\
    c_n & 0 & 0 & \dots & 1 & 0 \\
    -r & 0 & 0 & \dots & 0 & 1 \\
    n & 0 & 0 & \dots & 0 & 0
\end{bmatrix}
$$

The shortest vector of the lattice is:

$$
\begin{bmatrix}
    0 & x_1 & x_2 & \dots & x_n & 1
\end{bmatrix}
$$

which contains the flag.

## Flag
`ecsc25{apparently_LLL_is_now_baby_crypto}`
