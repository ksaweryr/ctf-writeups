# N0TR5A
> ### Category: crypto
>
> It's not RSA!
>
> ### Attachments
> `crypto_n0tr5a.zip`

## Solution
Given are: 1024-bit RSA modulus $n$, flag encrypted with that modulus, and 12 pairs of numbers $(e_i, k_i)$ such that $e_i \equiv ee_i \mod 2^{562}$ and $k_i = \frac{ee_i \cdot dd_i - 1}{\phi(n)}$ where $dd_i = key + 2(i + 1)$ and $ee_i \equiv dd_i^{-1} \mod \phi(n)$ where $key$ is a 462-bit prime. Through simple algebraic manipulations, the following equation can be derived:
$$
k_i \cdot \phi(n) - e_i \cdot key - e_i \cdot 2(i + 1) + 1 \equiv 0 \mod 2^{562}
$$

## Finding $\phi(n)...$ $\mod 2^{562}$

The following lattice can be reduced using LLL to find $\phi(n) \mod 2^{562}$ (let's call that value $\phi_1$):
$$
\begin{bmatrix}
k_0 & k_1 & \ldots & k_n & \frac{1}{2^{562}} & 0 \\
-e_0 & -e_1 & \ldots & -e_n & 0 & 0\\
-2e_0 + 1 & -4e_1 & \ldots & -2(n + 1)e_n + 1 & 0 & 1 \\
2^{562} & 0 & \ldots & 0 & 0 & 0 \\
0 & 2^{562} & \ldots & 0 & 0 & 0 \\
\vdots & \vdots & \vdots & \vdots & \vdots & \vdots \\
0 & 0 & \ldots & 2^{562} & 0 & 0

\end{bmatrix}
$$

because the vector $\begin{bmatrix} 0 & 0 & \ldots & 0 & \frac{\phi_1}{2^{562}} & 1 \end{bmatrix}$ is in that lattice (it's the image of $\begin{bmatrix} \phi_1 & key & 1 & m_1 & m_2 & \ldots & m_n\end{bmatrix}$ for some values $m_i$).

## Finding actual $\phi(n)$
Notice that $n = pq$ and $\phi(n) = (p - 1)(q - 1) = pq - p - q + 1 = n - (p + q - 1)$. As $p$ and $q$ are both 512-bit, $p + q - 1$ is at most 513-bit and thus $\phi(n) + 2^m \gt n$ for any $m \gt 513$ - this holds true specifically for $m = 562$. Since $\phi_1 \equiv \phi(n) \mod 2^{562}$, $\phi(n) = \phi_1 + a \cdot 2^{562}$. Since $\phi(n) \lt n$ but $\phi(n) + 2^{562} \gt n$, $a$ must be the biggest possible integer such that $\phi_1 + a \cdot 2^{562} \lt n$. This number can easily be found using binary search or some bit manipulation.

## Putting it all together
The script I've used to solve this challenge is available [here](./solve.sage).

## Flag
`n1ctf{7hE_Br1l1!4nCe_0f_D5tErm1Nan7_4Nd_C0PP5R4m|Th!}`