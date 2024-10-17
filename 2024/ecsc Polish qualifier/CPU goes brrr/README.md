# CPU goes brrr

> It might print the flag. If you wait long enough... [https://www.youtube.com/watch?v=h3hwff_CeeM](https://www.youtube.com/watch?v=h3hwff_CeeM).
>
> [brrr](https://hack.cert.pl/files/brrr-c97b4a13b1f872ae475ca20d53db37daf48a7fb1)

## Solution
The main function (apart from having a loop that never executes and doing other weird stuff) decodes characters stored in a global buffer by xoring them with a value returned by a call to a function `f` with the loop counter cubed as the argument. The first thing function `f` does is calling a function `g` with its argument. The function `g` calls function `h` on its argument and then calls function `i` on the result - if `i` doesn't return true, it repeats the process, if it does, it returns the result of `h`. It can be easily noticed that function `i` just checks if the argument `n` is a prime number in `O(n)` time. Function `h` supplied with argument `i` returns the `i`th [tribonacci number](https://oeis.org/A000213), calculated recursively without dynamic programming, which makes it run in exponential time. That means that function `g` returns the first tribonacci number at index greater or equal than `i` that is prime. After getting the result of the call to `g` (and performing bitwise negation on it - this value will be used as an accumulator), function `f` constructs its return value bit-by-bit by performing some operation on the accumulator `0xba04015` and using its most significant bit as the next bit for the return value. What is this operation? Just a round of a linear-feedback shift register. This means that we can represent this operation as a matrix multiplication and use fast exponantiation to calculated the matrix corresponding to performing this operation `0xba04015` times. We can implement all of the above more efficiently in Python (using some SageMath for matrix operations and more efficient `is_prime`) to calculate the flag - one thing to keep in mind is that tribonacci numbers will not overflow in Python, but they would in C - we just have to implement overflows, e.g. by performing calculations on numpy's `uint64`:

```py
from functools import cache
from itertools import count
import numpy as np
from sage.all import *


# Python's dynamic programming - `functools.cache` :p
@cache
def tribonacci(i):
    if i < 3:
        return 1
    else:
        return int(np.uint64(tribonacci(i - 1)) + np.uint64(tribonacci(i - 2)) + np.uint64(tribonacci(i - 3)))


def first_prime_tribonacci_after_index(idx):
    for i in count(idx):
        t = tribonacci(i)
        if is_prime(t) and t != 2:
            return t


m = matrix(GF(2), [0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
m = m.stack(matrix.identity(15).augment(matrix([0] * 15).transpose()))
lfsr_matrix = m**0xba04015


def ushort_to_vector(n):
    bits = []
    for i in range(16):
        bits.append(n & 1)
        n >>= 1
    return vector(bits[::-1])


def vector_to_ushort(v):
    result = 0
    for b in v:
        result <<= 1
        result |= int(b)
    return result


def called_from_main(n):
    a = first_prime_tribonacci_after_index(n)
    a = (~a) & ((1 << 16) - 1)
    result = 0
    for i in range(8):
        a = vector_to_ushort(lfsr_matrix * ushort_to_vector(a))
        result = (result * 2) + ((a >> 15) & 1)
    return result


flag_length = 37
encoded_chars = [ 0x6e, 0x68, 0x78, 0x08, 0xb0, 0x77, 0x45, 0x00, 0x6f, 0x89, 0x8b, 0x04, 0xbc, 0xe8, 0xc2, 0x99, 0x3b, 0xdc, 0x0b, 0x43, 0x4f, 0x21, 0x72, 0x56, 0xc8, 0xdd, 0xe3, 0xe8, 0x46, 0xed, 0x94, 0xd7, 0x6f, 0x05, 0x01, 0xf4, 0xbf ]

assert len(encoded_chars) == flag_length
for i in range(flag_length ** 3):
    # precalculate the results to avoid stack overflow when calling `tribonacci` with a big argument
    _ = tribonacci(i)

result = []

for i, b in enumerate(encoded_chars):
    i3 = i * i * i
    c = called_from_main(i3)
    result.append(b ^ c)

print(bytes(result).decode())

```

## Flag
`ecsc24{sl0w_4nd_5t3ady_w1ns_th3_r4ce}`
