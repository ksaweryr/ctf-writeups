from Crypto.Util.number import long_to_bytes


def calculate_lambda(A, B, p):
    cf = (A/p).continued_fraction()
    lm = None
    for i in range(cf.length()):
        if cf.denominator(i) < B and B <= cf.denominator(i + 1):
            lm = cf.denominator(i)
            break
    assert lm is not None
    return lm


with open('params_enc.txt', 'rt') as f:
    exec(f.read())

p = Integer(p)
F = GF(p)

alpha = []
beta = []
d = 32
assert len(Q) == len(R) == len(S) == d

B = p.isqrt()

# reduce HNP-2H to HNP
for i in range(len(Q)):
    A = (F(R[i])^-1 * F(S[i])).lift()
    lm = calculate_lambda(A, B, p)
    alpha.append(F(lm * (F(R[i])^-1).lift() * Q[i]).lift())
    beta.append((lm * (F(R[i])^-1).lift() * C[i] + floor(p.isqrt() * 2^33)) % p)


# construct the matrix used to solve HNP with Kannan's embedding
B = p.isqrt() * 2^34

mat = matrix.identity(QQ, d) * p
mat = mat.stack(-matrix(QQ, alpha))
mat = mat.stack(matrix(QQ, beta))
mat = mat.augment(vector(QQ, [0] * 32 + [B / p] + [0]))
mat = mat.augment(vector(QQ, [0] * 33 + [B]))

# verify and print the result
reduced = mat.LLL()
assert reduced[0][-2] == -B
print(long_to_bytes(int(reduced[1][-2] * p / B)).decode())
