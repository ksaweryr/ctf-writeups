# Levelled MFA

> Some hackers broke into our last service, so we have a new one!
>
> [https://levelledmfa.ecsc25.hack.cert.pl/](https://levelledmfa.ecsc25.hack.cert.pl/)
>
> **app.py**
> ```py
> from flask import Flask, request, abort, jsonify
> from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, verify_jwt_in_request, JWTManager
> import base64
> 
> 
> class LCG:
>     def __init__(self, bit_count: int):
>         import random
>         # from Crypto.Util.number import getPrime
>         # p = getPrime(bit_count)
>         # a = random.randint(p // 2, p)
>         # print(p, a)
>         p = 237265950040262713941897142843147616729
>         a = 233399005916624306523442005425011133900
>         self.a = a
>         self.p = p
>         self.current = random.randint(p // 2, p)
>         print(f'Starting seed: {self.current}')
> 
>     def _next(self):
>         self.current = self.a * self.current % self.p
>         return self.current
> 
>     def getrandbits(self, bit_count: int) -> int:
>         result_bits = []
>         while len(result_bits) < bit_count:
>             val = self._next()
>             bits = bin(val)[2:].zfill(self.p.bit_length())
>             result_bits.extend(bits)
>         result_bits = result_bits[:bit_count]
>         bitstring = ''.join(result_bits)
>         return int(bitstring, 2)
> 
> 
> random = LCG(128)
> 
> 
> def get_random_string(length):
>     return random.getrandbits(length * 8).to_bytes(length, 'big')
> 
> 
> def get_mfa():
>     return base64.b64encode(get_random_string(8)).decode()
> 
> 
> app = Flask(__name__)
> app.config["JWT_SECRET_KEY"] = get_random_string(32)
> jwt = JWTManager(app)
> 
> FLAG = open("flag.txt", 'r').read()
> random_passwords = [base64.b64encode(get_random_string(8)).decode() for _ in range(64)]
> 
> 
> @app.route('/generate', methods=['GET'])
> def generate_password():
>     token = verify_jwt_in_request(optional=True)
>     if token is None:
>         index = 0
>     else:
>         _, jwt_data = token
>         index = (jwt_data['current'] + 1) % len(random_passwords)
>     access_token = create_access_token(identity="user", additional_claims={'current': index})
>     return jsonify({'token': access_token, 'password': random_passwords[index]})
> 
> 
> @app.route('/flag', methods=['POST'])
> @jwt_required()
> def flag():
>     current_user = get_jwt_identity()
>     otp = get_mfa()
>     if current_user == "admin" and request.json['OTP'] == otp:
>         return jsonify({"flag": FLAG})
>     else:
>         abort(403, f"Nope, it was {otp}")
> 
> 
> @app.get("/")
> def index():
>     return "You can't connect to this API with your browser. Check the source code."
> 
> 
> if __name__ == "__main__":
>     app.run()
> 
> ```

## Solution
This challenge is mostly the same as [Easy MFA](../Easy%20MFA/) and as such most of the code from its solution can be reused. The difference is that here the random number generation algorithm to crack is a LCG where $b = 0$. Given are 64 random numbers generated as upper 64 bits of 128-bit LCG outputs; that is, given are numbers $h_1 \dots h_{64}$ such that $2^{64} \cdot h_i + l_i = x_i$ for a 64-bit $l_i$ where  $x_1 \dots x_{64}$ satisfying the congruences $x_{i + 1} \equiv ax_{i} \mod p$, or $x_{i + 1} \equiv a^ix_0 \mod p$. Substituting $h_{i + 1}$ into the congruence gives $2^{64} \cdot h_{i + 1} + l_{i + 1} \equiv a^ix_0 \mod p$, which is equivalent to $2^{64} \cdot h_{i + 1} - a^ix_0 + l_{i + 1} \equiv 0 \mod p$. With $h_{i + 1}$ and $a^i$ known and $x_0$ being the unknown value to be found, this is an instance of the hidden number problem. Following [A Gentle Tutorial for Lattice-Based Cryptanalisys](https://eprint.iacr.org/2023/032.pdf) and knowing that $p \in [2^{127}, 2^{128}]$, the problem should be solvable if the number of samples is $m = 24$ and the error terms $l_i$ are smaller than $B = 2^{109}$. Since in this case there are 64 samples and the errors are smaller than $2^{64}$, it is possible to recover $a_0$ using LLL. The approach I've chosen is to use Kannan's embedding, as it is more effective:

```py
from sage.all import *

a = 233399005916624306523442005425011133900
p = 237265950040262713941897142843147616729

results = [...] # outputs from the web app

tis = [-a**(i + 1) for i in range(64)]
ais = [-2**64 * results[i] for i in range(64)]
B = 2**64
to_use = 64
tis = tis[:to_use]
ais = ais[:to_use]

m = (matrix.identity(QQ, to_use) * p).stack(matrix(QQ, [tis, ais])).augment(vector(QQ, [0] * to_use + [QQ((B, p))] + [0])).augment(vector(QQ, [0] * (to_use + 1) + [B]))
red = m.LLL()

for row in red:
    if row[-1] in [-B, B]:
        rec = pow(a, -1, p) * (results[0] * 2**64 + row[0]) % p
        if seed is not None:
            assert seed == rec
        break
else:
    raise Exception('Not found!')

seed = pow(a, -2, p) * rec % p
print(f'{seed = }')

class LCG:
    def __init__(self, bit_count: int, seed):
        import random
        p = 237265950040262713941897142843147616729
        a = 233399005916624306523442005425011133900
        self.a = a
        self.p = p
        self.current = seed

    def _next(self):
        self.current = self.a * self.current % self.p
        return self.current

    def getrandbits(self, bit_count: int) -> int:
        result_bits = []
        while len(result_bits) < bit_count:
            val = self._next()
            bits = bin(val)[2:].zfill(self.p.bit_length())
            result_bits.extend(bits)
        result_bits = result_bits[:bit_count]
        bitstring = ''.join(result_bits)
        return int(bitstring, 2)


def get_random_string(length):
    return random.getrandbits(length * 8).to_bytes(length, 'big')


random = LCG(128, seed)
jwt_key = get_random_string(32)
print(f'{jwt_key = }')
```

The rest of the solution is exactly as in the preceeding challenge.

## Flag
`ecsc25{1_h0pe_it_w4s_n0t_just_ch4tgp7_vib1ng}`
