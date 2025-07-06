# Warmup: Crypto

> W tym roku przygotowaliśmy kilka zadań dla osób, które chcą zacząć swoją przygodę z konkursami z dziedziny cyberbezpieczeństwa (zazwyczaj nazywanymi CTFami). Dla tych z was, którzy pozjadali już zęby na CTFach, zadania te będą proste (lub wręcz trywialne), ale jeśli dla kogoś jest to pierwszy start - warto zacząć od nich przed przejściem do tych trudniejszych.
>
> Zadania wraz z ich opisami znajdziesz na poniższej stronie:
>
> [https://warmup.ecsc25.hack.cert.pl/#crypto](https://warmup.ecsc25.hack.cert.pl/#crypto)
>
> Na tej podstronie wpisz flagę z zadania w kategorii **kryptografia**.


## Solution
Three messages are encrypted with AES-CTR mode with the same key and IV, which means they will all have the same "key stream", since the CTR mode is basically a one-time pad. That means that it's possible to use the ciphertext and plaintext of the 2nd message (the longest one) to recover the flag by calculating $pt_{2} \oplus ct_{2} \oplus ct_{3}$:

```py
from Crypto.Cipher import AES


def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))


with open('encrypted.txt', 'rt') as f:
    lines = f.readlines()

print(xor(xor(bytes.fromhex(lines[1]), bytes.fromhex(lines[2])), b"did you ever hear the tragedy of darth plagueis the wise"))
```

## Flag
`ecsc25{crypto-means-cryptography-and-get-off-my-lawn}`
