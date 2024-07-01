# confidentialAlchemy

> Pinch of AES, touch of SHA and a spoon of XOR. Add encodings and mix thoroughly. Here! The perfect secret recipe!
>
> `nc confidential.ecsc24.hack.cert.pl 5100`
>
> ```bash
> #!/bin/bash
> 
> secrets_file="./secret.bin"
> flag_file="./flag.txt"
> 
> if [ ! -f "$flag_file" ]; then
>     echo "FLAG FILE MISSING !"
>     exit -1
> fi
> 
> if [ ! -f "$secrets_file" ]; then
>     dd if=/dev/urandom of="$secrets_file" bs=14 count=1 2>/dev/null
> fi
> 
> secret=`cat $secrets_file`
> 
> # AES enc
> enc_aes=`openssl enc -aes-256-cbc -pbkdf2 -iter 1000001 -salt -a -A -kfile "$secrets_file" -in $flag_file`
> 
> 
> # Gen SHA512 xor key
> sha512="$secret`echo -n "$secret" | sha512sum | cut -d' ' -f1`"
> 
> # xor
> perl -e '@a=split("", $ARGV[0]); @b=split("", $ARGV[1]); print unpack "H2", chr(ord(shift @a)^ord(shift @b)) while @a; print "\n"' "$sha512" "$enc_aes"
> ```


## Solution
When you encrypt something with OpenSSL and use a salt, the ciphertext will always start with the string `Salted__` (8 bytes). As the contents of `enc_aes` variable is Base64-encoded ciphertext (notice the `-A` flag in the command), it must start with `U2FsdGVkX1` followed by `8`, `9`, `+` or `/` (depending on the first 2 bits of the salt). Therefore we know the first 10 characters of `aes_enc` and we know that the 11th character can take one of 4 values. Now notice that the output we get is `enc_aes` xored with `sha512`, which is the concatenation of 14-byte `secret` and its hash. That means that after xoring the output with `U2FsdGVkX1`, we get the first 10 bytes of `secret`, we have 4 possibilites for the 11th byte, and we can just bruteforce the last 3. To validate that we found the collect key, we can use the fact that the (hex-decoded) output ends in a rather long hex-string (due to the fact that `sha512` is longer than `enc_aes`). A Python script to recover `secret` and `enc_aes` looks like this:

```py
from base64 import b64encode, b64decode
from hashlib import sha512


def xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])


data = bytes.fromhex('f11323f60f914e33c291d1e8c18a1c7c022b7d2c1324096c0d0112252e21223875460554747967415c707a4d362e7f52040d6042335a707336413161624d43470c5770147e66660426674953447e160a5a717f79035a75742857002c577147777e42180b5f59575c010a745e32643063343637393035313966633036393666336236343363663365633930363136')

tail_probably_just_hash = '2d0c46790519fc0696f3b643cf3ec90616'

for final_char in [b'8', b'9', b'+', b'/']:
    init = b'U2FsdGVkX1' + final_char
    secret_msbs = xor(init, data)
    for a in range(256):
        for b in range(256):
            for c in range(256):
                secret = secret_msbs + bytes([a, b, c])
                h = sha512(secret).hexdigest()
                xor_key = secret + h.encode()
                assert len(data) == len(xor_key)
                decrypted1 = xor(data, xor_key)
                if decrypted1.endswith(b'\x00' * len(tail_probably_just_hash)):
                    print(f'{secret = }')
                    print(f'{decrypted1 = }')
                    exit(0)
```

After calculating these values, we can just put the secret into `secret.bin`, the ciphertext into `enc` and use OpenSSL to decrypt the flag:

`$ openssl aes-256-cbc -d -pbkdf2 -iter 1000001 -in enc -kfile secret.bin`.

## Flag
`ecsc24{Flag__MoreCryptoMoreSecure!!!!111oneone}`
