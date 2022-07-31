# A ROCk
> I used to love RSALib, but not anymore...
> 
> Downloads
> [arock.zip](https://drive.google.com/uc?export=download&id=1YlGBKe7x0K5erD9O0SxrFjWcCE7sUvfM)

## Solution
The challenge's name and description hint that file `nums.txt` contains a ciphertext and a ROCA-vulnerable RSA public key. Factors of `n` can be easily and quickly recovered using [this script written in SageMath](https://github.com/FlorianPicca/ROCA) and then used to decrypt the ciphertext (here an example in IPython):
```py
In [1]: ct=3831129304332239255280117442393824529915871197799278700713657686877437561020805823052809122048327006270135775002283258453774226602640149683603252934547033

In [2]: p=123411621633636675541493070644959834875873057348494554188657868973313372350191

In [3]: q=70672758723177433011581077796363544664410141195648490771860623139983928782297

In [4]: e=65537

In [5]: d = pow(e, -1, (p - 1) * (q - 1))

In [6]: from binascii import unhexlify

In [7]: unhexlify(f'{pow(ct, d, p * q):x}'.encode())
Out[7]: b'LITCTF{rsalib_n0_m0r333}'
```

## Flag
`LITCTF{rsalib_n0_m0r333}`
