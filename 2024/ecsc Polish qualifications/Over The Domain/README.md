# Over The Domain

> Somebody sent us ransom note that they exfiltrated precious ZIP file from our server but we can see that only DNS queries have been made. Can you find what data has been stolen?
>
> [over-the-domain.pcap](https://hack.cert.pl/files/over-the-domain-38bca639a6724bb1fca1b697dbbbadbcb6fd5f04.pcap)

## Solution
... Prepare your guessing I guess.

Notice that some queries have Base64-encoded data prepended as a subdomain. Since the challenge description mentions we're looking for a zip file, try finding the zip file header:
```py
import pyshark
from base64 import b64decode

cap = pyshark.FileCapture('./over-the-domain.pcap')

packets = [*cap]

for p in packets:
    qr = p.dns.qry_name
    try:
        payload = b64decode(qr.split('.')[0])
        if payload.startswith(b'PK\x03\x04'):
            print('FOUND', qr)
    except:
        pass
```

This results in:
```
FOUND UEsDBAoAAAAAAHpj.X.yahoo.com
```
Now notice that in all DNS queries of the form `<base64-encoded data>.<single letter>.<real service>.<tld>` the single letter is either a lowercase letter or the uppercase `X`. As uppercase letters are before lowercase letters in the ASCII table and the zip file header is in a query with uppercase `X`, maybe we only have to consider queries to 4-part domains and sort them by the 2nd segment?

```python
import pyshark
from base64 import b64decode

cap = pyshark.FileCapture('./over-the-domain.pcap')

packets = [*cap]

packets = [p for p in packets if len(p.dns.qry_name.split('.')) > 3]
packets.sort(key=lambda x: x.dns.qry_name.split('.')[1])
result = b''

for p in packets:
    qr = p.dns.qry_name
    payload = b64decode(qr.split('.')[0])
    result += payload

with open('out.zip', 'wb') as f:
    f.write(result)
```
Indeed, this creates a valid zip file with the flag.

## Flag
`ecsc24{th1s_w4s_n0t_mean7_t0_b3_s33n}`
