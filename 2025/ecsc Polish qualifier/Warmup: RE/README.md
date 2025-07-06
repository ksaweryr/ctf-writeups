# Warmup: RE

> W tym roku przygotowaliśmy kilka zadań dla osób, które chcą zacząć swoją przygodę z konkursami z dziedziny cyberbezpieczeństwa (zazwyczaj nazywanymi CTFami). Dla tych z was, którzy pozjadali już zęby na CTFach, zadania te będą proste (lub wręcz trywialne), ale jeśli dla kogoś jest to pierwszy start - warto zacząć od nich przed przejściem do tych trudniejszych.
>
> Zadania wraz z ich opisami znajdziesz na poniższej stronie:
>
> [https://warmup.ecsc25.hack.cert.pl/#re](https://warmup.ecsc25.hack.cert.pl/#re)
>
> Na tej podstronie wpisz flagę z zadania w kategorii **reverse engineering**.


## Solution
The program xors user input with some predefined buffer (`key`) and compares the result against another buffer (`ref`). Xor the two buffers to get the flag:

```py
from ast import literal_eval


def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))


def eval_byte(x):
    x = literal_eval(x)
    if type(x) is int:
        if x < 0:
            x += 256
        return x
    else:
        return ord(x)


ripped = '''  key[0] = -0x1c;
  key[1] = -4;
  key[2] = -0x7d;
  key[3] = -0x50;
  key[4] = -0x14;
  key[5] = -0x7c;
  key[6] = 'r';
  key[7] = -0x76;
  key[8] = -0x1d;
  key[9] = -0x4c;
  key[10] = -0x14;
  key[11] = -0x6f;
  key[12] = '\x03';
  key[13] = '1';
  key[14] = '/';
  key[15] = '&';
  key[16] = '0';
  key[17] = -0x35;
  key[18] = -0x3c;
  key[19] = -8;
  key[20] = -7;
  key[21] = '1';
  key[22] = -0x47;
  key[23] = -0x6d;
  key[24] = -0x20;
  key[25] = -0x30;
  key[26] = -0x50;
  key[27] = 'R';
  key[28] = -0x19;
  key[29] = '\x0f';
  key[30] = -0x1c;
  key[31] = 'o';
  key[32] = 's';
  key[33] = -0xe;
  key[34] = 'G';
  key[35] = '\v';
  key[36] = -0x61;
  key[37] = -0x5b;
  key[38] = '_';
  ref[0] = -0x7f;
  ref[1] = -0x61;
  ref[2] = -0x10;
  ref[3] = -0x2d;
  ref[4] = -0x22;
  ref[5] = -0x4f;
  ref[6] = '\t';
  ref[7] = -0x1a;
  ref[8] = -0x76;
  ref[9] = -0x21;
  ref[10] = -0x77;
  ref[11] = -0x44;
  ref[12] = 'f';
  ref[13] = '_';
  ref[14] = 'H';
  ref[15] = 'O';
  ref[16] = '^';
  ref[17] = -0x52;
  ref[18] = -0x5f;
  ref[19] = -0x76;
  ref[20] = -0x70;
  ref[21] = '_';
  ref[22] = -0x22;
  ref[23] = -0x42;
  ref[24] = -0x7e;
  ref[25] = -0x5b;
  ref[26] = -0x3c;
  ref[27] = '\x7f';
  ref[28] = -0x72;
  ref[29] = 'a';
  ref[30] = -0x37;
  ref[31] = '\x1d';
  ref[32] = '\x16';
  ref[33] = -0x7c;
  ref[34] = '\"';
  ref[35] = 'y';
  ref[36] = -0x14;
  ref[37] = -0x40;
  ref[38] = '\"';'''

lines = [l.strip() for l in ripped.split('\n')]
k = [eval_byte(l.split(' = ')[1][:-1]) for l in lines if l.startswith('key')]
r = [eval_byte(l.split(' = ')[1][:-1]) for l in lines if l.startswith('ref')]
print(xor(k, r))
```

## Flag
`ecsc25{like-engineering-but-in-reverse}`
