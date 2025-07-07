# Quine

> Can you make this VM output a quine?
>
> [quine.7z](https://hack.cert.pl/files/quine-d5f9d330b78147c6f4462deabea79d9e03a63baf.7z)

## Solution
The program is a Rust VM with an instruction buffer, output buffer and 4 registers: `ip` (instruction pointer), `ax`, `bx` and `cx`. It loads the program from `bytecode.txt`, takes the middle part of the flag (everyting inside of `ecsc25{}`), converts it to bytes, xors with `0x48c8ce7c0a532ec7`, puts the result in `ax` and starts the program. The program consists of instructions that each contain 2 numbers: an opcode and an argument. The argument is evaluated by the `operand_value` function:

- if the operand is between 0 and 4, `operand_value` returns the value of the operand
- if the operand is between 5, 6 or 7, `operand_value` returns the current value of `ax`, `bx` or `cx`, respectively

Finally, the instructions are evaluated in the `single_step` function. Because Ghidra can't deal with the jump table, it was easier for me to set a breakpoint on `single_step` in gdb and dynamically figure out what the opcodes do. Based on that analysis, the opcodes are:

- 0: `ax := ax >> operand_value(operand)`
- 1: `bx := operand_value(operand) & 7`
- 2: `cx := operand_value(operand) & 7`
- 3: `bx := bx ^ operand_value(operand)`
- 4: `bx := f1(operand_value(operand))`
- 5: `cx := f2(operand_value(operand))`
- 6: if `ax` is not 0, set `ip` to `operand` (**not** `operand_value(operand)`); otherwise, terminate
- 7: append `operand_value(operand)` to output buffer

`f1` and `f2` are functions that calculate a hash using `std::hash::DefaultHasher`.

As such, the given program is:
```
cx := ax & 7   # 2,5,
bx := f1(2)    # 4,2, - f1(2) = 2
bx := bx ^ cx  # 3,7,
ax := ashr(3)  # 0,3,
cx := f2(3)    # 5,3, - f2(3) = 6
bx := bx ^ cx  # 3,7,
cx := ax & 7   # 2,5,
bx := bx ^ cx  # 3,7,
print(bx)      # 7,6,
loop           # 6,0 - loops if ax isn't 0, otherwise terminate
```

It seems that every number in the output depends only on 6 bits of the flag, as such the flag can be bruteforced 6 bits at a time. Since `f1` and `f2` are only invoked on constants `2` and `3` respectivelly, they can be precalculated (either using a debugger or by writing a simple Rust program) so that the solver can be written in a different programming language (Python):

```py
from Crypto.Util.number import long_to_bytes


def step(st):
    (a, b, c) = st

    c = a & 7
    b = 2 # f1(2)
    b = b ^ c
    a = a >> 3
    c = 6 # f2(3)
    b = b ^ c
    c = a & 7
    b = b ^ c
    return (b, (a, b, c))

target = [2,5,4,2,3,7,0,3,5,3,3,7,2,5,3,7,7,6,6,0]
states = [(0, 0, 0)]

for j, t in enumerate(target):
    new_states = []
    for _, b, c in states:
        results = [(i, step((i, b, c))) for i in range(2**6)]
        possible = [(i, (o, st)) for (i, (o, st)) in results if o == t]
        for (i, (_, st)) in possible:
            for (a, _, _) in states:
                if (a ^ (i << (j * 3))) & (7 << (j * 3)) == 0:
                    new_states.append(((a | (i << (j * 3))), b, c))
    states = new_states

for (a, _, _) in states:
    core = long_to_bytes(a ^ 0x48c8ce7c0a532ec7)
    assert len(core) == 8
    print('ecsc25{' + core.decode() + '}')
```

## Flag
`ecsc25{AoC24d17}`
