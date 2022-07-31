# not assembly
> Find the output and wrap it in `LITCTF{}` !
>
> Downloads
> [notassembly.png](https://drive.google.com/uc?export=download&id=1mV8gjChjRDSLuFUYDS_1lZemxA-SBNa7)

## Initial analysis
The image contains the following table:
|  |  |  |
|---|:---:|---:|
| FLAG | DC | 0 |
| CODETIGER | DC | 23 |
| ORZ | DC | 4138 |
|  | LOAD | ORZ |
| CODETIGER | MULT | =3 |
|  | ADD | CODETIGER |
|  | STORE | FLAG |
|  | SUB | =9538 |
|  | BL | ORZ |
|  | BU | CODETIGER |
| ORZ | LOAD | FLAG |
|  | SUB | =3571 |
|  | STORE | FLAG |
|  | PRINT | FLAG |
|  | END |  |

It's clear that despite challenge author's assertions it's some (pseudo)assembly code.
The code is divided into data section (first 3 lines, defines variables) and text section (the rest of the table, executable code).
The first column contains labels, the second one - opcodes and the third one - arguments.

## Decoding the opcodes
`DC` must be an opcode for something like `define` and it defines the variables' initial values.
`LOAD` is usually an instruction that loads a value (either a constant value or from a variable) to a register.
`MULT` multiplies the value stored in a register by the argument.
`ADD` adds the argument to a register.
`STORE` stores the value from a register to the pointed by the argument.
`SUB` subtracts the argument from the register.
`BL` stands for `branch if less` and jumps to the label passed as the argument if, in our case, value in the register is lesser then 0.
`BU` must be an unconditional branch that jumps to the label under any circumstances.
`PRINT` prints the variable.
`END` ends the program.
Note that every opcode takes at most 1 argument. Therefore we'll assume that the opcodes all operate on a single register.

## Rewriting the program
Now that we understand the opcodes, we can rewrite the program in an actual programming language and execute it. The following is this program written in Python:
```py
flag = 0
codetiger = 23
orz = 4138

while True:
	orz *= 3
	orz += codetiger
	flag = orz
	orz -= 9538
	if orz < 0:
		break

flag -= 3571
print(flag)
```

## Flag
`LITCTF{5149}`
