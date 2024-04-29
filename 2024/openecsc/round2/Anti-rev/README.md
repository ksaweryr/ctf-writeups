# Anti-rev
> ### Category:  rev
>
> Good luck finding the secret word for my super secure program!
>
> ### Attachments
>
> `anti-rev`
## Initial recon
The given file is a non-stripped executable for x64 Linux:
```
$ file anti-rev 
anti-rev: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=16178f4caa883dc2c4bdabf99358ac9d20a99642, for GNU/Linux 3.2.0, not stripped
```

After looking at the decompiled code in ghidra, something seems off - as if the `main` function only ever checked if the initial part of the flag is wrong:
```c
/* WARNING: Removing unreachable block (ram,0x00101def) */

int main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_38,0x1f,stdin);
  iVar1 = strncmp(local_38,"openECSC{",9);
  if (iVar1 == 0) {
    return iVar1;
  }
  puts("Wrong!");
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
It does however warn about an unreachable block, which turns out to be a piece of code executed if the whole flag is correct:
``` 
00101de9 83 7d c4 00     CMP        dword ptr [RBP + local_44],0x0
00101ded 74 09           JZ         LAB_00101df8
00101def 48 8d 05        LEA        RAX,[s_Correct!_0010200e]   = "Correct!"
         18 02 00 00
00101df6 eb 07           JMP        LAB_00101dff
```
## "Hidden" code
It's worth noting that there's a big chunk of data between the start of the `main` function and this block of code. Let's look at the code right before this block:
```
001011f8 48 8d 35        LEA        RSI,[s_openECSC{_00102004]  = "openECSC{"
         05 0e 00 00
001011ff 48 89 c7        MOV        RDI,RAX
00101202 e8 79 fe        CALL       <EXTERNAL>::strncmp
         ff ff
00101207 85 c0           TEST       EAX,EAX
00101209 0f 85 9a        JNZ        LAB_00101da9
         0b 00 00
0010120f e8 00 00        CALL       LAB_00101214
         00 00
                        LAB_00101214    XREF[1]:     0010120f(j)  
00101214 48 83 04        ADD        qword ptr [RSP]=>local_50,offset LAB_0010121a
         24 06
00101219 c3              RET
                        LAB_0010121a
```
The instruction at `0010120f` calls the piece of code at `LAB_00101214` (literally the next instruction), which in turn sets the value on top of the stack (i.e. the return address) to the address of `LAB_0010121a` (the start of big data block) and then returns - this prevents ghidra from correctly guessing that this big block of data is in fact code. We can still force it to disassemble the block by selecting it and pressing 'd'. This way we can read more code:
```
                        LAB_0010121a
0010121a 0f b6 45 ed     MOVZX      EAX,byte ptr [RBP + -0x13]
0010121e 3c 7d           CMP        AL,0x7d
00101220 0f 85 86        JNZ        LAB_00101dac
         0b 00 00
00101226 c6 45 c3 83     MOV        byte ptr [RBP + -0x3d],0x83
0010122a 48 8b 45 c8     MOV        RAX,qword ptr [RBP + -0x38]
0010122e 0f b6 00        MOVZX      EAX,byte ptr [RAX]
00101231 89 c2           MOV        EDX,EAX
00101233 89 d0           MOV        EAX,EDX
00101235 c1 e0 04        SHL        EAX,0x4
00101238 01 d0           ADD        EAX,EDX
0010123a 00 45 c3        ADD        byte ptr [RBP + -0x3d],AL
0010123d 48 8b 45 c8     MOV        RAX,qword ptr [RBP + -0x38]
00101241 48 83 c0 01     ADD        RAX,0x1
00101245 0f b6 00        MOVZX      EAX,byte ptr [RAX]
[...]
```
## Information about flag
Let's focus on the first 3 instructions - they load a byte from `RBP - 0x13` and compare it to `0x7d`, which is the ascii code for `}`. If they're not equal, a jump to a much furhter address (probably printing `Wrong!`) is performed, otherwise we continue with the operations. From the decompiled `main` we know that the flag is read into a variable called `local_38`, which in ghidra means a variable which starts 0x38 bytes before the return address - that is, at `RBP - 0x30`, since the first 8 bytes in front of the return address is the saved value of old base pointer. Since the character at `RBP - 0x13` should be a closing curly bracket, we can calculate that the length of the flag is 0x30 - 0x13 + 1 = 30 characters.
## A ~~lazy~~ smart approach
We can see that after this check a lot of simple operations are performed on some numbers, which are later saved in a separate buffer and compared to the values of flag's characters. There's a lot of that, so do we need to analyse all of that by hand? Not really - since the operations are relatively simple, we can use [angr](https://angr.io/) - a tool for symbolic analysis that's often useful when solving rev challenges. We don't need anything fancy here, just a basic angr script will suffice:
```py
import angr
import claripy

# create symbolic bit vectors representing bytes of the flag s.t. the following constraints hold:
# - every character should be printable (between ' ' and '~' in the ascii table)
# - there should be 20 characters between 'openECSC{' and '}' (30 - len('openECSC{') - len('}'))
to_find = [claripy.BVS(f'kernel_{i}', 8, ord(' '), ord('~')) for i in range(20)]
# concatenate known and unknown parts of the flag to get one bit vector
flag = claripy.Concat(claripy.BVV(b'openECSC{'), *to_find, claripy.BVV(b'}'))

p = angr.Project('./anti-rev')
# create a blank state, specify the entry address (address of main function)
# and the contents of standard input (the flag)
st = p.factory.blank_state(addr=p.loader.find_symbol('main').rebased_addr, stdin=flag)

sim = p.factory.simgr(st)
# tell angr to only consider states in which 'Correct' is printed to stdout
# and immediately reject the ones in which 'Wrong' is printed
sim.explore(find=lambda p: b'Correct' in p.posix.dumps(1), avoid=lambda p: b'Wrong' in p.posix.dumps(1))

if sim.found:
    sol = sim.found[0]
    # print the input that makes the program print 'Correct'
    print(sol.posix.dumps(0))
else:
    raise Exception('No solution :/')
```
Sure enough, soon after starting it, we get the flag.
## Flag
`openECSC{f4nCy_n0p5!_cb6a3551}`
