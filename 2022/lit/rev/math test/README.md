# math test
> this math test is hard
>
> Downloads
> [math](https://drive.google.com/uc?export=download&id=1jGE3v40Xk3-Fq2GsnGvwzU8prZEoL3Iz)

## Analysis
Let's decompile the main function (e.g. using Ghidra):
```c
void main(void)

{
  int local_c;
  
  puts("Welcome to the math test. If you get a perfect score, I will print the flag!");
  puts("All questions will have non-negative integer answers.\n");
  for (local_c = 0; local_c < NUM_Q; local_c = local_c + 1) {
    printf("Question #%d: ",(ulong)(local_c + 1));
    puts(*(char **)(questions + (long)local_c * 8));
    __isoc99_scanf(&DAT_00102286);
  }
  grade_test();
  return;
}
```
The function reads an answer for each question from stdin and then calls `grade_test`. Unfortunately, Ghidra decompiler failed at displaying the 2nd argument to `scanf`, so we'll have to look at disassembly to determine where the answers are being read to:

```
001013f0 8b 45 fc        MOV        EAX,dword ptr [RBP + local_c]
001013f3 48 98           CDQE
001013f5 48 8d 14        LEA        RDX,[RAX*0x8]
         c5 00 00 
         00 00
001013fd 48 8d 05        LEA        RAX,[submitted]                                  = ??
         7c 2f 00 00
00101404 48 01 d0        ADD        RAX,RDX
00101407 48 89 c6        MOV        RSI,RAX
0010140a 48 8d 05        LEA        RAX,[DAT_00102286]                               = 25h    %
         75 0e 00 00
00101411 48 89 c7        MOV        RDI=>DAT_00102286,RAX                            = 25h    %
00101414 b8 00 00        MOV        EAX,0x0
         00 00
00101419 e8 52 fc        CALL       <EXTERNAL>::__isoc99_scanf                       undefined __isoc99_scanf()
         ff ff
```
We can see that initially, value of variable `local_c` (the function iterator) is moved to `eax`. This value multiplied by 8 is then stored in `rdx`. Eventually, the address of a global variable `submitted` incremented by `rdx` is stored into `rax`. This means that `submitted` is an array of 8 bytes long elements (numbers) that stores the answers submitted by user.

Function `grade_test` isn't complicated as well:
```c
void grade_test(void)

{
  int local_10;
  uint local_c;
  
  local_c = 0;
  for (local_10 = 0; local_10 < NUM_Q; local_10 = local_10 + 1) {
    if (*(long *)(submitted + (long)local_10 * 8) == *(long *)(answers + (long)local_10 * 8)) {
      local_c = local_c + 1;
    }
  }
  printf("You got %d out of 10 right!\n",(ulong)local_c);
  if (local_c == 10) {
    puts("Wow! That\'s a perfect score!");
    puts("Here\'s the flag:");
    generate_flag();
  }
  else {
    puts("If you get a 10 out of 10, I will give you the flag!");
  }
  return;
}
```
It checks whether all 10 elements of `submitted` are equal to corresponding elements of `answers` and if that's the case, calls the function `generate_flag`. Given that `answers` is an array of static values that isn't modified anywhere in the program, we can just read it to get all the answers and never bother to decompile the `generate_flag` function.

## Reading the values in `answers`
Reading these values can be most easily done using gdb. First, we have to launch gdb:
```sh
$ gdb math
```
Then, we must find the address of `answers` variable:
```gdb
(gdb) info variables
[...]
0x0000000000004080  answers
[...]
```
Knowing this address, all that's left is to read the answers:
```gdb
(gdb) i/10gd 0x4080
0x4080 <answers>:       2       4
0x4090 <answers+16>:    240     3
0x40a0 <answers+32>:    165580141       10
0x40b0 <answers+48>:    5838215 111222345
0x40c0 <answers+64>:    543222111       9
```
The command `i/10gd 0x4080` means: "inspect memory (i/) and display 10 elements as integers (d) each 8 bytes in size (g) from address 0x4080".
Now we can run the executable and pass subsequent answers to ultimately get the flag.

## Flag
`LITCTF{y0u_must_b3_gr8_@_m4th_i_th0ught_th4t_t3st_was_imp0ss1bl3!}`
