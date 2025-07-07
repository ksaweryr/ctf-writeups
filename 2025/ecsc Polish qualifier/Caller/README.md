# Caller

> Naming things is hard.
>
> `nc caller.ecsc25.hack.cert.pl 5212`
>
> **caller.py**
> ```py
> import os
> import uuid
> 
> 
> def main():
>     FLAG = open("flag.txt", 'r').read().encode()
>     arg = input("> ")
>     blacklist = ['{', '}', ';', '\n']
>     if len(arg) > 10 or any([c in arg for c in blacklist]):
>         print("Bad input!")
>         return
>     template = f"""
> #include <stdio.h>
> #include <string.h>
> 
> char* f(){{
>     char* flag = "{FLAG}";
>     printf("%s",flag);
>     return flag;
> }}
> 
> void g(char* {arg}){{}}
> 
> int main(){{
>     g(NULL);
>     return 0;
> }}
> """
>     name = "test"
>     source = f"/tmp/{name}.c"
>     outfile = f"/tmp/{name}"
>     open(source, 'w').write(template)
>     os.system(f"export PATH=$PATH:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin && gcc {source} -o {outfile}")
>     os.system(f"{outfile}")
>     os.remove(source)
>     os.remove(outfile)
> 
> 
> main()
> ```

## Solution
C allows using expressions as array sizes in function arguments. Those expressions are then evaluated whenever the function is called. As such, if `arg` is `[(int)f()]` (exactly 10 characters), the signature of `g` becomes `void g(char*[(int)f()])` and the flag will be printed when `g(NULL)` is called.

## Flag
`ecsc25{thats_some_weird_variable_name}`
