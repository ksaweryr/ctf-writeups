# Build A Flag Workshop
> ### Category: reversing
>
> Don't you ever want to customize your very own flag? Well now you can with Chompy's brand new Build-A-Flag-Workshop (patent pending)!
>
> ### Attachments
> `build-a-flag-workshop`

## Solution
The application builds a flag by taking a quote selected by the user by setting various parameters (there are 27 options here) and joining it with a user-supplied "signature" (arbitrary string) using a `-` character. The most interesting function is the one at location `0x001019c0`, which checks if a flag is correct:
```c
void verify_flag(void) {
  int iVar1;
  char *generated_flag;
  char *token1;
  char *token2;
  char *token3;
  size_t n;
  long in_FS_OFFSET;
  ulong local_48;
  ulong local_40;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  generated_flag = (char *)generate_flag();
  if (generated_flag == (char *)0x0) {
    if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
      puts("Failed to generate flag.");
      return;
    }
    goto canary_fail;
  }
  token1 = strtok(generated_flag,"-");
  token2 = strtok((char *)0x0,"-");
  token3 = strtok((char *)0x0,"-");
  if (token1 == (char *)0x0) {
    if (token2 == (char *)0x0) goto null_token2_check_token3;
    puts(token2);
    if (token3 == (char *)0x0) goto wrong_flag;
print_token3_wrong_flag:
    puts(token3);
wrong_flag:
    token1 = "isn\'t Chompy\'s favorite, but it\'s yours and that\'s what matters.";
  }
  else {
    puts(token1);
    if (token2 == (char *)0x0) {
null_token2_check_token3:
      if (token3 != (char *)0x0) goto print_token3_wrong_flag;
      goto wrong_flag;
    }
    puts(token2);
    if (token3 != (char *)0x0) {
      puts(token3);
    }
    token1 = strstr(token1,"decide");
    if (token1 == (char *)0x0) goto wrong_flag;
    n = strlen(token2);
    MD5((uchar *)token2,n,(uchar *)&local_48);
    if (((local_48 ^ BYTE_ARRAY_00104010._0_8_ | local_40 ^ BYTE_ARRAY_00104010._8_8_) != 0) ||
       (token3 == (char *)0x0)) goto wrong_flag;
    iVar1 = strcmp(token3,"chompy");
    token1 = "is Chompy\'s favorite flag! Great work.";
    if (iVar1 != 0) goto wrong_flag;
  }
  __printf_chk(2,"sun{%s} %s\n",generated_flag,token1);
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    free(generated_flag);
    return;
  }
canary_fail:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Following it step-by-step:
```c
  generated_flag = (char *)generate_flag();
  if (generated_flag == (char *)0x0) {
    if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
      puts("Failed to generate flag.");
      return;
    }
    goto canary_fail;
  }
```
Flag is generated by concatenating a quote, `-` and a signature. If it fails, the function returns early.

```c
  token1 = strtok(generated_flag,"-");
  token2 = strtok((char *)0x0,"-");
  token3 = strtok((char *)0x0,"-");
```
Flag is split in 3 parts on `-` - as no quote contains a `-` and appending the signature only adds 1 `-`, the signature should contain one additional `-`.

I'll ignore the paths when either of `token1`, `token2` or `token3` is a null pointer, as they all lead to failure.

```c
    token1 = strstr(token1,"decide");
    if (token1 == (char *)0x0) goto wrong_flag;
```
The first token (the quote) must contain the substring `decide` - there's only one such quote - `all_we_have_to_decide_is_what_to_do_with_the_time_given_to_us`.

```c
    n = strlen(token2);
    MD5((uchar *)token2,n,(uchar *)&local_48);
    if (((local_48 ^ BYTE_ARRAY_00104010._0_8_ | local_40 ^ BYTE_ARRAY_00104010._8_8_) != 0) ||
       (token3 == (char *)0x0)) goto wrong_flag;
```
The second token must have MD5 signature stored in an array at memory location `0x00104010` - that is `ab17850978e36aaf6a2b8808f1ded971`. Googling this hash shows that the hashed string should be `gandalf`.

```c
    iVar1 = strcmp(token3,"chompy");
    token1 = "is Chompy\'s favorite flag! Great work.";
    if (iVar1 != 0) goto wrong_flag;
  }
  __printf_chk(2,"sun{%s} %s\n",generated_flag,token1);
```
The third token must be the string `chompy`. This is the last condition that has to be met for the flag to be accepted.

## Flag
`sun{all_we_have_to_decide_is_what_to_do_with_the_time_given_to_us-gandalf-chompy}`