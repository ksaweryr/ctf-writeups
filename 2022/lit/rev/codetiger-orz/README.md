# codetiger-orz
> codetiger orzzz
>
> Downloads
> [codetiger-orz.zip](https://drive.google.com/uc?export=download&id=12gmnfSKFI2pknJSJbGYTejS5dNcSOOQK)

## Solution
The code's a mess. First things first let's take a look at `derivePassword` function:
```py
def derivePassword():
    kw = ['~#+', 'v~s', 'r~st', '%xvt#', 'st%tr%x\'t']
    userKeyInput = input('Enter the key: ')  # 7-digit integer

    try:
        retrievePasswordKey = list(map(int, list(userKeyInput)))
        # retrievePasswordKey = list(str(10*0) + len(kw[2]) + str(2**0) + len(kw[0]) + '2' + len("orz) + '0')

        ct = kw[retrievePasswordKey[0]] + kw[retrievePasswordKey[1]] + kw[retrievePasswordKey[2]] + \
            kw[retrievePasswordKey[3]] + kw[retrievePasswordKey[4]] + \
            kw[retrievePasswordKey[5]] + kw[retrievePasswordKey[6]]
        # return ROT(ct, s)
        return 'defaultplaceholderkeystringabcde'
    except:
        if max(list(map(int, list(userKeyInput)))) >= len(kw):
            print('Key digits out of range!')
        else:
            print('Invalid key format!')
        exit()
```
We can see that there are 2 comments left: one with what seems the (almost) valid value for `retrievePasswordKey` and the other one with the actual return value.
First, let's fix `retrievePasswordKey`: all we have to do is change `+` operators to commas, change the call to function `list()` to square brackets `[]`, close an apostrophe in `len("orz)` and change the value of `userKeyInput` from a value returned by `input()` to this list. Existing `retrievePasswordKey` assignment will convert all strings in the list to ints for us.
Now for `return ROT(ct, s)`. This function can be found lower in the file:
```py
def ROT(ct, s):
    pt = ''
    for c in ct:
        index = alphabet.find(c)
        original_index = (index + s) % len(alphabet)
        pt = pt + alphabet[original_index]
    return pt
```
It seems fine so let's move it to the top without modifying it.
Since we don't know the value of `s`, we'll have to bruteforce it. We just have to change the function's return value from a call to ROT to a generator yielding values of `ROT(ct, s)` for subsequent `s`.
The fixed version of `derivePassword` looks like this:
```py
def derivePassword():
    kw = ['~#+', 'v~s', 'r~st', '%xvt#', 'st%tr%x\'t']
    userKeyInput = [str(10*0), len(kw[2]), str(2**0), len(kw[0]), '2', len("orz"), '0']

    try:
        retrievePasswordKey = list(map(int, (userKeyInput)))

        ct = kw[retrievePasswordKey[0]] + kw[retrievePasswordKey[1]] + kw[retrievePasswordKey[2]] + \
            kw[retrievePasswordKey[3]] + kw[retrievePasswordKey[4]] + \
            kw[retrievePasswordKey[5]] + kw[retrievePasswordKey[6]]
        return (ROT(ct, s) for s in range(1_000_000))
    except:
        if max(list(map(int, list(userKeyInput)))) >= len(kw):
            print('Key digits out of range!')
        else:
            print('Invalid key format!')
        exit()
```

Under this function there's a loose piece of code that runs when the script is executed:
```py
key_str = derivePassword()
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)

try:
    d = f.decrypt(payload)
except:
    print('The provided key was not correct!\nDECRYPTION FAILED.')
    exit()

solution = d.decode()  # decrypted solution
print(solution)
```
Now that we modified `derivePassword` it no longer returns a single string, rather a generator yielding scripts. Therefore we must change this code to check the strings in a loop, ignoring all exceptions:
```py
key_strs = derivePassword()

for key_str in key_strs:
    key_base64 = base64.b64encode(key_str.encode())
    f = Fernet(key_base64)
    try:
        d = f.decrypt(payload)
        solution = d.decode()  # decrypted solution
        print(solutionDecrypt(solution))
        break
    except:
        ...
```

Last things last, we must move `solutionDecrypt` function to the top of the file so it's available in the above piece of code. Now we can run the modified script and get the flag.

## Flag
`LITCTF{1m_73ry_6ad_a1_r3v_en9in33r1ing}`
