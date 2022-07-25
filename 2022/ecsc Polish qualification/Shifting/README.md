# Shifting
> This script is generating an encryption key from a plaintext itself. Can you decrypt given ciphertext without knowing the the original plaintext?
> 
> 173ca059bf5d2027251c499b87ca1806b6c6c304153d203b38
> 
> Code:
```php
<?php

function flag_at($i)
{
    global $flag, $l;
    return ord($flag[($l+$i)%$l]);
}

$flag = require('flag.php');
$out = '';
$key = crc32($flag);
$key = ($key)<<32 | $key;

$l = strlen($flag);
for($i=0;$i<$l;$i++)
{
    $shift = flag_at($i-1)%32;
    $keyi = ($key>>$shift)&255;
    $out .= chr(flag_at($i) ^ flag_at($i+1) ^ $keyi);
}

echo bin2hex($out).PHP_EOL;

?>
```

## Analysis
After substituting corresponding values in line 19 of the given code we end up with the following equation:
`out[i] = flag[i] ^ flag[i + 1] ^ ((key >> (flag[i - 1] % 32)) & 255)`
where:
  out[i]  - value of *i*th byte of the output (counting from 0)
  flag[i] - ASCII code of *i*th character of the flag (counting from 0, index -i is the *i*th last character of the flag)
  key     - (crc32(flag) << 32) | crc32(flag)

## Recovering part of the key
Since we know the last character of the flag (*}*), the initial 5 characters (*ecsc{*) and the output, for each *i* between 0 and 3 inclusive the only unknown value in the equation is *key*. Given that bitwise xor is self-inverse, we can transform this equation to the following form:
`((key >> (flag[i - 1] % 32)) & 255) = out[i] ^ flag[i] ^ flag[i + 1]`
from which we can calculate 8 bits of the key using each *i* (some of these bits will overlap between different *i*s and therefore we won't end up with the complete key). The following Python script generates part of the key:
```py
from binascii import unhexlify

# Python's `binascii.unhexlify` is the opposite of PHP's `bin2hex`
out_bytes = unhexlify(b'173ca059bf5d2027251c499b87ca1806b6c6c304153d203b38')
# Subsequent bits of the key from LSB to MSB
key = ['_' for _ in range(32)]

flag = b'ecsc{}'

for i in range(4):
    shift = flag[i - 1] % 32
    # keyi contains a string of length 8 with the binary representation of the current `$keyi`
    keyi = f'{(out_bytes[i] ^ flag[i] ^ flag[i + 1]):08b}'
    for j in range(8):
        # Taking negative index of keyi is the consequence of key holding the bits in reversed order
        key[(shift + j) % 32] = keyi[-j-1]

# reverse the key to output it from MSB to LSB
# '_' means a bit that couldn't be calculated using the given info
print(''.join(reversed(key)))
```

## Bruteforcing the solution
The output of the script is *001__01000001______0010110000010* where an underscore denotes a bit that hasn't been found. There are only 8 such bits (i.e. only 256 possible keys) and therefore we can quickly bruteforce the actual key using another Python script. First, let's transform the equation of *i* output byte, this time in such a way that the only value on the left-hand side is *flag[i+1]*:
`flag[i + 1] = flag[i] ^ out[i] ^ ((key >> (flag[i - 1] % 32)) & 255)`
Now we can run the following script to get all possible flags (i.e. strings generated from any possible key that end with '}'):
```py
from binascii import unhexlify

# all '_' have been changed to '0' to conveniently apply the bitmask
crc_base = 0b00100010000010000000010110000010
out = unhexlify(b'173ca059bf5d2027251c499b87ca1806b6c6c304153d203b38')

for i in range(256):
	flag = b'ecsc{'
	# treating i as a bitmask, OR it with unknown bits of the key
	crc = crc_base | ((i & ((1 << 7) - 1)) << 13) | ((i >> 6) << 27)
	key = (crc << 32) | crc
	for j in range(4, 24):
		shift = flag[j - 1] % 32
		keyi = (key >> shift) & 255
		flag += bytes([flag[j] ^ out[j] ^ keyi])
	if flag[-1] == ord('}'):
		print(flag.decode())
```

## Flag
`ecsc{too_much_plain_text}`
