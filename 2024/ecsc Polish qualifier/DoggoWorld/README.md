# DoggoWorld

> We have put up the site with photos of the best dogs for those who are knowledgeable of HTTP standard. Can you get these pictures?
>
> [https://doggoworld.ecsc24.hack.cert.pl/](https://doggoworld.ecsc24.hack.cert.pl/)


## Solution
Just do what the website tells you to do `¯\_(ツ)_/¯`.

1. Set `User-Agent` header to `doggobrowser`.
2. Set `X-Forwarder-For` header to `127.0.0.1`.
3. Set `Accept-Language` header to `en-US`.
4. Set `do_you_like_dogs_and_cats` cookie to `yes`. 
5. Change method to `POST` and set form data key `doggo` to `ZmxhZw==` (Base64-encoded word `flag`). Save the output as a file.
6. Read the flag from the file

Final request:
`$ curl -v https://doggoworld.ecsc24.hack.cert.pl -H 'User-Agent: doggobrowser' -H 'X-Forwarded-For: 127.0.0.1' -H 'Accept-Language: en-US' -H 'Cookie: do_you_like_dogs_and_cats=YES; Path=/' -X POST -d 'doggo=ZmxhZw==' --output flag.jpeg`

## Flag
`ecsc24{d0gs_and_c4ts_are_c0ol}`
