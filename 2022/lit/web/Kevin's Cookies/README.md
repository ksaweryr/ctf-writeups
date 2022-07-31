# Kevin's Cookies
> Welcome to Kevin Zhu's [cookie store](http://litctf.live:31778/)! I heard he sells many super delicious cookies :yum:

## Solution
Upon opening the website we're greeted with the following text:
```
I have so many cookies to share with you. Unfortunately, judging from your current cookies, it seems like you do not like any cookies 🍪 :<. Thus I will not bother giving you any
```
Let's take a look at the cookies (e.g. using browser's devtools). A cookie named `likeCookies` set to `false` can be seen. Let's change the value to `true` and reload the website; now the text changes to the following:
```
Oh silly you. What do you mean you like a true cookie? I have 20 cookies numbered from 1 to 20, and all of them are made from super true authentic recipes.
```
I figured that manually going through 20 cookies would be faster then automating it and so I've found that for `likeCookie` set to `17`, the website yields the flag

## Flag
`LITCTF{Bd1mens10n_15_l1k3_sup3r_dup3r_0rzzzz}`
