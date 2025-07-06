# Photo Archiver

> Don't you hate when a very cool page goes down and all of your bookmarked memes go down? That's why I created a service to archive random URLs on the Internet.
>
> [https://photo-archiver.ecsc25.hack.cert.pl/](https://photo-archiver.ecsc25.hack.cert.pl/)

## Solution
The goal is to make the server make a request to its own endpoint from its internal network interface, while also having the hostname be resolved by Google to something else than `127.0.0.1` (so passing `127.0.0.2` or `localhost` doesn't work). The simplest way is to set an A record for a domain you own to make it point to some address in the `127.0.0.0/8` network other than `127.0.0.1` (so `127.0.4.20`, `127.0.6.9`, `127.0.21.37` - pick your favourite one). Then just make the server request a file from that domain (satisfying the other constraints is trivial):

```sh
$ curl -X POST https://photo-archiver.ecsc25.hack.cert.pl/archive -d 'url=http://YOUR_DOMAIN:23612/flag#.png' -H 'Cookie: session=YOUR_SESSION_ID'
```

## Flag
`ecsc25{TOCTOU-is-a-weird-acronym}`
