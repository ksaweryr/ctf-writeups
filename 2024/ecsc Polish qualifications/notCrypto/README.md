# notCrypto

> It's really not a crypto challenge, I swear!
>
> [not-crypto.java](https://hack.cert.pl/files/not-crypto-c3f82ac94591ea6540fc1f5956ca8f6687084da3.java)
>
> `nc notcrypto.ecsc24.hack.cert.pl 5103`


## Analysis
The application will take user's password, replace every character with random UUID from a map (the same character always maps to the same UUID), derive the key from the password & finally use it to encrypt the flag and send it back to the user.

## Vulnerability
The vulnerability lies in the way the map is constructed:
```java
private final Map<C, String> secrets = IntStream.range(Character.MIN_VALUE, Character.MAX_VALUE)
        .mapToObj(C::new)
        .collect(Collectors.toMap(
                Function.identity(),
                c -> UUID.randomUUID().toString()
        ));
```
`IntStream.range` method returns a stream of integers from the lower bound inclusive to the upper bound exclusive - that means that `Character.MAX_VALUE` will not be in the stream, hence it won't be in the map. Now the method `generateRandomPassword`:
```java
String generateRandomPassword(String userInput) {

    return userInput.chars()
            .mapToObj(i -> (char) i)
            .map(C::new)
            .map(secrets::get)
            .collect(Collectors.joining());
}
```
calls `secrets::get` to map the characters in the stream. However, when the character is `Character.MAX_VALUE`, it gets mapped to `null`. Therefore, if we provide a string of 12 `Character.MAX_VALUE`, the "random" password will be the string `null` repeated 12 times.

## Solution
What is `Character.MAX_VALUE`?
```java
jshell> ("" + Character.MAX_VALUE).getBytes()
$1 ==> byte[3] { -17, -65, -65 }
```
A sequence of 3 bytes - `\xef\xbf\xbf`. Now we can get the flag encrypted with the key derived from the password `"null" * 12`:
```python
from pwn import *

io = remote('notcrypto.ecsc24.hack.cert.pl', 5103)

io.sendline(b'\xef\xbf\xbf' * 12)
flag = io.recvline()

print(flag)
```
And finally, modify the Java code slightly to decrypt the flag instead of encrypting it:
```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;


public class Main {
    public static void main(String[] args) throws Exception {
        new Decryptor().decrypt("GF7BaA0U0rzw3mEz1DNKA57Dbp2sP8fNsrm9t33scB5yOUOfpXTqSf75v1UsNt/47f0ueiBTlVA0Sn5OOauzSw==");
    }
}

class Decryptor {

    SecretKey getKeyFromPassword(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), "Why so salty?".getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public void decrypt(String flag) throws Exception {
        byte[] cipherText = Base64.getDecoder().decode(flag);
        String userInput = "null".repeat(12);
        SecretKey key = getKeyFromPassword(userInput);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        try {
            System.out.println(new String(cipher.doFinal(cipherText)));
        } catch(javax.crypto.BadPaddingException ex) {
            System.out.println(":|");
        }
    }
}
```

## Flag
`ecsc24{integer_cache_and_2_byte_chars_#justjavathings}`