# SEALed communication
> Our field agent is missing. We managed to retrieve remotely some files from his personal device and intercepted last message he send to our server. Use them to find out his last known position.
> Note:The flag format is ecsc{/[a-z]/}. You have to add ecsc{} to the found location.
> [sealed.zip](https://hack.cert.pl/files/sealed-2a2195ea20a69b2065c8f5ca5a06c65c1907c4b6.zip)


## Analysing *Client.exe*
*Client.exe* is a .Net binary file, which means we can decompile it using a tool like Avalonial ILSpy. The program reads 2 double values (latitude and longitude), converts them to strings containing 8 digit integers, which are the result of multiplying corresponding values \*1000000, and encodes them using BFV encryption scheme from SEAL library before sending them to the server. Afterwards it receives a response from the server and decrypts it using the same keypair and encryption scheme, which means we can build a decryptor using the code of the executable with minor modifications.

## Extracting encrypted data from *traffic.pcap*
After opening the file with wireshark we see 19 frames, of which 1 (no. 18) is a HTTP frame. Following its stream (ctrl+alt+shift+t) we can see the request sent by the client, which contains encrypted and base64-encoded latitude and longitude saved in JSON format. Let's copy latitude to a file *latitude.txt* and longitude to *longitude.txt*

## Creating decryptor
To create the decryptor project with Microsoft's SEALNet package we'll use dotnet cli tool:
```sh
$ dotnet new console -lang C# -n decoder
$ dotnet add package Microsoft.Research.SEALNet
```
Next we need to write a decoder, mostly by copying code from ILSpy. The final result is available in this repository in [this file](decoder/Program.cs). The only problem is that more recent versions of SEALNet no longer provide IntegerEncoder class used in the program. Fortunately, the working scheme of DecodeInt32 method we need is very simple: it evaluates a polynomial passed as an argument for X = 2, as mentioned in [one of the older versions' source](https://github.com/microsoft/SEAL/blob/3.5.9/dotnet/src/IntegerEncoder.cs#L223):
```cs
/// Decodes a plaintext polynomial and returns the result as BigUInt.
/// Mathematically this amounts to evaluating the input polynomial at X = 2.
```
We can therefore output the polynomials from the C# program and pipe them to this simple Python script to decrypt the coordinates:
```py
for _ in range(2):
    polynomial = input().replace('^', '**').replace('1x', 'x')
    exec(f'x = 2; print(({polynomial}) / 1000000.0)')
```
The project can be built and executed by running the following command in the *decoder* directory:
```sh
$ dotnet build && dotnet run | python3 solve.py
```
The output of this command, the latitude and longitude, is:
```
19.981809
49.232134
```

## Finding the agent's location
Putting `19.981809N 49.232134E` in Google Maps leads us to the middle of a desert in the Middle East. It turns out that the latitude and longitude are swapped and `49.232134N 19.981809E` is the actual location - Kasprowy Wierch.

## Flag
`ecsc{kasprowywierch}`
