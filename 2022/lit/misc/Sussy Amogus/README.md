# Sussy amogus
> Hello! I am Ray, and as you might know, I have an addiction to Among Us. To make as many people as possible to also experience my obsession, I created this Amogus Virus :D. Here are [two scripts](https://www.dropbox.com/s/kht2cuks0oapp8v/Challenge.zip?dl=0), one to infect your computer, one to disinfect (only works on windows machines).
> **NOTE: THIS IS AN ACTUAL VIRUS SO PROCEED WITH CAUTION**, although the damages are easily reversible.


## Reverse engineering `infect.exe`
Using `$ file infect.exe` we can determine that it's a .NET binary and can therefore be decompiled using an utility such as AvalonialILSpy. In the `Main` method of the `MainApp` class a very long base64-encoded string, which decoded content is stored in `@string` variable, can be found. Upon decoding it turns out to be a PowerShell script.

## Analysing the script
An interesting line can be found in the script:
```powershell
Set-Content "$($env:USERPROFILE)\Desktop\sussy.txt:imposter" -Value "YVGPGS{q3rm_ahgm_1a_l0He_z0hgu}"
```
It seems that a flag encoded in some way is saved in file `sussy.txt` upon running the script. `YVGPGS{q3rm_ahgm_1a_l0He_z0hgu}` turns out to be just ROT13-encoded flag.

## Flag
`LITCTF{d3ez_nutz_1n_y0Ur_m0uth}`
