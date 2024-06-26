#requires -version 3

Function Invoke-PowerExec {
<#
.SYNOPSIS
    Invoke PowerShell commands on remote computers.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-PowerExec runs PowerShell script block on remote computers through various execution methods.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ComputerList
    Specifies the target hosts, such as specific addresses or network ranges (CIDR).

.PARAMETER ComputerDomain
    Specifies an Active Directory domain for enumerating target computers.

.PARAMETER ComputerFilter
    Specifies a specific role for enumerating target controllers, defaults to 'All'.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used, defaults to Negotiate.

.PARAMETER Method
    Specifies the execution method to use, defaults to WinRM.

.PARAMETER Protocol
    Specifies the transport protocol to use, defaults to Wsman.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

.PARAMETER Threads
    Specifies the number of threads to use, defaults to 10.
    This is only relevant for WinRM execution method, multi-threadeding is not supported for others.

.EXAMPLE
    PS C:\> Invoke-PowerExec -ScriptBlock {Write-Output "$Env:COMPUTERNAME ($Env:USERDOMAIN\$Env:USERNAME)"} -ComputerList $(gc hosts.txt) -Method CimProcess

.EXAMPLE
    PS C:\> New-PowerLoader -FilePath .\script.ps1 | Invoke-PowerExec -ComputerDomain ADATUM.CORP -Credential ADATUM\Administrator -Method WinRM -Threads 10
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerList,

        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerDomain = $Env:LOGONSERVER,

        [ValidateSet('All', 'DomainControllers', 'Servers', 'Workstations')]
        [String]
        $ComputerFilter = 'All',

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Negotiate',

        [ValidateSet('CimProcess', 'CimTask', 'CimService', 'CimSubscription', 'SmbService', 'SmbTask', 'SmbDcom', 'WinRM')]
        [String]
        $Method = 'WinRM',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Wsman',

        [Int]
        $Timeout = 3,

        [ValidateNotNullOrEmpty()]
        [Int]
        $Threads = 10
    )

    if ($PSBoundParameters.ContainsKey('Protocol') -and $Method -notmatch 'Cim.*') {
        Write-Warning "Specified protocol will be ignored with the execution method $Method."
    }
    if ($PSBoundParameters.ContainsKey('Authentication') -and $Method -match 'Smb.*') {
        Write-Warning "Specified authentication method will be ignored with the execution method $Method."
    }

    $hostList = New-Object Collections.ArrayList

    foreach ($computer in $ComputerList) {
        if ($computer.contains("/")) {
            $hostList.AddRange($(New-IPv4RangeFromCIDR -CIDR $computer))
        }
        else {
            $hostList.Add($computer) | Out-Null
        }
    }

    if ($PSBoundParameters['ComputerDomain'] -or $PSBoundParameters['ComputerFilter']) {
        switch ($ComputerFilter) {
            'All' {
                $filter = '(&(objectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))'
            }
            'DomainControllers' {
                $filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
            }
            'Servers' {
                $filter = '(&(objectCategory=computer)(operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=8192))'
            }
            'Workstations' {
                $filter = '(&(objectCategory=computer)(!operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2))'
            }
        }
        Get-LdapObject -Server $ComputerDomain -SSL:$SSL -Filter $filter -Properties 'dnshostname' -Credential $Credential | ForEach-Object {
            if ($computer = $_.dnshostname) {
                $hostList.Add($computer.ToString()) | Out-Null
            }
        }
    }

    $index = 0
    $buffer = $Threads
    do {
        if (($index + $buffer) -lt $hostList.Count) {
            $buffHostList = $hostList[$index..($index + $buffer-1)]
        }
        else {
            $diff = ($hostList.Count - $index)
            $buffHostList = $hostList[$index..($index + $diff-1)]
        }
        New-PowerExec -ScriptBlock $ScriptBlock -ComputerList $buffHostList -Credential $Credential -Authentication $Authentication -Method $Method -Protocol $Protocol -Timeout $Timeout -Threads $Threads
        $index = $index + $buffer
    }
    while ($index -lt $hostList.Count)
}

# Adapted from Find-Fruit by @rvrsh3ll
Function Local:New-IPv4RangeFromCIDR {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CIDR
    )

    $hostList = New-Object Collections.ArrayList
    $netPart = $CIDR.split("/")[0]
    [uint32]$maskPart = $CIDR.split("/")[1]

    $address = [Net.IPAddress]::Parse($netPart)
    if ($maskPart -ge $address.GetAddressBytes().Length * 8) {
        throw "Bad host mask"
    }

    $numhosts = [Math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))

    $startaddress = $address.GetAddressBytes()
    [array]::Reverse($startaddress)

    $startaddress = [BitConverter]::ToUInt32($startaddress, 0)
    [uint32]$startMask = ([Math]::Pow(2, $maskPart) - 1) * ([Math]::Pow(2, (32 - $maskPart)))
    $startAddress = $startAddress -band $startMask
    # In powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
    $startAddress = [BitConverter]::GetBytes($startaddress)[0..3]
    [array]::Reverse($startaddress)
    $address = [Net.IPAddress][byte[]]$startAddress

    for ($i = 0; $i -lt $numhosts - 2; $i++) {
        $nextAddress = $address.GetAddressBytes()
        [array]::Reverse($nextAddress)
        $nextAddress = [BitConverter]::ToUInt32($nextAddress, 0)
        $nextAddress++
        $nextAddress = [BitConverter]::GetBytes($nextAddress)[0..3]
        [array]::Reverse($nextAddress)
        $address = [Net.IPAddress][byte[]]$nextAddress
        $hostList.Add($address.IPAddressToString) | Out-Null
    }
    return $hostList
}

Function Local:Get-LdapRootDSE {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL
    )

    $searchString = "LDAP://$Server/RootDSE"
    if ($SSL) {
        # Note that the server certificate has to be trusted
        $authType = [DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    }
    else {
        $authType = [DirectoryServices.AuthenticationTypes]::Anonymous
    }
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null, $authType)
    return $rootDSE
}

Function Local:Get-LdapObject {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        if ((-not $SearchBase) -or $SSL) {
            # Get default naming context
            try {
                $rootDSE = Get-LdapRootDSE -Server $Server
                $defaultNC = $rootDSE.defaultNamingContext[0]
            }
            catch {
                Write-Error "Domain controller unreachable"
                continue
            }
            if (-not $SearchBase) {
                $SearchBase = $defaultNC
            }
        }
    }

    Process {
        try {
            if ($SSL) {
                $results = @()
                $domain = $defaultNC -replace 'DC=' -replace ',','.'
                [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
                $searcher = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
                $searcher.SessionOptions.SecureSocketLayer = $true
                $searcher.SessionOptions.VerifyServerCertificate = {$true}
                $searcher.SessionOptions.DomainName = $domain
                $searcher.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
                if ($Credential.UserName) {
                    $searcher.Bind($Credential)
                }
                else {
                    $searcher.Bind()
                }
                if ($Properties -ne '*') {
                    $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope, $Properties)
                }
                else {
                    $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope)
                }
                $pageRequestControl = New-Object -TypeName System.DirectoryServices.Protocols.PageResultRequestControl -ArgumentList $PageSize
                $request.Controls.Add($pageRequestControl) | Out-Null
                $response = $searcher.SendRequest($request)
                while ($true) {
                    $response = $searcher.SendRequest($request)
                    if ($response.ResultCode -eq 'Success') {
                        foreach ($entry in $response.Entries) {
                            $results += $entry
                        }
                    }
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
                    if ($pageResponseControl.Cookie.Length -eq 0) {
                        break
                    }
                    $pageRequestControl.Cookie = $pageResponseControl.Cookie
                }
                
            }
            else {
                $adsPath = "LDAP://$Server/$SearchBase"
                if ($Credential.UserName) {
                    $domainObject = New-Object DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
                }
                else {
                    $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$adsPath)
                }
                $searcher.SearchScope = $SearchScope
                $searcher.PageSize = $PageSize
                $searcher.CacheResults = $false
                $searcher.filter = $Filter
                $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
                $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
                $results = $searcher.FindAll()
            }
        }
        catch {
            Write-Error $_
            continue
        }

        $results | Where-Object {$_} | ForEach-Object {
            if (Get-Member -InputObject $_ -name "Attributes" -Membertype Properties) {
                # Convert DirectoryAttribute object (LDAPS results)
                $p = @{}
                foreach ($a in $_.Attributes.Keys | Sort-Object) {
                    if (($a -eq 'objectsid') -or ($a -eq 'sidhistory') -or ($a -eq 'objectguid') -or ($a -eq 'securityidentifier') -or ($a -eq 'msds-allowedtoactonbehalfofotheridentity') -or ($a -eq 'usercertificate') -or ($a -eq 'ntsecuritydescriptor') -or ($a -eq 'logonhours')) {
                        $p[$a] = $_.Attributes[$a]
                    }
                    elseif ($a -eq 'dnsrecord') {
                        $p[$a] = ($_.Attributes[$a].GetValues([byte[]]))[0]
                    }
                    elseif (($a -eq 'whencreated') -or ($a -eq 'whenchanged')) {
                        $value = ($_.Attributes[$a].GetValues([byte[]]))[0]
                        $format = "yyyyMMddHHmmss.fZ"
                        $p[$a] = [datetime]::ParseExact([Text.Encoding]::UTF8.GetString($value), $format, [cultureinfo]::InvariantCulture)
                    }
                    else {
                        $values = @()
                        foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                            $values += [Text.Encoding]::UTF8.GetString($v)
                        }
                        $p[$a] = $values
                    }
                }
            }
            else {
                $p = $_.Properties
            }
            $objectProperties = @{}
            $p.Keys | ForEach-Object {
                if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
    }

    End {
        if ($results -and -not $SSL) {
            $results.dispose()
        }
        if ($searcher) {
            $searcher.dispose()
        }
    }
}

Function Local:New-PowerExec {
    Param (
        [Parameter(Mandatory = $True)]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerList,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        $Authentication = 'Default',

        [ValidateSet('CimProcess', 'CimTask', 'CimService', 'CimSubscription', 'SmbService', 'SmbTask', 'SmbDcom', 'WinRM')]
        [String]
        $Method = 'CimProcess',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [Int]
        $Timeout = 3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 10
    )

    $output = $null
    switch ($Method) {
        'WinRM' {
            $psOption = New-PSSessionOption -NoMachineProfile -OperationTimeout $($Timeout*1000)
            if ($Credential.Username) {
                $psSessions = New-PSSession -ComputerName $ComputerList -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction SilentlyContinue
            }
            else {
                $psSessions = New-PSSession -ComputerName $ComputerList -Authentication $Authentication -SessionOption $psOption -ErrorAction SilentlyContinue
            }
            if ($psSessions) {
                $job = Invoke-Command -Session $psSessions -ScriptBlock $ScriptBlock -AsJob -ThrottleLimit $Threads
                $job | Wait-Job -Timeout 900 | Out-Null # Each set of jobs has a 10 minute timeout to prevent endless stalling
                if ($job.State -contains "Running") {
                    Write-Warning "Job timeout exceeded, continuing..."
                }
                $job.ChildJobs | Foreach-Object {
                    $childJob = $_
                    Write-Host "`n[$($childJob.Location)] Execution finished."
                    Receive-Job -Job $childJob
                }
                Remove-Job $job
                Remove-PSSession $psSessions
            }
        }
        'CimProcess' {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            else {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            if ($cimSessions) {
                $parameters = @{
                    ScriptBlock = $ScriptBlock
                    Verbose = $VerbosePreference
                }
                Invoke-CimProcess @parameters -CimSession $cimSessions
                Remove-CimSession -CimSession $cimSessions
            }
        }
        'CimTask' {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            else {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            if ($cimSessions) {
                $parameters = @{
                    ScriptBlock = $ScriptBlock
                    Verbose = $VerbosePreference
                }
                Invoke-CimTask @parameters -CimSession $cimSessions
                Remove-CimSession -CimSession $cimSessions
            }
        }
        'CimService' {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            else {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            if ($cimSessions) {
                $parameters = @{
                    ScriptBlock = $ScriptBlock
                    Verbose = $VerbosePreference
                }
                Invoke-CimService @parameters -CimSession $cimSessions
                Remove-CimSession -CimSession $cimSessions
            }
        }
        'CimSubscription' {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            else {
                $cimSessions = New-CimSession -ComputerName $ComputerList -Authentication $Authentication -SessionOption $cimOption -OperationTimeoutSec $Timeout -Verbose:$false -ErrorAction SilentlyContinue
            }
            if ($cimSessions) {
                $parameters = @{
                    ScriptBlock = $ScriptBlock
                    Verbose = $VerbosePreference
                }
                Invoke-CimSubscription @parameters -CimSession $cimSessions
                Remove-CimSession -CimSession $cimSessions
            }
        }
        'SmbService' {
            $parameters = @{
                ScriptBlock = $ScriptBlock
                Credential = $Credential
                Verbose = $VerbosePreference
            }
            foreach ($computer in $ComputerList) {
                try {
                    Invoke-SmbService @parameters -ComputerName $computer
                }
                catch {
                    Write-Verbose "[$computer] Execution failed. $_"
                    continue
                }
            }
        }
        'SmbTask' {
            $parameters = @{
                ScriptBlock = $ScriptBlock
                Credential = $Credential
                Verbose = $VerbosePreference
            }
            foreach ($computer in $ComputerList) {
                try {
                    Invoke-SmbTask @parameters -ComputerName $computer
                }
                catch {
                    Write-Verbose "[$computer] Execution failed. $_"
                    continue
                }
            }
        }
        'SmbDcom' {
            $parameters = @{
                ScriptBlock = $ScriptBlock
                Credential = $Credential
                Verbose = $VerbosePreference
            }
            foreach ($computer in $ComputerList) {
                try {
                    Invoke-SmbDcom @parameters -ComputerName $computer
                }
                catch {
                    Write-Verbose "[$computer] Execution failed. $_"
                    continue
                }
            }
        }
    }
}

Function Local:Invoke-CimDelivery {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock
    )
    Begin {
        $computerName = $CimSession.ComputerName
        Write-Verbose "[$computerName] Getting CIM object..."
        $cimObject = Get-CimInstance -Class Win32_OSRecoveryConfiguration -CimSession $CimSession -ErrorAction Stop -Verbose:$false
        $obj = New-Object -TypeName psobject
        $obj | Add-Member -MemberType NoteProperty -Name 'OriginalValue' -Value $cimObject.DebugFilePath
    }
    Process {
        Write-Verbose "[$computerName] Encoding payload into CIM property DebugFilePath..."
        $script = ''
        $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
        $script += '$output = [Management.Automation.PSSerializer]::Serialize((& $scriptBlock *>&1))' + [Environment]::NewLine
        $script += '$encOutput = [Int[]][Char[]]$output -Join '',''' + [Environment]::NewLine
        $script += '$x = Get-WmiObject -Class Win32_OSRecoveryConfiguration' + [Environment]::NewLine
        $script += '$x.DebugFilePath = $encOutput' + [Environment]::NewLine
        $script += '$x.Put()'
        $encScript = [Int[]][Char[]]$script -Join ','
        $cimObject.DebugFilePath = $encScript
        $cimObject | Set-CimInstance -Verbose:$false
        $obj | Add-Member -MemberType NoteProperty -Name 'TamperedValue' -Value $cimObject.DebugFilePath
    }
    End {
        $loader = ''
        $loader += '$x = Get-WmiObject -Class Win32_OSRecoveryConfiguration; '
        $loader += '$y = [char[]][int[]]$x.DebugFilePath.Split('','') -Join ''''; '
        $loader += '$z = [ScriptBlock]::Create($y); '
        $loader += '& $z'
        $obj | Add-Member -MemberType NoteProperty -Name 'Loader' -Value $loader
        return $obj
    }
}

Function Local:Invoke-CimRecovery {
    Param (
        [Parameter(Mandatory = $True)]
        [CimSession]
        $CimSession,

        [ValidateNotNullOrEmpty()]
        [String]
        $DefaultValue = '%SystemRoot%\MEMORY.DMP'
    )
    Begin {
        $computerName = $CimSession.ComputerName
        Write-Verbose "[$computerName] Getting CIM object..."
        $cimObject = Get-CimInstance -ClassName Win32_OSRecoveryConfiguration -CimSession $cimSession -Verbose:$false -ErrorAction Stop
    }
    Process {
        try {
            Write-Verbose "[$computerName] Decoding data from property DebugFilePath..."
            $serializedOutput = [char[]][int[]]$cimObject.DebugFilePath.Split(',') -Join ''
            $output = ([Management.Automation.PSSerializer]::Deserialize($serializedOutput))
        }
        catch [Management.Automation.RuntimeException] {
            Write-Warning "[$computerName] Failed to decode data."
        }
        finally {
            Write-Verbose "[$computerName] Restoring original value: $DefaultValue"
            $cimObject.DebugFilePath = $DefaultValue
            $cimObject | Set-CimInstance -Verbose:$false
        }
    }
    End {
        return $output
    }
}

Function Local:Invoke-CimProcess {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [CimSession[]]
        $CimSession
    )
    foreach ($session in $cimSession) {
        $computerName = $session.ComputerName
        try {
            $delivery = Invoke-CimDelivery -CimSession $session -ScriptBlock $ScriptBlock
            $command = 'powershell -NoP -NonI -C "' + $delivery.Loader + '"'
        }
        catch {
            Write-Verbose "[$computerName] Delivery failed. $_"
            continue
        }
        try {
            Write-Verbose "[$computerName] Running command..."
            Write-Debug "$command"
            $process = Invoke-CimMethod -ClassName Win32_Process -Name Create -Arguments @{CommandLine=$command} -CimSession $session -Verbose:$false
            while ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $session -Verbose:$false).ProcessID) {
                Start-Sleep -Seconds 1
            }
        }
        catch {
            Write-Warning "[$computerName] Execution failed. $_"
        }
        finally {
            Write-Host "`n[$computerName] Execution finished."
            Invoke-CimRecovery -CimSession $session -DefaultValue $delivery.OriginalValue
        }
    }
}

Function Local:Invoke-CimTask {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [CimSession[]]
        $CimSession,

        [ValidateNotNullOrEmpty()]
        [String]
        $TaskName = [guid]::NewGuid().Guid
    )
    foreach ($session in $cimSession) {
        $computerName = $session.ComputerName
        try {
            $delivery = Invoke-CimDelivery -CimSession $session -ScriptBlock $ScriptBlock
            $argument = '-NoP -NonI -C "' + $delivery.Loader + '"'
        }
        catch {
            Write-Verbose "[$computerName] Delivery failed. $_"
            continue
        }
        try {
            $taskParameters = @{
                TaskName = $TaskName
                Action = New-ScheduledTaskAction -WorkingDirectory "%windir%\System32\WindowsPowerShell\v1.0\" -Execute "powershell" -Argument $argument
                Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
                Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest -CimSession $session
            }
            Write-Verbose "[$computerName] Registering scheduled task $TaskName..."
            $scheduledTask = Register-ScheduledTask @taskParameters -CimSession $session -ErrorAction Stop
            Write-Verbose "[$computerName] Running command..."
            Write-Debug "powershell $argument"
            $cimJob = $scheduledTask | Start-ScheduledTask -AsJob -ErrorAction Stop
            $cimJob | Wait-Job | Remove-Job -Force -Confirm:$False
            while (($scheduledTaskInfo = $scheduledTask | Get-ScheduledTaskInfo).LastTaskResult -eq 267009) {
                Start-Sleep -Seconds 1
            }
            if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
                Write-Warning "[$ComputerName] Failed to execute scheduled task."
            }
            Write-Verbose "[$computerName] Unregistering scheduled task $TaskName..."
            if ($Protocol -eq 'Wsman') {
                $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$False | Out-Null
            }
            else {
                $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask | Out-Null
            }
        }
        catch {
            Write-Warning "[$computerName] Execution failed. $_"
        }
        finally {
            Write-Host "`n[$computerName] Execution finished."
            Invoke-CimRecovery -CimSession $session -DefaultValue $delivery.OriginalValue
        }
    }
}

Function Local:Invoke-CimService {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [CimSession[]]
        $CimSession,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServiceName = [guid]::NewGuid().Guid
    )
    foreach ($session in $cimSession) {
        $computerName = $session.ComputerName
        try {
            $delivery = Invoke-CimDelivery -CimSession $session -ScriptBlock $ScriptBlock
            $command = '%COMSPEC% /c powershell -NoP -NonI -C "' + $delivery.Loader + '"'
        }
        catch {
            Write-Verbose "[$computerName] Delivery failed. $_"
            continue
        }
        try {
            Write-Verbose "[$computerName] Creating service $ServiceName..."
            $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                StartMode = 'Manual'
                StartName = 'LocalSystem'
                ServiceType = ([Byte] 16)
                ErrorControl = ([Byte] 1)
                Name = $ServiceName
                DisplayName = $ServiceName
                DesktopInteract  = $false
                PathName = $command
            } -CimSession $session -Verbose:$false

            if ($result.ReturnValue -eq 0) {
                Write-Verbose "[$computerName] Running command..."
                Write-Debug "$command"
                $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -CimSession $session -Verbose:$false
                Invoke-CimMethod -MethodName StartService -InputObject $service -Verbose:$false | Out-Null
                do {
                    Start-Sleep -Seconds 1
                    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -CimSession $session -Verbose:$false
                }
                until ($service.ExitCode -ne 1077 -or $service.State -ne 'Stopped')

                Write-Verbose "[$computerName] Removing service $ServiceName..."
                Invoke-CimMethod -MethodName Delete -InputObject $service -Verbose:$false | Out-Null
            }
            else {
                Write-Warning "[$computerName] Service creation failed ($($result.ReturnValue))."
            }
        }
        catch {
            Write-Warning "[$computerName] Execution failed. $_"
        }
        finally {
            Write-Host "`n[$computerName] Execution finished."
            Invoke-CimRecovery -CimSession $session -DefaultValue $delivery.OriginalValue
        }
    }
}

Function Local:Invoke-CimSubscription {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [CimSession[]]
        $CimSession,

        [ValidateNotNullOrEmpty()]
        [String]
        $FilterName = [guid]::NewGuid().Guid,

        [ValidateNotNullOrEmpty()]
        [String]
        $ConsumerName = [guid]::NewGuid().Guid,

        [Int]
        $Sleep = 10
    )
    foreach ($session in $cimSession) {
        $computerName = $session.ComputerName
        try {
            $delivery = Invoke-CimDelivery -CimSession $session -ScriptBlock $ScriptBlock
            $command = 'powershell.exe -NoP -NonI -C "' + $delivery.Loader + '"'
        }
        catch {
            Write-Verbose "[$computerName] Delivery failed. $_"
            continue
        }
        try {
            Write-Verbose "[$computerName] Creating event filter $FilterName..."
            $filterParameters = @{
                EventNamespace = 'root/CIMV2'
                Name = $FilterName
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND TargetInstance.EventCode='4625'"
                QueryLanguage = 'WQL'
            }
            $filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Arguments $filterParameters -CimSession $session -ErrorAction Stop -Verbose:$false

            Write-Verbose "[$computerName] Creating event consumer $ConsumerName..."
            $consumerParameters = @{
                Name = $ConsumerName
                CommandLineTemplate = $command
            }
            $consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Arguments $consumerParameters -CimSession $session -ErrorAction Stop -Verbose:$false

            Write-Verbose "[$computerName] Creating event to consumer binding..."
            $bindingParameters = @{
                Filter = [Ref]$filter
                Consumer = [Ref]$consumer
            }
            $binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Arguments $bindingParameters -CimSession $session -ErrorAction Stop -Verbose:$false

            Write-Verbose "[$computerName] Running command..."
            Write-Debug "$command"
            try {
                $cimOption = New-CimSessionOption -Protocol Dcom
                New-CimSession -ComputerName $ComputerName -Credential (New-Object Management.Automation.PSCredential("Guest",(New-Object Security.SecureString))) -Authentication Default -SessionOption $cimOption -OperationTimeoutSec 10 -ErrorAction SilentlyContinue -Verbose:$false
            }
            catch {
                Write-Warning "[$computerName] Trigger failed."
            }

            Write-Verbose "[$computerName] Waiting for $Sleep seconds..."
            Start-Sleep -Seconds $Sleep

            Write-Verbose "[$computerName] Removing event subscription..."
            $binding | Remove-CimInstance -Verbose:$false
            $consumer | Remove-CimInstance -Verbose:$false
            $filter | Remove-CimInstance -Verbose:$false
        }
        catch {
            Write-Warning "[$computerName] Execution failed. $_"
        }
        finally {
            Write-Host "`n[$computerName] Execution finished."
            Invoke-CimRecovery -CimSession $session -DefaultValue $delivery.OriginalValue
        }
    }
}

function Local:Invoke-SmbService {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String]
        $PipeName = [guid]::NewGuid().Guid,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServiceName = [guid]::NewGuid().Guid
    )
    Begin {
        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }

        $CloseServiceHandleAddr = Get-ProcAddress Advapi32.dll CloseServiceHandle
        $CloseServiceHandleDelegate = Get-DelegateType @([IntPtr]) ([Int])
        $CloseServiceHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseServiceHandleAddr, $CloseServiceHandleDelegate)    

        $OpenSCManagerAAddr = Get-ProcAddress Advapi32.dll OpenSCManagerA
        $OpenSCManagerADelegate = Get-DelegateType @([String], [String], [Int]) ([IntPtr])
        $OpenSCManagerA = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAAddr, $OpenSCManagerADelegate)

        $OpenServiceAAddr = Get-ProcAddress Advapi32.dll OpenServiceA
        $OpenServiceADelegate = Get-DelegateType @([IntPtr], [String], [Int]) ([IntPtr])
        $OpenServiceA = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenServiceAAddr, $OpenServiceADelegate)
      
        $CreateServiceAAddr = Get-ProcAddress Advapi32.dll CreateServiceA
        $CreateServiceADelegate = Get-DelegateType @([IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
        $CreateServiceA = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateServiceAAddr, $CreateServiceADelegate)

        $StartServiceAAddr = Get-ProcAddress Advapi32.dll StartServiceA
        $StartServiceADelegate = Get-DelegateType @([IntPtr], [Int], [Int]) ([IntPtr])
        $StartServiceA = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StartServiceAAddr, $StartServiceADelegate)

        $DeleteServiceAddr = Get-ProcAddress Advapi32.dll DeleteService
        $DeleteServiceDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
        $DeleteService = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeleteServiceAddr, $DeleteServiceDelegate)

        $GetLastErrorAddr = Get-ProcAddress Kernel32.dll GetLastError
        $GetLastErrorDelegate = Get-DelegateType @() ([Int])
        $GetLastError = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)

        $loader = ''
        $loader += '$s = new-object IO.Pipes.NamedPipeServerStream(''' + $PipeName + ''', 3); '
        $loader += '$s.WaitForConnection(); '
        $loader += '$r = new-object IO.StreamReader $s; '
        $loader += '$x = ''''; '
        $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
        $loader += '$z = [ScriptBlock]::Create($x); '
        $loader += '& $z'
        $command = '%COMSPEC% /c start %COMSPEC% /c powershell -NoP -NonI -C "' + $loader + '"'

        $script = ''
        $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
        $script += '$output = [Management.Automation.PSSerializer]::Serialize((& $scriptBlock *>&1))' + [Environment]::NewLine
        $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
        $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
        $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
        $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
        $script += '$writer.Dispose()' + [Environment]::NewLine
        $script += '$r.Dispose()' + [Environment]::NewLine
        $script += '$s.Dispose()' + [Environment]::NewLine
        $script = $script -creplace '(?m)^\s*\r?\n',''
        $payload = [char[]] $script
    }
    Process {
        Write-Verbose "[$ComputerName] Opening service manager..."
        $managerHandle = $OpenSCManagerA.Invoke("\\$ComputerName", "ServicesActive", 0xF003F)
        if ((-not $managerHandle) -or ($managerHandle -eq 0)) {
            throw $GetLastError.Invoke()
        }

        Write-Verbose "[$ComputerName] Creating $ServiceName..."
        $serviceHandle = $CreateServiceA.Invoke($managerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $command, $null, $null, $null, $null, $null)
        if ((-not $serviceHandle) -or ($serviceHandle -eq 0)) {
            $err = $GetLastError.Invoke()
            Write-Warning "[$ComputerName] CreateService failed, LastError: $err"
            break
        }
        $CloseServiceHandle.Invoke($serviceHandle) | Out-Null

        Write-Verbose "[$ComputerName] Opening the service..."
        $serviceHandle = $OpenServiceA.Invoke($managerHandle, $ServiceName, 0xF003F)
        if ((-not $serviceHandle) -or ($serviceHandle -eq 0)) {
            $err = $GetLastError.Invoke()
            Write-Warning "[$ComputerName] OpenServiceA failed, LastError: $err"
        }

        Write-Verbose "[$ComputerName] Starting the service..."
        if ($StartServiceA.Invoke($serviceHandle, $null, $null) -eq 0){
            $err = $GetLastError.Invoke()
            if ($err -eq 1053) {
                Write-Verbose "[$ComputerName] Command didn't respond to start."
            }
            else {
                Write-Warning "[$ComputerName] StartService failed, LastError: $err"
            }
            Start-Sleep -Seconds 1
        }

        Write-Verbose "[$ComputerName] Connecting to named pipe server \\$ComputerName\pipe\$PipeName..."
        $pipeTimeout = 10000 # 10s
        $pipeClient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
        $pipeClient.Connect($pipeTimeout)
        Write-Verbose "[$ComputerName] Delivering payload..."
        $writer = New-Object IO.StreamWriter($pipeClient)
        $writer.AutoFlush = $true
        $writer.WriteLine($payload)
        Write-Verbose "[$ComputerName] Getting execution output..."
        $reader = New-Object IO.StreamReader($pipeClient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Host "`n[$ComputerName] Execution finished."
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))
    }
    End {
        $reader.Dispose()
        $pipeClient.Dispose()

        Write-Verbose "[$ComputerName] Deleting the service..."
        if ($DeleteService.invoke($serviceHandle) -eq 0){
            $err = $GetLastError.Invoke()
            Write-Warning "[$ComputerName] DeleteService failed, LastError: $err"
        }
        $CloseServiceHandle.Invoke($serviceHandle) | Out-Null
        $CloseServiceHandle.Invoke($managerHandle) | Out-Null

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

function Local:Invoke-SmbTask {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String]
        $PipeName = [guid]::NewGuid().Guid,

        [ValidateNotNullOrEmpty()]
        [String]
        $TaskName = [guid]::NewGuid().Guid
    )
    Begin {
        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }

        $loader = ''
        $loader += '$s = new-object IO.Pipes.NamedPipeServerStream(''' + $PipeName + ''', 3); '
        $loader += '$s.WaitForConnection(); '
        $loader += '$r = new-object IO.StreamReader $s; '
        $loader += '$x = ''''; '
        $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
        $loader += '$z = [ScriptBlock]::Create($x); '
        $loader += '& $z'
        $arguments = '-NoP -NonI -C "' + $loader + '"'

        $script = ''
        $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
        $script += '$output = [Management.Automation.PSSerializer]::Serialize((& $scriptBlock *>&1))' + [Environment]::NewLine
        $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
        $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
        $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
        $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
        $script += '$writer.Dispose()' + [Environment]::NewLine
        $script += '$r.Dispose()' + [Environment]::NewLine
        $script += '$s.Dispose()' + [Environment]::NewLine
        $script = $script -creplace '(?m)^\s*\r?\n',''
        $payload = [char[]] $script
    }
    Process {
        try {
            $com = [Type]::GetTypeFromProgID("Schedule.Service")
            $scheduleService = [Activator]::CreateInstance($com)
        }
        catch {
            throw $_
        }

        try {
            $scheduleService.Connect($ComputerName)
        }
        catch {
            throw $_
        }
        $scheduleTaskFolder = $scheduleService.GetFolder("\")
        $taskDefinition = $scheduleService.NewTask(0)
        $taskDefinition.Settings.StopIfGoingOnBatteries = $false
        $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
        $taskDefinition.Settings.Hidden = $true
        $taskDefinition.Principal.RunLevel = 1
        $taskAction = $taskDefinition.Actions.Create(0)
        $taskAction.WorkingDirectory = '%windir%\System32\WindowsPowerShell\v1.0\'
        $taskAction.Path = 'powershell'
        $taskAction.Arguments = $arguments
        try {
            $taskAction.HideAppWindow = $true
        }
        catch {}
        Write-Verbose "[$ComputerName] Registering scheduled task $TaskName..."
        try {
            $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($TaskName, $taskDefinition, 6, 'System', $null, 5)
        }
        catch {
            throw $_
        }
        Write-Verbose "[$ComputerName] Running scheduled task..."
        Write-Debug "powershell $arguments"
        $scheduledTask = $registeredTask.Run($null)

        Write-Verbose "[$ComputerName] Connecting to named pipe server \\$ComputerName\pipe\$PipeName..."
        $pipeTimeout = 10000 # 10s
        $pipeClient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
        $pipeClient.Connect($pipeTimeout)
        Write-Verbose "[$ComputerName] Delivering payload..."
        $writer = New-Object IO.StreamWriter($pipeClient)
        $writer.AutoFlush = $true
        $writer.WriteLine($payload)
        Write-Verbose "[$ComputerName] Getting execution output..."
        $reader = New-Object IO.StreamReader($pipeClient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Host "`n[$ComputerName] Execution finished."
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))
    }
    End {
        $reader.Dispose()
        $pipeClient.Dispose()

        if ($scheduledTask) { 
            Write-Verbose "[$ComputerName] Unregistering scheduled task $TaskName..."
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

function Local:Invoke-SmbDcom {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String]
        $PipeName = [guid]::NewGuid().Guid
    )
    Begin {
        Function Local:Invoke-UserProcess {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $True)]
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential,

                [Parameter(Mandatory = $True)]
                [String]
                $Command
            )
            $networkCredential = $Credential.GetNetworkCredential()
            $userDomain = $networkCredential.Domain
            $userName = $networkCredential.UserName
            $password = $networkCredential.Password
            $systemModule = [Microsoft.Win32.IntranetZoneCredentialPolicy].Module
            $nativeMethods = $systemModule.GetType('Microsoft.Win32.NativeMethods')
            $safeNativeMethods = $systemModule.GetType('Microsoft.Win32.SafeNativeMethods')
            $CreateProcessWithLogonW = $nativeMethods.GetMethod('CreateProcessWithLogonW', [Reflection.BindingFlags] 'NonPublic, Static')
            $LogonFlags = $nativeMethods.GetNestedType('LogonFlags', [Reflection.BindingFlags] 'NonPublic')
            $StartupInfo = $nativeMethods.GetNestedType('STARTUPINFO', [Reflection.BindingFlags] 'NonPublic')
            $ProcessInformation = $safeNativeMethods.GetNestedType('PROCESS_INFORMATION', [Reflection.BindingFlags] 'NonPublic')
            $flags = [Activator]::CreateInstance($LogonFlags)
            $flags.value__ = 2 # LOGON_NETCREDENTIALS_ONLY
            $startInfo = [Activator]::CreateInstance($StartupInfo)
            $procInfo = [Activator]::CreateInstance($ProcessInformation)
            $passwordStr = ConvertTo-SecureString $password -AsPlainText -Force
            $passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($passwordStr)
            $strBuilder = New-Object System.Text.StringBuilder
            $strBuilder.Append($Command) | Out-Null
            $result = $CreateProcessWithLogonW.Invoke($null, @([String] $userName,
                                                    [String] $userDomain,
                                                    [IntPtr] $passwordPtr,
                                                    ($flags -as $LogonFlags),
                                                    $null,
                                                    [Text.StringBuilder] $strBuilder,
                                                    0x08000000,
                                                    $null,
                                                    $null,
                                                    $startInfo,
                                                    $procInfo))
            if (-not $result) {
                Write-Error "Unable to create process as user $userName."
            }
        }

        $loader = ''
        $loader += '$s = new-object IO.Pipes.NamedPipeServerStream(''' + $PipeName + ''', 3); '
        $loader += '$s.WaitForConnection(); '
        $loader += '$r = new-object IO.StreamReader $s; '
        $loader += '$x = ''''; '
        $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
        $loader += '$z = [ScriptBlock]::Create($x); '
        $loader += '& $z'
        $arguments = '/c powershell -NoP -NonI -C "' + $loader + '"'

        $script = ''
        $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
        $script += '$output = [Management.Automation.PSSerializer]::Serialize((& $scriptBlock *>&1))' + [Environment]::NewLine
        $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
        $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
        $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
        $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
        $script += '$writer.Dispose()' + [Environment]::NewLine
        $script += '$r.Dispose()' + [Environment]::NewLine
        $script += '$s.Dispose()' + [Environment]::NewLine
        $script = $script -creplace '(?m)^\s*\r?\n',''
        $payload = [char[]] $script
    }
    Process {
        if ($Credential.UserName) {
            Write-Verbose "[$ComputerName] Running command..."
            Write-Debug "%COMSPEC% $arguments"
            $script = ''
            $script += '$obj = [Activator]::CreateInstance([Type]::GetTypeFromProgID(''MMC20.Application'', ''' + $ComputerName + '''));'
            $script += '$obj.Document.ActiveView.ExecuteShellCommand(''%COMSPEC%'', $null, ''' + $arguments.Replace("'","''") + ''', ''7'')'
            try {
                Invoke-UserProcess -Credential $Credential -Command ('powershell.exe -NoP -NonI -C "' + $script.Replace('"','""') + '"')
            }
            catch {
                throw $_
            }
        }
        else {
            try {
                $com = [Type]::GetTypeFromProgID("MMC20.Application", $ComputerName)
                $obj = [Activator]::CreateInstance($com)
            }
            catch {
                throw $_
            }
            Write-Verbose "[$ComputerName] Running command..."
            Write-Debug "%COMSPEC% $arguments"
            $obj.Document.ActiveView.ExecuteShellCommand('%COMSPEC%', $null, $arguments, '7')
        }

        Write-Verbose "[$ComputerName] Connecting to named pipe server \\$ComputerName\pipe\$PipeName..."
        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }
        $pipeTimeout = 10000 # 10s
        $pipeClient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
        $pipeClient.Connect($pipeTimeout)
        Write-Verbose "[$ComputerName] Delivering payload..."
        $writer = New-Object IO.StreamWriter($pipeClient)
        $writer.AutoFlush = $true
        $writer.WriteLine($payload)
        Write-Verbose "[$ComputerName] Getting execution output..."
        $reader = New-Object IO.StreamReader($pipeClient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Host "`n[$ComputerName] Execution finished."
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))
    }
    End {
        $reader.Dispose()
        $pipeClient.Dispose()

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

Function Local:Get-DelegateType {
    Param (
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Type]
        $ReturnType = [Void]
    )
    $domain = [AppDomain]::CurrentDomain
    $dynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
    $assemblyBuilder = $domain.DefineDynamicAssembly($dynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $typeBuilder = $moduleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
    $constructorBuilder = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $Parameters)
    $constructorBuilder.SetImplementationFlags('Runtime, Managed')
    $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $methodBuilder.SetImplementationFlags('Runtime, Managed')
    Write-Output $typeBuilder.CreateType()
}

Function Local:Get-ProcAddress {
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Module,

        [Parameter(Mandatory = $True)]
        [String]
        $Procedure
    )
    $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([Runtime.InteropServices.HandleRef], [String]))
    $kern32Handle = $getModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $handleRef = New-Object Runtime.InteropServices.HandleRef($tmpPtr, $kern32Handle)
    Write-Output $getProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef]$handleRef, $Procedure))
}

Function Local:Invoke-UserImpersonation {
    Param(
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    $logonUserAddr = Get-ProcAddress Advapi32.dll LogonUserA
    $logonUserDelegate = Get-DelegateType @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
    $logonUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($logonUserAddr, $logonUserDelegate)

    $impersonateLoggedOnUserAddr = Get-ProcAddress Advapi32.dll ImpersonateLoggedOnUser
    $impersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $impersonateLoggedOnUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($impersonateLoggedOnUserAddr, $impersonateLoggedOnUserDelegate)

    $logonTokenHandle = [IntPtr]::Zero
    $networkCredential = $Credential.GetNetworkCredential()
    $userDomain = $networkCredential.Domain
    $userName = $networkCredential.UserName

    if (-not $logonUser.Invoke($userName, $userDomain, $networkCredential.Password, 9, 3, [ref]$logonTokenHandle)) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[UserImpersonation] LogonUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }

    if (-not $impersonateLoggedOnUser.Invoke($logonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
    Write-Output $logonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    $closeHandleAddr = Get-ProcAddress Kernel32.dll CloseHandle
    $closeHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $closeHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($closeHandleAddr, $closeHandleDelegate)

    $revertToSelfAddr = Get-ProcAddress Advapi32.dll RevertToSelf
    $revertToSelfDelegate = Get-DelegateType @() ([Bool])
    $revertToSelf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($revertToSelfAddr, $revertToSelfDelegate)

    if ($PSBoundParameters['TokenHandle']) {
        $closeHandle.Invoke($TokenHandle) | Out-Null
    }
    if (-not $revertToSelf.Invoke()) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] Error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
}
