function Invoke-PowerExec {
<#
.SYNOPSIS
    Invoke PowerShell commands on remote computers.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-PowerExec runs PowerShell script block on remote computers through various techniques.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ComputerList
    Specifies the target hosts, such as specific addresses or network ranges (CIDR).

.PARAMETER DomainComputers
    Specifies an Active Directory domain for enumerating target hosts.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Protocol
    Specifies the execution technique to use, defaults to WinRM.

.PARAMETER Threads
    Specifies the number of threads to use, defaults to 5.

.EXAMPLE
    PS C:\> Invoke-PowerExec -ScriptBlock {Write-Output "$Env:COMPUTERNAME ($Env:USERDOMAIN\$Env:USERNAME)"} -ComputerList $(gc hosts.txt) -Protocol WinRM

.EXAMPLE
    PS C:\> Get-PowerLoader -FilePath .\script.ps1 | Invoke-PowerExec -DomainComputers ADATUM.CORP -Credential ADATUM\Administrator -Protocol WMI -Threads 10
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerList,

        [ValidateNotNullOrEmpty()]
        [string]
        $DomainComputers,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('WinRM', 'WMI')]
        [String]
        $Protocol = 'WinRM',

        [ValidateNotNullOrEmpty()]
        [Int]
        $Threads = 5
    )

    $hostList = New-Object System.Collections.ArrayList
    foreach ($iHost in $ComputerList) {
        if ($iHost.contains("/")) {
            $netPart = $iHost.split("/")[0]
            [uint32]$maskPart = $iHost.split("/")[1]
            $address = [System.Net.IPAddress]::Parse($netPart)
            if ($maskPart -ge $address.GetAddressBytes().Length * 8) {
                throw "Bad host mask"
            }
            $numhosts = [System.math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))
            $startaddress = $address.GetAddressBytes()
            [array]::Reverse($startaddress)
            $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
            [uint32]$startMask = ([System.math]::Pow(2, $maskPart) - 1) * ([System.Math]::Pow(2, (32 - $maskPart)))
            $startAddress = $startAddress -band $startMask
            # In powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
            $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
            [array]::Reverse($startaddress)
            $address = [System.Net.IPAddress][byte[]]$startAddress
            for ($i = 0; $i -lt $numhosts - 2; $i++) {
                $nextAddress = $address.GetAddressBytes()
                [array]::Reverse($nextAddress)
                $nextAddress = [System.BitConverter]::ToUInt32($nextAddress, 0)
                $nextAddress++
                $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                [array]::Reverse($nextAddress)
                $address = [System.Net.IPAddress][byte[]]$nextAddress
                $hostList.Add($address.IPAddressToString) | Out-Null
            }
        }
        else {
            $hostList.Add($iHost) | Out-Null
        }
    }
    if ($DomainComputers) {
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainComputers/RootDSE", $null, $null)
        $rootDN = $domainObject.rootDomainNamingContext[0]
        $searchString = "LDAP://$DomainComputers/$rootDN"
        if ($Credential.UserName) {
            $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainObject)
        }
        else {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$searchString)
        }
        $searcher.filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        try {
            $results = $searcher.FindAll()
            $results | Where-Object {$_} | ForEach-Object {
                $hostList.Add($($_.properties.dnshostname).ToString()) | Out-Null
            }
            $results.dispose()
            $searcher.dispose()
        }
        catch {
            Write-Error "$_"
        }
    }

    if ($Threads -eq 1 -or $hostList.Count -eq 1) {
        foreach ($computer in $hostList) {
            New-PowerExec -ScriptBlock $ScriptBlock -ComputerName $computer -Credential $Credential -Protocol $Protocol
        }
    }
    else {
        $parameters = @{
            ScriptBlock = $ScriptBlock
            Credential = $Credential
            Protocol = $Protocol
            Verbose = $VerbosePreference
        }
        New-ThreadedFunction -ScriptBlock ${function:New-PowerExec} -ScriptParameters $parameters -Collection $hostList -CollectionParameter 'ComputerName' -Threads $Threads
    }
}

function Local:New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Array]
        $Collection,

        [ValidateNotNullOrEmpty()]
        [String]
        $CollectionParameter = 'ComputerName',

        [Parameter(Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 5,

        [Switch]
        $NoImports
    )

    BEGIN {
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # Import the current session state's variables and functions so the chained functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # Grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # These variables are added by Runspace.Open() method and produce Stop errors if added twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # Add variables from Parent Scope (current runspace) into the InitialSessionState
            foreach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add functions from current runspace to the InitialSessionState
            foreach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # Create a pool of $Threads runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # Get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        foreach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $Collection = $Collection | Where-Object {$_}
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

        # Cleanup
        $SleepSeconds = 10
        Write-Verbose "[THREAD] Waiting $SleepSeconds seconds for final cleanup..."
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

function Local:New-PowerExec {
    Param (
        [Parameter(Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateSet('WinRM', 'WMI')]
        [String]
        $Protocol = 'WinRM'
    )

    $output = $null
    switch ($Protocol) {
        'WinRM' {
            try {
                $output = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            }
            catch [System.Management.Automation.RuntimeException] {
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
        'WMI' {
            try {
                $output = Invoke-WmiExec -ScriptBlock $ScriptBlock -ComputerName $ComputerName -Credential $Credential -Verbose:$false
            }    
            catch [System.Runtime.InteropServices.COMException] {
                Write-Verbose "[$ComputerName] RPC server is unavailable."
            }
            catch [System.UnauthorizedAccessException] {
                Write-Verbose "[$ComputerName] Access is denied."
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[$ComputerName] Insufficient rights."
            }
            catch [System.Management.Automation.RuntimeException] {
                if($Error[0].FullyQualifiedErrorId -eq 'InvokeMethodOnNull') {
                    Write-Verbose "[$ComputerName] DNS resolution failed."
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

function Local:Invoke-WMIExec {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        try {
            $originalObject = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            $originalProperty = $originalObject.DebugFilePath
            Write-Verbose "[WMIEXEC] Encoding payload into WMI property DebugFilePath"
            $script = ''
            $script += '[ScriptBlock] $ScriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
            $script += '$output = & $ScriptBlock *>&1 | Out-String' + [Environment]::NewLine
            $script += 'if (-not $output) { $output = "No output." }' + [Environment]::NewLine
            $script += '$encOutput = [Int[]][Char[]]$output.Trim() -Join '',''' + [Environment]::NewLine
            $script += '$x = Get-WmiObject -Class Win32_OSRecoveryConfiguration' + [Environment]::NewLine
            $script += '$x.DebugFilePath = $encOutput' + [Environment]::NewLine
            $script += '$x.Put()'
            $encScript = [Int[]][Char[]]$script -Join ','
            $originalObject.DebugFilePath = $encScript
            $originalObject.Put() | Out-Null
        }
        catch {
            Write-Error $_
        }
    }
    PROCESS {
        $loader = ''
        $loader += '$x = Get-WmiObject -Class Win32_OSRecoveryConfiguration; '
        $loader += '$y = [char[]][int[]]$x.DebugFilePath.Split('','') -Join ''''; '
        $loader += '$z = [ScriptBlock]::Create($y); '
        $loader += '& $z'
        $command = 'powershell -NoP -NonI -C "' + $loader + '"'
        Write-Verbose "[WMIEXEC] Running command: $command"    
        $Process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command -ComputerName $ComputerName -Credential $Credential
        $ProcessId = $Process.ProcessId
        do {
            Get-WmiObject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Out-Null
            Start-Sleep -Seconds 1
        }
        until ((Get-WmiObject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Where {$_.Name -eq "powershell.exe"}).ProcessID -eq $null)
    }
    END {
        Write-Verbose "[WMIEXEC] Getting output from WMI property DebugFilePath"
        $modifiedObject = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
        $output = [char[]][int[]]$modifiedObject.DebugFilePath.Split(',') -Join ''
        Write-Output $output

        Write-Verbose "[WMIEXEC] Restoring original WMI property value: $originalProperty"
        $modifiedObject.DebugFilePath = $originalProperty
        $modifiedObject.Put() | Out-Null
    }
}