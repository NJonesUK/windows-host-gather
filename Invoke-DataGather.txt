<#
.SYNOPSIS
    Enumerates data about a Windows host to identify exploitable vulnerabilities and privilege escalation vectors.

.DESCRIPTION
    Invoke-DataGather collects comprehensive information about a Windows host system including:
    - System configuration and version information
    - User and group information
    - Network configuration
    - Running processes and services
    - Installed software and patches
    - Security settings and permissions
    - Scheduled tasks and startup programs
    - File system permissions and shares
    - Registry settings that may indicate vulnerabilities

.PARAMETER OutputPath
    Specifies the path where the gathered data will be saved. If not specified, results are returned as an object.

.PARAMETER OutputFormat
    Specifies the output format: 'Object', 'Json', or 'Xml'. Default is 'Object'.

.EXAMPLE
    Invoke-DataGather

    Gathers data about the current host and returns results as an object.

.EXAMPLE
    Invoke-DataGather -OutputPath "C:\Temp\host-data.json" -OutputFormat Json

    Gathers data about the current host and saves results to a JSON file.

.NOTES
    This cmdlet requires administrative privileges for complete enumeration.
    Some data collection may trigger security alerts depending on system configuration.
#>
function Invoke-DataGather {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Object', 'Json', 'Xml')]
        [string]$OutputFormat = 'Object',

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -and (Test-Path (Split-Path $_ -Parent)) -eq $false) {
                throw "Parent directory does not exist: $(Split-Path $_ -Parent)"
            }
            return $true
        })]
        [string]$OutputPath
    )

    begin {
        Write-Verbose "Starting data gathering process..."
        $ErrorActionPreference = 'Continue'
        $gatheredData = @{}
        $errors = @()
    }

    process {
        try {
            Write-Verbose "Gathering system information..."
            
            # Initialize the data structure
            $gatheredData = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Hostname = $env:COMPUTERNAME
                Domain = $env:USERDOMAIN
                Username = $env:USERNAME
                EnvironmentVariables = $null
                CurrentUserPrivileges = $null
                CurrentUserGroups = $null
                LocalUsers = $null
                LocalGroups = $null
                LocalAdministrators = $null
                LapsRegistry = $null
                AlwaysInstallElevated = $null
                StoredCredentials = $null
                SystemInfo = $null
                UserInfo = $null
                NetworkInterfaces = $null
                DnsSettings = $null
                RoutingTable = $null
                ListeningPorts = $null
                ActiveProcesses = $null
                InstalledPrograms = $null
                Services = $null
                UnquotedServicePaths = $null
                ScheduledTasks = $null
                Shares = $null
            }

            # Gather all environment variables
            try {
                Write-Debug "Collecting environment variables..."
                $envVars = @{}
                Get-ChildItem Env: | ForEach-Object {
                    $envVars[$_.Name] = $_.Value
                }
                $gatheredData.EnvironmentVariables = $envVars
                Write-Verbose "Collected $($envVars.Count) environment variables"
            }
            catch {
                $errorMessage = "Failed to gather environment variables: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather current user privileges (similar to whoami /priv)
            try {
                Write-Debug "Collecting current user privileges..."
                $privileges = @()
                
                # Use whoami.exe as primary method (most reliable)
                try {
                    $whoamiOutput = whoami.exe /priv 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0 -and $whoamiOutput) {
                        # Parse whoami output - privileges are listed after the header
                        $lines = $whoamiOutput -split "`n" | Where-Object { 
                            $_ -match "^\s+\S+\s+(Enabled|Disabled)\s*$" -or 
                            $_ -match "^\s+\S+\s+\S+\s+(Enabled|Disabled)\s*$"
                        }
                        
                        foreach ($line in $lines) {
                            # Match format: "PRIVILEGE_NAME             Enabled" or "PRIVILEGE_NAME             State             Enabled"
                            if ($line -match "^\s+(\S+)\s+(Enabled|Disabled)") {
                                $privileges += [PSCustomObject]@{
                                    Privilege = $matches[1]
                                    State = $matches[2]
                                    Enabled = ($matches[2] -eq "Enabled")
                                }
                            }
                            elseif ($line -match "^\s+(\S+)\s+\S+\s+(Enabled|Disabled)") {
                                $privileges += [PSCustomObject]@{
                                    Privilege = $matches[1]
                                    State = $matches[2]
                                    Enabled = ($matches[2] -eq "Enabled")
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve privileges via whoami.exe: $_"
                }
                
                # If whoami failed, try alternative method using .NET
                if ($privileges.Count -eq 0) {
                    try {
                        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        # Note: This method is limited and may not show all privileges
                        Write-Debug "Using alternative method for privilege enumeration"
                    }
                    catch {
                        Write-Debug "Alternative privilege enumeration method failed"
                    }
                }
                
                $gatheredData.CurrentUserPrivileges = $privileges
                Write-Verbose "Collected $($privileges.Count) user privileges"
            }
            catch {
                $errorMessage = "Failed to gather current user privileges: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather current user groups (similar to whoami /groups)
            try {
                Write-Debug "Collecting current user groups..."
                $groups = @()
                
                # Primary method: Use .NET WindowsIdentity
                try {
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    foreach ($group in $currentUser.Groups) {
                        try {
                            $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value
                            $groups += [PSCustomObject]@{
                                GroupName = $groupName
                                SID = $group.Value
                            }
                        }
                        catch {
                            $groups += [PSCustomObject]@{
                                GroupName = "Unknown"
                                SID = $group.Value
                            }
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve groups via .NET method: $_"
                }
                
                # Fallback: Use whoami.exe if .NET method failed
                if ($groups.Count -eq 0) {
                    try {
                        $whoamiGroups = whoami.exe /groups 2>&1 | Out-String
                        if ($LASTEXITCODE -eq 0 -and $whoamiGroups) {
                            $lines = $whoamiGroups -split "`n" | Where-Object { 
                                $_ -match "^\s+\S+\s+\S+\s+.+" 
                            }
                            foreach ($line in $lines) {
                                if ($line -match "^\s+(\S+)\s+(\S+)\s+(.+)") {
                                    $groups += [PSCustomObject]@{
                                        SID = $matches[1]
                                        Attributes = $matches[2]
                                        GroupName = $matches[3].Trim()
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Debug "Could not retrieve groups via whoami.exe"
                    }
                }
                
                $gatheredData.CurrentUserGroups = $groups
                Write-Verbose "Collected $($groups.Count) user groups"
            }
            catch {
                $errorMessage = "Failed to gather current user groups: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all local users with enabled status
            try {
                Write-Debug "Collecting local users..."
                $localUsers = @()
                
                $users = Get-LocalUser -ErrorAction SilentlyContinue
                foreach ($user in $users) {
                    try {
                        $lastLogon = $null
                        
                        # Try to get last logon time from event logs (requires admin)
                        try {
                            $lastLogonEvent = Get-WinEvent -FilterHashtable @{
                                LogName = 'Security'
                                Id = 4624
                                StartTime = (Get-Date).AddDays(-365)
                            } -MaxEvents 1 -ErrorAction SilentlyContinue | 
                            Where-Object { $_.Properties[5].Value -eq $user.Name } | 
                            Select-Object -First 1
                            
                            if ($lastLogonEvent) {
                                $lastLogon = $lastLogonEvent.TimeCreated
                            }
                        }
                        catch {
                            Write-Debug "Could not retrieve last logon time for $($user.Name)"
                        }
                        
                        $localUsers += [PSCustomObject]@{
                            Name = $user.Name
                            Description = $user.Description
                            SID = $user.SID
                            Enabled = $user.Enabled
                            PasswordExpires = $user.PasswordExpires
                            UserMayChangePassword = $user.UserMayChangePassword
                            PasswordRequired = $user.PasswordRequired
                            PasswordLastSet = $user.PasswordLastSet
                            AccountExpires = $user.AccountExpires
                            LastLogon = $lastLogon
                        }
                    }
                    catch {
                        Write-Debug "Error processing user $($user.Name): $_"
                    }
                }
                
                $gatheredData.LocalUsers = $localUsers
                Write-Verbose "Collected $($localUsers.Count) local users"
            }
            catch {
                $errorMessage = "Failed to gather local users: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all local groups
            try {
                Write-Debug "Collecting local groups..."
                $localGroups = @()
                
                $groups = Get-LocalGroup -ErrorAction SilentlyContinue
                
                foreach ($group in $groups) {
                    try {
                        $members = @()
                        try {
                            $groupMembers = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                            foreach ($member in $groupMembers) {
                                $members += [PSCustomObject]@{
                                    Name = $member.Name
                                    SID = $member.SID
                                    PrincipalSource = $member.PrincipalSource
                                    ObjectClass = $member.ObjectClass
                                }
                            }
                        }
                        catch {
                            Write-Debug "Could not retrieve members for group $($group.Name)"
                        }
                        
                        # Get SID - handle both Get-LocalGroup and WMI objects
                        $groupSid = $null
                        if ($group.SID) {
                            $groupSid = $group.SID
                        }
                        elseif ($group.Name) {
                            try {
                                $groupObj = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
                                if ($groupObj) {
                                    $groupSid = $groupObj.SID
                                }
                            }
                            catch {
                                Write-Debug "Could not retrieve SID for group $($group.Name)"
                            }
                        }
                        
                        $localGroups += [PSCustomObject]@{
                            Name = if ($group.Name) { $group.Name } else { $group.Caption }
                            Description = if ($group.Description) { $group.Description } else { $null }
                            SID = $groupSid
                            Members = $members
                            MemberCount = $members.Count
                        }
                    }
                    catch {
                        $localGroups += [PSCustomObject]@{
                            Name = if ($group.Name) { $group.Name } else { $group.Caption }
                            Description = $null
                            SID = $null
                            Members = @()
                            MemberCount = 0
                        }
                    }
                }
                
                $gatheredData.LocalGroups = $localGroups
                Write-Verbose "Collected $($localGroups.Count) local groups"
            }
            catch {
                $errorMessage = "Failed to gather local groups: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather local administrator accounts
            try {
                Write-Debug "Collecting local administrator accounts..."
                $administrators = @()
                
                try {
                    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
                    foreach ($admin in $adminGroup) {
                        $administrators += [PSCustomObject]@{
                            Name = $admin.Name
                            SID = $admin.SID
                            PrincipalSource = $admin.PrincipalSource.ToString()
                            ObjectClass = $admin.ObjectClass
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve administrators via Get-LocalGroupMember"
                }
                
                $gatheredData.LocalAdministrators = $administrators
                Write-Verbose "Collected $($administrators.Count) local administrator accounts"
            }
            catch {
                $errorMessage = "Failed to gather local administrator accounts: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather LAPS registry key contents
            try {
                Write-Debug "Collecting LAPS registry key contents..."
                $lapsRegistryPath = "HKLM:\Software\Policies\Microsoft Services\AdmPwd"
                $lapsRegistry = $null
                
                if (Test-Path -Path $lapsRegistryPath) {
                    try {
                        $registryValues = Get-ItemProperty -Path $lapsRegistryPath -ErrorAction Stop
                        
                        $lapsData = [PSCustomObject]@{
                            KeyPath = $lapsRegistryPath
                            Exists = $true
                            Properties = @{}
                        }
                        
                        # Extract all property values (excluding PS* properties added by Get-ItemProperty)
                        $registryValues.PSObject.Properties | Where-Object {
                            $_.Name -notlike "PS*"
                        } | ForEach-Object {
                            $lapsData.Properties[$_.Name] = $_.Value
                        }
                        
                        $lapsRegistry = $lapsData
                        Write-Verbose "Collected LAPS registry key with $($lapsData.Properties.Count) properties"
                    }
                    catch {
                        $errorMessage = "Failed to read LAPS registry key: $_"
                        Write-Warning $errorMessage
                        $lapsRegistry = [PSCustomObject]@{
                            KeyPath = $lapsRegistryPath
                            Exists = $true
                            Error = $errorMessage
                            Properties = $null
                        }
                    }
                }
                else {
                    Write-Verbose "LAPS registry key does not exist at: $lapsRegistryPath"
                    $lapsRegistry = [PSCustomObject]@{
                        KeyPath = $lapsRegistryPath
                        Exists = $false
                        Properties = $null
                    }
                }
                
                $gatheredData.LapsRegistry = $lapsRegistry
            }
            catch {
                $errorMessage = "Failed to gather LAPS registry key: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Check if AlwaysInstallElevated is enabled
            try {
                Write-Debug "Checking AlwaysInstallElevated registry keys..."
                $alwaysInstallElevated = [PSCustomObject]@{
                    Enabled = $false
                    HKLMEnabled = $false
                    HKCUEnabled = $false
                    HKLMValue = $null
                    HKCUValue = $null
                }
                
                # Check HKLM registry key
                $hklmPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
                if (Test-Path $hklmPath) {
                    try {
                        $hklmValues = Get-ItemProperty -Path $hklmPath -ErrorAction SilentlyContinue
                        if ($hklmValues -and $hklmValues.AlwaysInstallElevated) {
                            $alwaysInstallElevated.HKLMValue = $hklmValues.AlwaysInstallElevated
                            $alwaysInstallElevated.HKLMEnabled = ($hklmValues.AlwaysInstallElevated -eq 1)
                        }
                    }
                    catch {
                        Write-Debug "Could not read HKLM AlwaysInstallElevated registry key: $_"
                    }
                }
                
                # Check HKCU registry key
                $hkcuPath = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
                if (Test-Path $hkcuPath) {
                    try {
                        $hkcuValues = Get-ItemProperty -Path $hkcuPath -ErrorAction SilentlyContinue
                        if ($hkcuValues -and $hkcuValues.AlwaysInstallElevated) {
                            $alwaysInstallElevated.HKCUValue = $hkcuValues.AlwaysInstallElevated
                            $alwaysInstallElevated.HKCUEnabled = ($hkcuValues.AlwaysInstallElevated -eq 1)
                        }
                    }
                    catch {
                        Write-Debug "Could not read HKCU AlwaysInstallElevated registry key: $_"
                    }
                }
                
                # AlwaysInstallElevated is enabled if both HKLM and HKCU are set to 1
                $alwaysInstallElevated.Enabled = ($alwaysInstallElevated.HKLMEnabled -and $alwaysInstallElevated.HKCUEnabled)
                
                $gatheredData.AlwaysInstallElevated = $alwaysInstallElevated
                Write-Verbose "Checked AlwaysInstallElevated - Enabled: $($alwaysInstallElevated.Enabled)"
            }
            catch {
                $errorMessage = "Failed to check AlwaysInstallElevated: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather stored credentials using cmdkey /list
            try {
                Write-Debug "Collecting stored credentials..."
                $storedCredentials = @()
                
                try {
                    # Run cmdkey /list and capture output
                    $cmdkeyOutput = cmdkey.exe /list 2>&1 | Out-String
                    
                    if ($cmdkeyOutput -and $LASTEXITCODE -eq 0) {
                        # Parse cmdkey output
                        $lines = $cmdkeyOutput -split "`n"
                        $currentCredential = $null
                        
                        foreach ($line in $lines) {
                            $line = $line.Trim()
                            
                            # Skip empty lines and header lines
                            if ([string]::IsNullOrWhiteSpace($line) -or 
                                $line -eq "Currently stored credentials:" -or
                                $line -match "^Target:") {
                                continue
                            }
                            
                            # Match credential target line: "Target: <target>"
                            if ($line -match "^Target:\s*(.+)") {
                                # Save previous credential if exists
                                if ($currentCredential) {
                                    $storedCredentials += $currentCredential
                                }
                                
                                # Start new credential
                                $currentCredential = [PSCustomObject]@{
                                    Target = $matches[1].Trim()
                                    Type = $null
                                    User = $null
                                }
                            }
                            # Match credential type line: "Type: <type>"
                            elseif ($line -match "^Type:\s*(.+)") {
                                if ($currentCredential) {
                                    $currentCredential.Type = $matches[1].Trim()
                                }
                            }
                            # Match user line: "User: <user>"
                            elseif ($line -match "^User:\s*(.+)") {
                                if ($currentCredential) {
                                    $currentCredential.User = $matches[1].Trim()
                                }
                            }
                        }
                        
                        # Add last credential if exists
                        if ($currentCredential) {
                            $storedCredentials += $currentCredential
                        }
                    }
                    else {
                        Write-Debug "cmdkey /list returned no output or error"
                    }
                }
                catch {
                    Write-Debug "Could not execute cmdkey /list: $_"
                }
                
                $gatheredData.StoredCredentials = $storedCredentials
                Write-Verbose "Collected $($storedCredentials.Count) stored credentials"
            }
            catch {
                $errorMessage = "Failed to gather stored credentials: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather network interfaces using Get-NetIPConfiguration
            try {
                Write-Debug "Collecting network interfaces..."
                $networkInterfaces = @()
                
                $ipConfigs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
                foreach ($config in $ipConfigs) {
                    $interfaceInfo = [PSCustomObject]@{
                        InterfaceAlias = $config.InterfaceAlias
                        InterfaceIndex = $config.InterfaceIndex
                        InterfaceDescription = $config.InterfaceDescription
                        NetAdapter = [PSCustomObject]@{
                            Status = $config.NetAdapter.Status
                            LinkSpeed = $config.NetAdapter.LinkSpeed
                            PhysicalMediaType = $config.NetAdapter.PhysicalMediaType
                            MacAddress = $config.NetAdapter.MacAddress
                        }
                        IPv4Address = $null
                        IPv6Address = $null
                        IPv4DefaultGateway = $null
                        IPv6DefaultGateway = $null
                        DNSServer = $null
                    }
                    
                    if ($config.IPv4Address) {
                        $interfaceInfo.IPv4Address = [PSCustomObject]@{
                            IPAddress = $config.IPv4Address.IPAddress
                            PrefixLength = $config.IPv4Address.PrefixLength
                            AddressFamily = $config.IPv4Address.AddressFamily
                        }
                    }
                    
                    if ($config.IPv6Address) {
                        $interfaceInfo.IPv6Address = [PSCustomObject]@{
                            IPAddress = $config.IPv6Address.IPAddress
                            PrefixLength = $config.IPv6Address.PrefixLength
                            AddressFamily = $config.IPv6Address.AddressFamily
                        }
                    }
                    
                    if ($config.IPv4DefaultGateway) {
                        $interfaceInfo.IPv4DefaultGateway = $config.IPv4DefaultGateway.NextHop
                    }
                    
                    if ($config.IPv6DefaultGateway) {
                        $interfaceInfo.IPv6DefaultGateway = $config.IPv6DefaultGateway.NextHop
                    }
                    
                    if ($config.DNSServer) {
                        $interfaceInfo.DNSServer = $config.DNSServer.ServerAddresses
                    }
                    
                    $networkInterfaces += $interfaceInfo
                }
                
                $gatheredData.NetworkInterfaces = $networkInterfaces
                Write-Verbose "Collected $($networkInterfaces.Count) network interfaces"
            }
            catch {
                $errorMessage = "Failed to gather network interfaces: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather DNS settings using Get-DnsClientServerAddress
            try {
                Write-Debug "Collecting DNS settings..."
                $dnsSettings = @()
                
                $dnsConfigs = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
                foreach ($dnsConfig in $dnsConfigs) {
                    $dnsSettings += [PSCustomObject]@{
                        InterfaceAlias = $dnsConfig.InterfaceAlias
                        InterfaceIndex = $dnsConfig.InterfaceIndex
                        ServerAddresses = $dnsConfig.ServerAddresses
                        AddressFamily = $dnsConfig.AddressFamily
                        ValidateServerCertificate = $dnsConfig.ValidateServerCertificate
                    }
                }
                
                $gatheredData.DnsSettings = $dnsSettings
                Write-Verbose "Collected DNS settings for $($dnsSettings.Count) interfaces"
            }
            catch {
                $errorMessage = "Failed to gather DNS settings: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather routing table using Get-NetRoute
            try {
                Write-Debug "Collecting routing table..."
                $routes = @()
                
                $netRoutes = Get-NetRoute -ErrorAction SilentlyContinue
                foreach ($route in $netRoutes) {
                    $routes += [PSCustomObject]@{
                        DestinationPrefix = $route.DestinationPrefix
                        NextHop = $route.NextHop
                        InterfaceAlias = $route.InterfaceAlias
                        InterfaceIndex = $route.InterfaceIndex
                        RouteMetric = $route.RouteMetric
                        Protocol = $route.Protocol
                        AddressFamily = $route.AddressFamily
                        Type = $route.Type
                        ValidLifetime = $route.ValidLifetime
                        PreferredLifetime = $route.PreferredLifetime
                    }
                }
                
                $gatheredData.RoutingTable = $routes
                Write-Verbose "Collected $($routes.Count) routing table entries"
            }
            catch {
                $errorMessage = "Failed to gather routing table: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather listening ports and associated processes
            try {
                Write-Debug "Collecting listening ports and processes..."
                $listeningPorts = @()
                
                # Use Get-NetTCPConnection for TCP connections
                $tcpConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
                foreach ($conn in $tcpConnections) {
                    $processName = $null
                    if ($conn.OwningProcess) {
                        try {
                            # Only retrieve process name, not full process object with path
                            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                            $processName = $process.ProcessName
                        }
                        catch {
                            Write-Debug "Could not retrieve process information for PID $($conn.OwningProcess)"
                        }
                    }
                    
                    $listeningPorts += [PSCustomObject]@{
                        Protocol = "TCP"
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        State = $conn.State
                        OwningProcess = $conn.OwningProcess
                        ProcessName = $processName
                        CreationTime = $conn.CreationTime
                    }
                }
                
                # Use Get-NetUDPEndpoint for UDP endpoints
                $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
                foreach ($endpoint in $udpEndpoints) {
                    $processName = $null
                    if ($endpoint.OwningProcess) {
                        try {
                            # Only retrieve process name, not full process object with path
                            $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
                            $processName = $process.ProcessName
                        }
                        catch {
                            Write-Debug "Could not retrieve process information for PID $($endpoint.OwningProcess)"
                        }
                    }
                    
                    $listeningPorts += [PSCustomObject]@{
                        Protocol = "UDP"
                        LocalAddress = $endpoint.LocalAddress
                        LocalPort = $endpoint.LocalPort
                        State = "Listen"
                        OwningProcess = $endpoint.OwningProcess
                        ProcessName = $processName
                        CreationTime = $endpoint.CreationTime
                    }
                }
                
                $gatheredData.ListeningPorts = $listeningPorts
                Write-Verbose "Collected $($listeningPorts.Count) listening ports"
            }
            catch {
                $errorMessage = "Failed to gather listening ports: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all active processes on the system
            try {
                Write-Debug "Collecting active processes..."
                $processes = @()
                
                $allProcesses = Get-Process -ErrorAction SilentlyContinue
                foreach ($proc in $allProcesses) {
                    try {
                        $processInfo = [PSCustomObject]@{
                            Id = $proc.Id
                            ProcessName = $proc.ProcessName
                            Path = $proc.Path
                            StartTime = $proc.StartTime
                            CPU = $proc.CPU
                            WorkingSet = $proc.WorkingSet
                            PagedMemorySize = $proc.PagedMemorySize
                            VirtualMemorySize = $proc.VirtualMemorySize
                            Threads = $proc.Threads.Count
                            Handles = $proc.Handles
                            PriorityClass = $proc.PriorityClass.ToString()
                            Company = $proc.Company
                            Product = $proc.Product
                            Description = $proc.Description
                            FileVersion = $proc.FileVersion
                        }
                        
                        $processes += $processInfo
                    }
                    catch {
                        Write-Debug "Error processing process $($proc.ProcessName): $_"
                    }
                }
                
                $gatheredData.ActiveProcesses = $processes
                Write-Verbose "Collected $($processes.Count) active processes"
            }
            catch {
                $errorMessage = "Failed to gather active processes: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather system information using .NET and registry
            try {
                Write-Debug "Collecting system information..."
                
                # Get OS version using .NET
                $osVersion = [System.Environment]::OSVersion
                $osVersionString = $osVersion.Version.ToString()
                
                # Get OS name and build from registry
                $osName = $null
                $buildNumber = $null
                $architecture = $null
                try {
                    $osRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    if (Test-Path $osRegPath) {
                        $osReg = Get-ItemProperty -Path $osRegPath -ErrorAction SilentlyContinue
                        if ($osReg) {
                            $osName = $osReg.ProductName
                            $buildNumber = $osReg.CurrentBuildNumber
                            if ($osReg.DisplayVersion) {
                                $osName = "$osName $($osReg.DisplayVersion)"
                            }
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve OS name from registry: $_"
                }
                
                # Get architecture
                if ([System.Environment]::Is64BitOperatingSystem) {
                    $architecture = "64-bit"
                }
                else {
                    $architecture = "32-bit"
                }
                
                # Get total physical memory
                # Note: Total memory cannot be reliably retrieved without WMI/CIM/COM
                # Leaving as null to maintain WMI-free implementation
                $totalMemory = $null
                
                # Get manufacturer and model from registry
                $manufacturer = $null
                $model = $null
                try {
                    $biosRegPath = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
                    if (Test-Path $biosRegPath) {
                        $biosReg = Get-ItemProperty -Path $biosRegPath -ErrorAction SilentlyContinue
                        if ($biosReg) {
                            $manufacturer = $biosReg.Manufacturer
                            $model = $biosReg.SystemProductName
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve manufacturer/model from registry: $_"
                }
                
                # Get install date from registry
                $installDate = $null
                try {
                    $installRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    if (Test-Path $installRegPath) {
                        $installReg = Get-ItemProperty -Path $installRegPath -ErrorAction SilentlyContinue
                        if ($installReg -and $installReg.InstallDate) {
                            $installDate = [DateTime]::FromFileTime($installReg.InstallDate)
                        }
                    }
                }
                catch {
                    Write-Debug "Could not retrieve install date from registry: $_"
                }
                
                # Get last boot time using .NET
                $lastBootTime = $null
                try {
                    $lastBootTime = (Get-Date).AddMilliseconds(-[System.Environment]::TickCount)
                }
                catch {
                    Write-Debug "Could not calculate last boot time: $_"
                }
                
                $gatheredData.SystemInfo = [PSCustomObject]@{
                    OSVersion = $osVersionString
                    OSName = $osName
                    Architecture = $architecture
                    BuildNumber = $buildNumber
                    InstallDate = $installDate
                    LastBootUpTime = $lastBootTime
                    TotalPhysicalMemory = $totalMemory
                    Manufacturer = $manufacturer
                    Model = $model
                }
                
                Write-Verbose "Collected system information"
            }
            catch {
                $errorMessage = "Failed to gather system information: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all installed programs from registry
            try {
                Write-Debug "Collecting installed programs..."
                $installedPrograms = @()
                
                # Registry paths for installed programs (32-bit and 64-bit)
                $registryPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                
                foreach ($regPath in $registryPaths) {
                    if (Test-Path $regPath) {
                        try {
                            $programs = Get-ItemProperty -Path "$regPath\*" -ErrorAction SilentlyContinue
                            foreach ($program in $programs) {
                                try {
                                    # Skip system components and updates
                                    if ($program.DisplayName -and 
                                        $program.DisplayName -notmatch "^(KB|Update|Hotfix|Security Update)" -and
                                        $program.PSChildName -notmatch "^{[0-9A-F-]+}$") {
                                        
                                        $installedPrograms += [PSCustomObject]@{
                                            DisplayName = $program.DisplayName
                                            DisplayVersion = $program.DisplayVersion
                                            Publisher = $program.Publisher
                                            InstallDate = $program.InstallDate
                                            InstallLocation = $program.InstallLocation
                                            UninstallString = $program.UninstallString
                                            QuietUninstallString = $program.QuietUninstallString
                                            EstimatedSize = $program.EstimatedSize
                                            Version = $program.Version
                                            VersionMajor = $program.VersionMajor
                                            VersionMinor = $program.VersionMinor
                                        }
                                    }
                                }
                                catch {
                                    Write-Debug "Error processing program: $_"
                                }
                            }
                        }
                        catch {
                            Write-Debug "Could not read registry path ${regPath}: $_"
                        }
                    }
                }
                
                # Remove duplicates based on DisplayName
                $installedPrograms = $installedPrograms | Sort-Object DisplayName -Unique
                
                $gatheredData.InstalledPrograms = $installedPrograms
                Write-Verbose "Collected $($installedPrograms.Count) installed programs"
            }
            catch {
                $errorMessage = "Failed to gather installed programs: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all services and their configurations
            try {
                Write-Debug "Collecting services..."
                $services = @()
                
                $allServices = Get-Service -ErrorAction SilentlyContinue
                foreach ($service in $allServices) {
                    try {
                        $serviceInfo = [PSCustomObject]@{
                            Name = $service.Name
                            DisplayName = $service.DisplayName
                            Status = $service.Status.ToString()
                            StartType = $null
                            Description = $null
                            ServiceType = $null
                            CanStop = $service.CanStop
                            CanPauseAndContinue = $service.CanPauseAndContinue
                            ServicesDependedOn = @()
                        }
                        
                        # Get detailed service information from registry
                        try {
                            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                            if (Test-Path $regPath) {
                                $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                                if ($regValues) {
                                    $serviceInfo.Description = $regValues.Description
                                    
                                    # Map Start value to StartType
                                    if ($regValues.Start) {
                                        switch ($regValues.Start) {
                                            0 { $serviceInfo.StartType = "Boot" }
                                            1 { $serviceInfo.StartType = "System" }
                                            2 { $serviceInfo.StartType = "Automatic" }
                                            3 { $serviceInfo.StartType = "Manual" }
                                            4 { $serviceInfo.StartType = "Disabled" }
                                            default { $serviceInfo.StartType = $regValues.Start }
                                        }
                                    }
                                    
                                    # Translate ServiceType numeric value to string
                                    if ($regValues.Type) {
                                        $typeValue = $regValues.Type
                                        $typeStrings = @()
                                        
                                        # ServiceType is a bitmask, check each bit
                                        if (($typeValue -band 1) -eq 1) { $typeStrings += "Kernel Driver" }
                                        if (($typeValue -band 2) -eq 2) { $typeStrings += "File System Driver" }
                                        if (($typeValue -band 4) -eq 4) { $typeStrings += "Adapter" }
                                        if (($typeValue -band 8) -eq 8) { $typeStrings += "Recognizer Driver" }
                                        if (($typeValue -band 16) -eq 16) { $typeStrings += "Win32 Own Process" }
                                        if (($typeValue -band 32) -eq 32) { $typeStrings += "Win32 Share Process" }
                                        if (($typeValue -band 256) -eq 256) { $typeStrings += "Interactive Process" }
                                        
                                        # If no known bits match, return the numeric value as string
                                        if ($typeStrings.Count -eq 0) {
                                            $serviceInfo.ServiceType = $typeValue.ToString()
                                        }
                                        else {
                                            $serviceInfo.ServiceType = $typeStrings -join ", "
                                        }
                                    }
                                    
                                    # Get dependent services from registry
                                    $dependOnService = $regValues.DependOnService
                                    if ($dependOnService) {
                                        if ($dependOnService -is [array]) {
                                            $serviceInfo.ServicesDependedOn = $dependOnService
                                        }
                                        else {
                                            $serviceInfo.ServicesDependedOn = @($dependOnService)
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Debug "Could not retrieve detailed configuration for service $($service.Name): $_"
                        }
                        
                        $services += $serviceInfo
                    }
                    catch {
                        Write-Debug "Error processing service $($service.Name): $_"
                    }
                }
                
                $gatheredData.Services = $services
                Write-Verbose "Collected $($services.Count) services"
            }
            catch {
                $errorMessage = "Failed to gather services: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather unquoted service paths (potential privilege escalation vector)
            try {
                Write-Debug "Collecting unquoted service paths..."
                $unquotedServicePaths = @()
                
                # Get all services
                $allServices = Get-Service -ErrorAction SilentlyContinue
                
                foreach ($service in $allServices) {
                    try {
                        # Get service configuration from registry
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                        if (Test-Path $regPath) {
                            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                            
                            if ($regValues) {
                                # Check if service is set to Auto start (Start = 2)
                                $startMode = $regValues.Start
                                $isAuto = ($startMode -eq 2)
                                
                                # Get the service path (ImagePath in registry, PathName in WMI)
                                $pathName = $regValues.ImagePath
                                
                                # Apply filters matching the provided snippet:
                                # - StartMode must be "Auto" (Start = 2)
                                # - PathName must not start with "C:\Windows*"
                                # - PathName must not start with a quote (unquoted paths)
                                if ($isAuto -and 
                                    $pathName -and 
                                    $pathName -notlike "C:\Windows*" -and 
                                    $pathName -notlike '"*') {
                                    
                                    $unquotedServicePaths += [PSCustomObject]@{
                                        Name = $service.Name
                                        DisplayName = $service.DisplayName
                                        PathName = $pathName
                                        StartMode = "Auto"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Debug "Error processing service $($service.Name) for unquoted path check: $_"
                    }
                }
                
                $gatheredData.UnquotedServicePaths = $unquotedServicePaths
                Write-Verbose "Collected $($unquotedServicePaths.Count) unquoted service paths"
            }
            catch {
                $errorMessage = "Failed to gather unquoted service paths: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all non-Microsoft scheduled tasks
            try {
                Write-Debug "Collecting non-Microsoft scheduled tasks..."
                $scheduledTasks = @()
                
                $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
                foreach ($task in $allTasks) {
                    try {
                        # Filter out Microsoft tasks
                        $taskPath = $task.TaskPath
                        $isMicrosoftTask = $false
                        
                        # Check if task is in Microsoft folder or has Microsoft in path/author
                        if ($taskPath -like "*\Microsoft\*" -or 
                            $taskPath -eq "\Microsoft\" -or
                            $taskPath -like "\Microsoft Windows\*" -or
                            $task.TaskName -like "*Microsoft*") {
                            $isMicrosoftTask = $true
                        }
                        
                        # Check task author/description for Microsoft
                        try {
                            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                            $taskDetails = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                            
                            if ($taskDetails) {
                                if ($taskDetails.Author -like "*Microsoft*" -or 
                                    $taskDetails.Description -like "*Microsoft*") {
                                    $isMicrosoftTask = $true
                                }
                            }
                        }
                        catch {
                            Write-Debug "Could not retrieve task details for $($task.TaskName): $_"
                        }
                        
                        # Only include non-Microsoft tasks
                        if (-not $isMicrosoftTask) {
                            try {
                                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                                $taskDetails = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                                
                                $taskData = [PSCustomObject]@{
                                    TaskName = $task.TaskName
                                    TaskPath = $task.TaskPath
                                    State = $task.State.ToString()
                                    Author = if ($taskDetails) { $taskDetails.Author } else { $null }
                                    Description = if ($taskDetails) { $taskDetails.Description } else { $null }
                                    LastRunTime = if ($taskInfo) { $taskInfo.LastRunTime } else { $null }
                                    NextRunTime = if ($taskInfo) { $taskInfo.NextRunTime } else { $null }
                                    LastTaskResult = if ($taskInfo) { $taskInfo.LastTaskResult } else { $null }
                                    Actions = @()
                                    Triggers = @()
                                }
                                
                                # Get task actions
                                if ($taskDetails -and $taskDetails.Actions) {
                                    foreach ($action in $taskDetails.Actions) {
                                        $taskData.Actions += [PSCustomObject]@{
                                            Execute = $action.Execute
                                            Arguments = $action.Arguments
                                            WorkingDirectory = $action.WorkingDirectory
                                        }
                                    }
                                }
                                
                                # Get task triggers
                                if ($taskDetails -and $taskDetails.Triggers) {
                                    foreach ($trigger in $taskDetails.Triggers) {
                                        $triggerData = [PSCustomObject]@{
                                            Enabled = $trigger.Enabled
                                            StartBoundary = $trigger.StartBoundary
                                            EndBoundary = $trigger.EndBoundary
                                            Repetition = $null
                                        }
                                        
                                        if ($trigger.Repetition) {
                                            $triggerData.Repetition = [PSCustomObject]@{
                                                Interval = $trigger.Repetition.Interval
                                                Duration = $trigger.Repetition.Duration
                                                StopAtDurationEnd = $trigger.Repetition.StopAtDurationEnd
                                            }
                                        }
                                        
                                        $taskData.Triggers += $triggerData
                                    }
                                }
                                
                                $scheduledTasks += $taskData
                            }
                            catch {
                                Write-Debug "Error processing task $($task.TaskName): $_"
                            }
                        }
                    }
                    catch {
                        Write-Debug "Error processing scheduled task: $_"
                    }
                }
                
                $gatheredData.ScheduledTasks = $scheduledTasks
                Write-Verbose "Collected $($scheduledTasks.Count) non-Microsoft scheduled tasks"
            }
            catch {
                $errorMessage = "Failed to gather scheduled tasks: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            # Gather all network shares
            try {
                Write-Debug "Collecting network shares..."
                $shares = @()
                
                # Get SMB shares using Get-SmbShare
                $smbShares = Get-SmbShare -ErrorAction SilentlyContinue
                
                foreach ($share in $smbShares) {
                    try {
                        $shareInfo = [PSCustomObject]@{
                            Name = $share.Name
                            Path = $share.Path
                            Description = $share.Description
                            ShareType = $share.ShareType.ToString()
                            ShareState = $share.ShareState.ToString()
                            AvailabilityType = $share.AvailabilityType.ToString()
                            ScopeName = $share.ScopeName
                            FolderEnumerationMode = $share.FolderEnumerationMode.ToString()
                            ContinuouslyAvailable = $share.ContinuouslyAvailable
                            EncryptData = $share.EncryptData
                            CachingMode = $share.CachingMode.ToString()
                            ConcurrentUserLimit = $share.ConcurrentUserLimit
                            AccessPermissions = @()
                        }
                        
                        # Get share access permissions
                        try {
                            $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                            foreach ($access in $shareAccess) {
                                $shareInfo.AccessPermissions += [PSCustomObject]@{
                                    AccountName = $access.AccountName
                                    AccessRight = $access.AccessRight.ToString()
                                    AccessControlType = $access.AccessControlType.ToString()
                                }
                            }
                        }
                        catch {
                            Write-Debug "Could not retrieve access permissions for share $($share.Name): $_"
                        }
                        
                        $shares += $shareInfo
                    }
                    catch {
                        Write-Debug "Error processing share $($share.Name): $_"
                    }
                }
                
                $gatheredData.Shares = $shares
                Write-Verbose "Collected $($shares.Count) network shares"
            }
            catch {
                $errorMessage = "Failed to gather network shares: $_"
                Write-Warning $errorMessage
                $errors += $errorMessage
            }

            Write-Verbose "Data gathering modules will be expanded in future updates..."

        }
        catch {
            $errorMessage = "Critical error during data gathering: $_"
            Write-Error $errorMessage
            $errors += $errorMessage
            throw
        }
    }

    end {
        try {
            # Add any errors encountered to the output
            if ($errors.Count -gt 0) {
                $gatheredData | Add-Member -MemberType NoteProperty -Name 'Errors' -Value $errors -Force
            }

            # Handle output based on format and path
            if ($OutputPath) {
                Write-Verbose "Saving results to: $OutputPath"
                
                switch ($OutputFormat) {
                    'Json' {
                        $gatheredData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                        Write-Verbose "Results saved as JSON to: $OutputPath"
                    }
                    'Xml' {
                        $gatheredData | Export-Clixml -Path $OutputPath
                        Write-Verbose "Results saved as XML to: $OutputPath"
                    }
                    'Object' {
                        $gatheredData | Export-Clixml -Path $OutputPath
                        Write-Verbose "Results saved as PowerShell object to: $OutputPath"
                    }
                }
                
                return $gatheredData
            }
            else {
                # Return object directly
                return $gatheredData
            }
        }
        catch {
            Write-Error "Failed to process output: $_"
            throw
        }
    }
}
