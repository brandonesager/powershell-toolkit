#Requires -Version 5.1
<#
.SYNOPSIS
    Client-side RDP connectivity diagnostic script for RMM deployment

.DESCRIPTION
    Performs comprehensive client-side diagnostics for RDP connectivity issues.
    Tests DNS, network connectivity, VPN, RDP client config, credentials, firewall,
    event logs, proxy settings, certificates, Group Policy, and network quality.

    Enumerates all user profiles on the machine to check per-user RDP cache and
    configuration rather than relying on SYSTEM-context environment variables.

.PARAMETER TargetComputer
    The remote computer to test RDP connectivity to

.EXAMPLE
    .\Get-RDPClientDiagnostics.ps1 -TargetComputer "WORKSTATION01"

.EXAMPLE
    .\Get-RDPClientDiagnostics.ps1 -TargetComputer "SERVER01"

.NOTES
    Category: Diagnostics

    Exit Codes:
        0 = Client can successfully reach server on port 3389 (issue likely server-side)
        1 = Client has connectivity issues preventing RDP connection
        2 = Script execution error

    Log File: C:\ProgramData\RMM\Logs\RDP-Client-Diagnostics.log
    Report File: C:\Temp\RDP-Client-Diagnostics-Report.txt

.KEYWORDS
    RDP, diagnose, connectivity, RMM, SYSTEM
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TargetComputer
)

$ErrorActionPreference = "Stop"

# Script configuration
$LogPath = "C:\ProgramData\RMM\Logs\RDP-Client-Diagnostics.log"
$ReportPath = "C:\Temp\RDP-Client-Diagnostics-Report.txt"
$LogDir = Split-Path $LogPath -Parent
$ReportDir = Split-Path $ReportPath -Parent

# Global findings collection
$Global:Findings = @()
$Global:DiagnosticStartTime = Get-Date

# Ensure directories exist
foreach ($dir in @($LogDir, $ReportDir)) {
    if (-not (Test-Path $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Error "Failed to create directory: $dir"
            exit 2
        }
    }
}

#region Helper Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped log entries to log file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] - $Message"

    try {
        $LogEntry | Out-File -FilePath $LogPath -Append -ErrorAction Stop
    } catch {
        Write-Error "Failed to write to log file: $_"
    }
}

function Add-Finding {
    <#
    .SYNOPSIS
        Adds a diagnostic finding to the global findings collection
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Critical", "Warning", "Info")]
        [string]$Severity,

        [Parameter(Mandatory=$true)]
        [string]$Category,

        [Parameter(Mandatory=$true)]
        [string]$Finding,

        [Parameter(Mandatory=$false)]
        [string]$Details = "",

        [Parameter(Mandatory=$false)]
        [string]$Recommendation = ""
    )

    $Global:Findings += [PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Finding = $Finding
        Details = $Details
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }

    Write-Log "$Severity - $Category - $Finding" $Severity.ToUpper()
}

#endregion

#region Diagnostic Functions

function Test-DNSResolution {
    <#
    .SYNOPSIS
        Tests DNS resolution for target computer
    #>
    param([string]$Target)

    Write-Log "Starting DNS Resolution diagnostics for $Target"

    try {
        # Test DNS resolution
        try {
            $DnsResult = Resolve-DnsName -Name $Target -ErrorAction Stop

            if ($DnsResult) {
                $IPAddress = ($DnsResult | Where-Object {$_.Type -eq 'A'}).IPAddress
                Add-Finding -Severity "Info" -Category "DNS Resolution" `
                    -Finding "Successfully resolved $Target" `
                    -Details "IP Address: $IPAddress"

                # Test reverse DNS
                try {
                    $ReverseDns = Resolve-DnsName -Name $IPAddress -ErrorAction SilentlyContinue
                    if ($ReverseDns) {
                        Add-Finding -Severity "Info" -Category "DNS Resolution" `
                            -Finding "Reverse DNS lookup successful" `
                            -Details "PTR record: $($ReverseDns.NameHost)"
                    }
                } catch {
                    Add-Finding -Severity "Info" -Category "DNS Resolution" `
                        -Finding "Reverse DNS lookup not available" `
                        -Details "This is typically not critical for RDP"
                }
            }
        } catch {
            Add-Finding -Severity "Critical" -Category "DNS Resolution" `
                -Finding "Failed to resolve hostname $Target" `
                -Details "Error: $($_.Exception.Message)" `
                -Recommendation "Verify DNS server configuration and ensure target computer name is correct"
            return
        }

        # Check hosts file for overrides
        try {
            $HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
            if (Test-Path $HostsFile) {
                $HostsContent = Get-Content $HostsFile -ErrorAction Stop
                $HostsEntry = $HostsContent | Where-Object {$_ -match $Target -and $_ -notmatch '^#'}

                if ($HostsEntry) {
                    Add-Finding -Severity "Warning" -Category "DNS Resolution" `
                        -Finding "Hosts file override detected for $Target" `
                        -Details "Entry: $HostsEntry" `
                        -Recommendation "Review hosts file entry to ensure it's correct and intentional"
                } else {
                    Add-Finding -Severity "Info" -Category "DNS Resolution" `
                        -Finding "No hosts file overrides found" `
                        -Details "DNS resolution is using standard DNS servers"
                }
            }
        } catch {
            Write-Log "Could not read hosts file: $($_.Exception.Message)" "WARNING"
        }

        # Check DNS server configuration
        try {
            $DnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 |
                Where-Object {$_.ServerAddresses.Count -gt 0}

            if ($DnsServers) {
                $DnsServerList = ($DnsServers | ForEach-Object {
                    "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')"
                }) -join '; '

                Add-Finding -Severity "Info" -Category "DNS Resolution" `
                    -Finding "DNS server configuration retrieved" `
                    -Details $DnsServerList
            }
        } catch {
            Write-Log "Could not retrieve DNS server configuration: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Add-Finding -Severity "Critical" -Category "DNS Resolution" `
            -Finding "DNS diagnostics failed" `
            -Details "Error: $($_.Exception.Message)" `
            -Recommendation "Review error details and check DNS client service status"
        Write-Log "DNS Resolution test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to target computer
    #>
    param([string]$Target)

    Write-Log "Starting Network Connectivity diagnostics for $Target"

    try {
        # Ping test
        try {
            $PingResult = Test-Connection -ComputerName $Target -Count 4 -ErrorAction Stop

            $SuccessCount = ($PingResult | Where-Object {$_.StatusCode -eq 0}).Count
            $AvgResponseTime = ($PingResult | Measure-Object -Property ResponseTime -Average).Average

            if ($SuccessCount -eq 4) {
                Add-Finding -Severity "Info" -Category "Network Connectivity" `
                    -Finding "Ping test successful (4/4 packets)" `
                    -Details "Average response time: $([math]::Round($AvgResponseTime, 2))ms"
            } elseif ($SuccessCount -gt 0) {
                $PacketLoss = ((4 - $SuccessCount) / 4) * 100
                Add-Finding -Severity "Warning" -Category "Network Connectivity" `
                    -Finding "Partial packet loss detected" `
                    -Details "Success: $SuccessCount/4 packets, Packet Loss: $PacketLoss%, Avg RTT: $([math]::Round($AvgResponseTime, 2))ms" `
                    -Recommendation "Investigate network stability issues"
            } else {
                Add-Finding -Severity "Critical" -Category "Network Connectivity" `
                    -Finding "All ping packets lost" `
                    -Details "0/4 packets received" `
                    -Recommendation "Check network connectivity, firewall rules, and verify target is online"
            }

            # Check latency
            if ($AvgResponseTime -gt 150) {
                Add-Finding -Severity "Warning" -Category "Network Connectivity" `
                    -Finding "High network latency detected" `
                    -Details "Average RTT: $([math]::Round($AvgResponseTime, 2))ms (>150ms threshold)" `
                    -Recommendation "RDP may be slow or unresponsive due to high latency"
            }

        } catch {
            Add-Finding -Severity "Critical" -Category "Network Connectivity" `
                -Finding "Cannot ping target computer" `
                -Details "Error: $($_.Exception.Message)" `
                -Recommendation "Verify network connectivity and firewall configuration"
        }

        # Test RDP port connectivity
        try {
            Write-Log "Testing TCP port 3389 connectivity to $Target"
            $PortTest = Test-NetConnection -ComputerName $Target -Port 3389 -ErrorAction Stop -WarningAction SilentlyContinue

            if ($PortTest.TcpTestSucceeded) {
                Add-Finding -Severity "Info" -Category "Network Connectivity" `
                    -Finding "RDP port 3389 is reachable" `
                    -Details "TCP connection successful to $($PortTest.RemoteAddress):3389"
            } else {
                Add-Finding -Severity "Critical" -Category "Network Connectivity" `
                    -Finding "RDP port 3389 is not reachable" `
                    -Details "TCP connection failed" `
                    -Recommendation "Verify RDP service is running on target and firewall allows port 3389"
            }
        } catch {
            Add-Finding -Severity "Critical" -Category "Network Connectivity" `
                -Finding "Port connectivity test failed" `
                -Details "Error: $($_.Exception.Message)" `
                -Recommendation "Check network configuration and firewall settings"
        }

        # Traceroute (limited to 15 hops for RMM context)
        try {
            Write-Log "Running traceroute to $Target (max 15 hops)"
            $TraceResult = Test-NetConnection -ComputerName $Target -TraceRoute -Hops 15 -ErrorAction Stop -WarningAction SilentlyContinue

            if ($TraceResult.TraceRoute) {
                $HopCount = $TraceResult.TraceRoute.Count
                Add-Finding -Severity "Info" -Category "Network Connectivity" `
                    -Finding "Traceroute completed" `
                    -Details "Reached target in $HopCount hops: $($TraceResult.TraceRoute -join ' -> ')"
            }
        } catch {
            Write-Log "Traceroute test failed (non-critical): $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Add-Finding -Severity "Critical" -Category "Network Connectivity" `
            -Finding "Network connectivity diagnostics failed" `
            -Details "Error: $($_.Exception.Message)"
        Write-Log "Network Connectivity test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-VPNStatus {
    <#
    .SYNOPSIS
        Tests VPN connection status and configuration
    #>

    Write-Log "Starting VPN Status diagnostics"

    try {
        # Check for VPN connections
        try {
            $VpnConnections = Get-VpnConnection -ErrorAction Stop

            if ($VpnConnections) {
                $ConnectedVpns = $VpnConnections | Where-Object {$_.ConnectionStatus -eq 'Connected'}

                if ($ConnectedVpns) {
                    foreach ($Vpn in $ConnectedVpns) {
                        Add-Finding -Severity "Info" -Category "VPN Status" `
                            -Finding "VPN connection active: $($Vpn.Name)" `
                            -Details "Server: $($Vpn.ServerAddress), Status: $($Vpn.ConnectionStatus)"
                    }
                } else {
                    $DisconnectedVpns = $VpnConnections | Select-Object -ExpandProperty Name
                    Add-Finding -Severity "Warning" -Category "VPN Status" `
                        -Finding "VPN configured but not connected" `
                        -Details "Available VPNs: $($DisconnectedVpns -join ', ')" `
                        -Recommendation "If remote access requires VPN, connect before attempting RDP"
                }

                # Check split tunneling
                foreach ($Vpn in $VpnConnections) {
                    if ($Vpn.SplitTunneling -eq $true) {
                        Add-Finding -Severity "Warning" -Category "VPN Status" `
                            -Finding "Split tunneling enabled on $($Vpn.Name)" `
                            -Details "Not all traffic routes through VPN" `
                            -Recommendation "Verify target computer is accessible via split tunnel configuration"
                    }
                }
            } else {
                Add-Finding -Severity "Info" -Category "VPN Status" `
                    -Finding "No VPN connections configured" `
                    -Details "Direct network connectivity is being used"
            }
        } catch {
            Write-Log "Could not retrieve VPN connections: $($_.Exception.Message)" "WARNING"
        }

        # Check VPN-related routes
        try {
            $Routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.RouteMetric -lt 300}

            if ($Routes) {
                $RouteCount = $Routes.Count
                Add-Finding -Severity "Info" -Category "VPN Status" `
                    -Finding "Active IPv4 routes detected" `
                    -Details "Found $RouteCount routes with metrics < 300"
            }
        } catch {
            Write-Log "Could not retrieve routing table: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "VPN Status test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-RDPClient {
    <#
    .SYNOPSIS
        Tests RDP client application and cache
    #>

    Write-Log "Starting RDP Client diagnostics"

    try {
        # Check mstsc.exe
        try {
            $MstscPath = "$env:SystemRoot\System32\mstsc.exe"
            if (Test-Path $MstscPath) {
                $MstscVersion = (Get-Item $MstscPath -ErrorAction Stop).VersionInfo.FileVersion
                Add-Finding -Severity "Info" -Category "RDP Client" `
                    -Finding "mstsc.exe found" `
                    -Details "Version: $MstscVersion, Path: $MstscPath"
            } else {
                Add-Finding -Severity "Critical" -Category "RDP Client" `
                    -Finding "mstsc.exe not found" `
                    -Details "Expected location: $MstscPath" `
                    -Recommendation "RDP client may be corrupted - run SFC /scannow"
            }
        } catch {
            Write-Log "Could not check mstsc.exe: $($_.Exception.Message)" "WARNING"
        }

        # Check Windows Remote Desktop app (modern app)
        try {
            $RdpApp = Get-AppxPackage -Name "Microsoft.RemoteDesktop*" -ErrorAction SilentlyContinue
            if ($RdpApp) {
                Add-Finding -Severity "Info" -Category "RDP Client" `
                    -Finding "Windows Remote Desktop app installed" `
                    -Details "Version: $($RdpApp.Version)"
            }
        } catch {
            Write-Log "Could not check Remote Desktop app: $($_.Exception.Message)" "WARNING"
        }

        # Check RDP client cache across all user profiles
        try {
            $UserProfiles = Get-ChildItem 'C:\Users' -Directory |
                Where-Object { $_.Name -notin 'Public','Default','Default User' }

            foreach ($profile in $UserProfiles) {
                $CachePath = Join-Path $profile.FullName 'AppData\Local\Microsoft\Terminal Server Client\Cache'
                if (Test-Path $CachePath) {
                    $CacheFiles = Get-ChildItem -Path $CachePath -File -ErrorAction SilentlyContinue
                    $CacheSize = ($CacheFiles | Measure-Object -Property Length -Sum).Sum

                    Add-Finding -Severity "Info" -Category "RDP Client" `
                        -Finding "RDP cache directory exists for $($profile.Name)" `
                        -Details "Files: $($CacheFiles.Count), Size: $([math]::Round($CacheSize/1KB, 2)) KB"

                    if ($CacheSize -gt 50MB) {
                        Add-Finding -Severity "Warning" -Category "RDP Client" `
                            -Finding "RDP cache is unusually large for $($profile.Name)" `
                            -Details "Cache size: $([math]::Round($CacheSize/1MB, 2)) MB" `
                            -Recommendation "Consider clearing RDP cache: Delete contents of $CachePath"
                    }
                }
            }
        } catch {
            Write-Log "Could not check RDP cache: $($_.Exception.Message)" "WARNING"
        }

        # Check Default.rdp file across all user profiles
        try {
            $UserProfiles = Get-ChildItem 'C:\Users' -Directory |
                Where-Object { $_.Name -notin 'Public','Default','Default User' }

            foreach ($profile in $UserProfiles) {
                $DefaultRdpPath = Join-Path $profile.FullName 'Documents\Default.rdp'
                if (Test-Path $DefaultRdpPath) {
                    $RdpContent = Get-Content $DefaultRdpPath -ErrorAction SilentlyContinue
                    $ServerEntry = $RdpContent | Where-Object {$_ -match '^full address:s:'}

                    Add-Finding -Severity "Info" -Category "RDP Client" `
                        -Finding "Default.rdp file exists for $($profile.Name)" `
                        -Details "Last saved connection: $ServerEntry"
                }
            }
        } catch {
            Write-Log "Could not check Default.rdp: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "RDP Client test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-CredentialManager {
    <#
    .SYNOPSIS
        Tests cached credentials for target computer
    #>
    param([string]$Target)

    Write-Log "Starting Credential Manager diagnostics"

    try {
        # Check cached credentials using cmdkey
        try {
            $CmdKeyOutput = cmdkey /list 2>&1

            if ($CmdKeyOutput -match $Target) {
                $MatchingLines = $CmdKeyOutput | Where-Object {$_ -match $Target}
                Add-Finding -Severity "Warning" -Category "Credential Manager" `
                    -Finding "Cached credentials found for $Target" `
                    -Details "$($MatchingLines -join '; ')" `
                    -Recommendation "If credentials have changed, delete cached credentials: cmdkey /delete:TERMSRV/$Target"
            } else {
                Add-Finding -Severity "Info" -Category "Credential Manager" `
                    -Finding "No cached credentials found for $Target" `
                    -Details "User will be prompted for credentials when connecting"
            }

            # Check for generic TERMSRV credentials
            $TermsrvCreds = $CmdKeyOutput | Where-Object {$_ -match 'TERMSRV/'}
            if ($TermsrvCreds) {
                $CredCount = ($TermsrvCreds | Measure-Object).Count
                Add-Finding -Severity "Info" -Category "Credential Manager" `
                    -Finding "Found $CredCount RDP credential entries" `
                    -Details "Total TERMSRV credentials cached"
            }
        } catch {
            Write-Log "Could not retrieve credential list: $($_.Exception.Message)" "WARNING"
        }

        # Check Windows Credential Manager via registry
        try {
            $CredRegPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
            if (Test-Path $CredRegPath) {
                $SavedServers = Get-ChildItem -Path $CredRegPath -ErrorAction Stop
                if ($SavedServers) {
                    $ServerNames = $SavedServers | Select-Object -ExpandProperty PSChildName
                    Add-Finding -Severity "Info" -Category "Credential Manager" `
                        -Finding "RDP connection history found" `
                        -Details "Previously connected servers: $($ServerNames -join ', ')"
                }
            }
        } catch {
            Write-Log "Could not check RDP connection history: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Credential Manager test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ClientFirewall {
    <#
    .SYNOPSIS
        Tests client-side firewall configuration for RDP
    #>

    Write-Log "Starting Client Firewall diagnostics"

    try {
        # Check Windows Firewall status
        try {
            $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

            foreach ($Profile in $FirewallProfiles) {
                if ($Profile.Enabled) {
                    Add-Finding -Severity "Info" -Category "Client Firewall" `
                        -Finding "$($Profile.Name) firewall profile is enabled" `
                        -Details "Default outbound action: $($Profile.DefaultOutboundAction)"

                    if ($Profile.DefaultOutboundAction -eq 'Block') {
                        Add-Finding -Severity "Critical" -Category "Client Firewall" `
                            -Finding "$($Profile.Name) profile blocks outbound traffic by default" `
                            -Details "This may prevent RDP client connections" `
                            -Recommendation "Review firewall rules to ensure RDP client traffic is allowed"
                    }
                } else {
                    Add-Finding -Severity "Warning" -Category "Client Firewall" `
                        -Finding "$($Profile.Name) firewall profile is disabled" `
                        -Details "This profile is not actively filtering traffic"
                }
            }
        } catch {
            Write-Log "Could not retrieve firewall profiles: $($_.Exception.Message)" "WARNING"
        }

        # Check for RDP outbound rules
        try {
            $RdpOutboundRules = Get-NetFirewallRule -Direction Outbound -ErrorAction Stop |
                Where-Object {$_.DisplayName -match 'Remote Desktop' -or $_.DisplayName -match 'RDP'}

            if ($RdpOutboundRules) {
                foreach ($Rule in $RdpOutboundRules) {
                    $Action = if ($Rule.Enabled) { $Rule.Action } else { "Disabled" }
                    Add-Finding -Severity "Info" -Category "Client Firewall" `
                        -Finding "Outbound RDP rule found: $($Rule.DisplayName)" `
                        -Details "Action: $Action, Enabled: $($Rule.Enabled)"

                    if ($Rule.Enabled -and $Rule.Action -eq 'Block') {
                        Add-Finding -Severity "Critical" -Category "Client Firewall" `
                            -Finding "Outbound RDP traffic is blocked" `
                            -Details "Rule: $($Rule.DisplayName)" `
                            -Recommendation "Disable blocking rule or modify firewall configuration"
                    }
                }
            } else {
                Add-Finding -Severity "Info" -Category "Client Firewall" `
                    -Finding "No specific outbound RDP firewall rules found" `
                    -Details "Using default outbound policy"
            }
        } catch {
            Write-Log "Could not retrieve firewall rules: $($_.Exception.Message)" "WARNING"
        }

        # Check for third-party firewall
        try {
            $ThirdPartyFirewalls = @(
                'HKLM:\SOFTWARE\CheckPoint\ZoneAlarm',
                'HKLM:\SOFTWARE\Comodo\Firewall',
                'HKLM:\SOFTWARE\McAfee\Firewall',
                'HKLM:\SOFTWARE\Norton\Firewall',
                'HKLM:\SOFTWARE\Panda Security\Panda Security Firewall'
            )

            foreach ($FwPath in $ThirdPartyFirewalls) {
                if (Test-Path $FwPath) {
                    $FwName = ($FwPath -split '\\')[-1]
                    Add-Finding -Severity "Warning" -Category "Client Firewall" `
                        -Finding "Third-party firewall detected: $FwName" `
                        -Details "Registry path: $FwPath" `
                        -Recommendation "Verify third-party firewall allows outbound RDP connections"
                }
            }
        } catch {
            Write-Log "Could not check for third-party firewalls: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Client Firewall test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-NetworkConfiguration {
    <#
    .SYNOPSIS
        Tests network adapter and IP configuration
    #>

    Write-Log "Starting Network Configuration diagnostics"

    try {
        # Get IP configuration
        try {
            $NetAdapters = Get-NetIPConfiguration -ErrorAction Stop |
                Where-Object {$_.IPv4Address.Count -gt 0}

            foreach ($Adapter in $NetAdapters) {
                $IPv4 = $Adapter.IPv4Address.IPAddress
                $Gateway = if ($Adapter.IPv4DefaultGateway) { $Adapter.IPv4DefaultGateway.NextHop } else { "None" }
                $DnsServers = if ($Adapter.DNSServer) { ($Adapter.DNSServer.ServerAddresses -join ', ') } else { "None" }

                Add-Finding -Severity "Info" -Category "Network Configuration" `
                    -Finding "Active adapter: $($Adapter.InterfaceAlias)" `
                    -Details "IPv4: $IPv4, Gateway: $Gateway, DNS: $DnsServers"

                # Check for missing gateway
                if ($Gateway -eq "None" -and $Adapter.InterfaceAlias -notmatch 'Loopback') {
                    Add-Finding -Severity "Warning" -Category "Network Configuration" `
                        -Finding "No default gateway configured on $($Adapter.InterfaceAlias)" `
                        -Details "This may prevent communication with remote networks" `
                        -Recommendation "Configure default gateway for network connectivity"
                }

                # Check for missing DNS
                if ($DnsServers -eq "None") {
                    Add-Finding -Severity "Warning" -Category "Network Configuration" `
                        -Finding "No DNS servers configured on $($Adapter.InterfaceAlias)" `
                        -Details "This will prevent hostname resolution" `
                        -Recommendation "Configure DNS servers"
                }
            }

            if (-not $NetAdapters) {
                Add-Finding -Severity "Critical" -Category "Network Configuration" `
                    -Finding "No active network adapters with IPv4 configuration" `
                    -Details "Cannot establish network connectivity" `
                    -Recommendation "Check network adapter status and configuration"
            }
        } catch {
            Add-Finding -Severity "Critical" -Category "Network Configuration" `
                -Finding "Failed to retrieve network configuration" `
                -Details "Error: $($_.Exception.Message)" `
                -Recommendation "Check network adapter status"
            Write-Log "Network configuration retrieval failed: $($_.Exception.Message)" "ERROR"
        }

        # Get adapter status
        try {
            $Adapters = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -ne 'Disabled'}

            foreach ($Adapter in $Adapters) {
                $StatusSeverity = if ($Adapter.Status -eq 'Up') { "Info" } else { "Warning" }
                Add-Finding -Severity $StatusSeverity -Category "Network Configuration" `
                    -Finding "Adapter $($Adapter.Name): $($Adapter.Status)" `
                    -Details "Interface: $($Adapter.InterfaceDescription), Link Speed: $($Adapter.LinkSpeed)"
            }
        } catch {
            Write-Log "Could not retrieve adapter status: $($_.Exception.Message)" "WARNING"
        }

        # Check routing table for default route
        try {
            $DefaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Select-Object -First 1

            if ($DefaultRoute) {
                Add-Finding -Severity "Info" -Category "Network Configuration" `
                    -Finding "Default route configured" `
                    -Details "Next hop: $($DefaultRoute.NextHop), Interface: $($DefaultRoute.InterfaceAlias), Metric: $($DefaultRoute.RouteMetric)"
            } else {
                Add-Finding -Severity "Critical" -Category "Network Configuration" `
                    -Finding "No default route configured" `
                    -Details "Cannot route traffic to remote networks" `
                    -Recommendation "Configure default gateway"
            }
        } catch {
            Write-Log "Could not check routing table: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Network Configuration test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ClientEventLogs {
    <#
    .SYNOPSIS
        Tests client event logs for RDP-related errors
    #>
    param([string]$Target)

    Write-Log "Starting Client Event Log diagnostics"

    try {
        $StartTime = (Get-Date).AddHours(-24)

        # Check RemoteDesktop-Client events
        try {
            $RdpClientEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-TerminalServices-ClientActiveXCore/Operational'
                StartTime = $StartTime
            } -MaxEvents 50 -ErrorAction SilentlyContinue

            if ($RdpClientEvents) {
                $ErrorEvents = $RdpClientEvents | Where-Object {$_.LevelDisplayName -eq 'Error'}
                $WarningEvents = $RdpClientEvents | Where-Object {$_.LevelDisplayName -eq 'Warning'}

                Add-Finding -Severity "Info" -Category "Client Event Logs" `
                    -Finding "RDP Client events found (last 24h)" `
                    -Details "Total: $($RdpClientEvents.Count), Errors: $($ErrorEvents.Count), Warnings: $($WarningEvents.Count)"

                # Report recent errors
                foreach ($Event in ($ErrorEvents | Select-Object -First 5)) {
                    Add-Finding -Severity "Warning" -Category "Client Event Logs" `
                        -Finding "RDP Client error detected" `
                        -Details "Event ID: $($Event.Id), Time: $($Event.TimeCreated), Message: $($Event.Message.Substring(0, [Math]::Min(200, $Event.Message.Length)))"
                }
            } else {
                Add-Finding -Severity "Info" -Category "Client Event Logs" `
                    -Finding "No recent RDP Client events found" `
                    -Details "No connection attempts in last 24 hours"
            }
        } catch {
            Write-Log "Could not retrieve RDP Client events: $($_.Exception.Message)" "WARNING"
        }

        # Check for explicit credential logon attempts (Event ID 4648)
        try {
            $CredEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4648
                StartTime = $StartTime
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($CredEvents) {
                $RdpCredEvents = $CredEvents | Where-Object {$_.Message -match $Target}

                if ($RdpCredEvents) {
                    Add-Finding -Severity "Info" -Category "Client Event Logs" `
                        -Finding "Credential logon attempts to $Target detected" `
                        -Details "Found $($RdpCredEvents.Count) attempts in last 24 hours"
                }
            }
        } catch {
            Write-Log "Could not retrieve Security event log (requires admin rights): $($_.Exception.Message)" "WARNING"
        }

        # Check Application log for RDP errors
        try {
            $AppEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ProviderName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'
                StartTime = $StartTime
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($AppEvents) {
                $ErrorEvents = $AppEvents | Where-Object {$_.LevelDisplayName -eq 'Error'}

                foreach ($Event in ($ErrorEvents | Select-Object -First 3)) {
                    Add-Finding -Severity "Warning" -Category "Client Event Logs" `
                        -Finding "RDP Core error in Application log" `
                        -Details "Event ID: $($Event.Id), Time: $($Event.TimeCreated), Message: $($Event.Message.Substring(0, [Math]::Min(150, $Event.Message.Length)))"
                }
            }
        } catch {
            Write-Log "Could not retrieve Application events: $($_.Exception.Message)" "WARNING"
        }

        # Check for certificate validation errors
        try {
            $CertEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Schannel'
                StartTime = $StartTime
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($CertEvents) {
                $CertErrors = $CertEvents | Where-Object {$_.LevelDisplayName -eq 'Error'}

                if ($CertErrors) {
                    Add-Finding -Severity "Warning" -Category "Client Event Logs" `
                        -Finding "Certificate validation errors detected" `
                        -Details "Found $($CertErrors.Count) Schannel errors in last 24 hours" `
                        -Recommendation "This may indicate certificate trust issues with RDP server"
                }
            }
        } catch {
            Write-Log "Could not retrieve Schannel events: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Client Event Log test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ProxyConfiguration {
    <#
    .SYNOPSIS
        Tests proxy configuration that may interfere with RDP
    #>

    Write-Log "Starting Proxy Configuration diagnostics"

    try {
        # Check IE/System proxy settings
        try {
            $ProxyRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxyEnabled = (Get-ItemProperty -Path $ProxyRegPath -Name ProxyEnable -ErrorAction Stop).ProxyEnable

            if ($ProxyEnabled -eq 1) {
                $ProxyServer = (Get-ItemProperty -Path $ProxyRegPath -Name ProxyServer -ErrorAction Stop).ProxyServer
                $ProxyOverride = (Get-ItemProperty -Path $ProxyRegPath -Name ProxyOverride -ErrorAction SilentlyContinue).ProxyOverride

                Add-Finding -Severity "Warning" -Category "Proxy Configuration" `
                    -Finding "System proxy is enabled" `
                    -Details "Proxy: $ProxyServer, Bypass: $ProxyOverride" `
                    -Recommendation "RDP should not use proxy, but verify proxy bypass list includes local addresses"
            } else {
                Add-Finding -Severity "Info" -Category "Proxy Configuration" `
                    -Finding "System proxy is disabled" `
                    -Details "Direct network connections are used"
            }
        } catch {
            Write-Log "Could not check IE proxy settings: $($_.Exception.Message)" "WARNING"
        }

        # Check WinHTTP proxy
        try {
            $WinHttpProxy = netsh winhttp show proxy 2>&1

            if ($WinHttpProxy -match 'Direct access') {
                Add-Finding -Severity "Info" -Category "Proxy Configuration" `
                    -Finding "WinHTTP proxy: Direct access" `
                    -Details "No WinHTTP proxy configured"
            } else {
                $ProxyLine = $WinHttpProxy | Where-Object {$_ -match 'Proxy Server'}
                Add-Finding -Severity "Warning" -Category "Proxy Configuration" `
                    -Finding "WinHTTP proxy configured" `
                    -Details "$ProxyLine" `
                    -Recommendation "Verify this does not interfere with RDP connections"
            }
        } catch {
            Write-Log "Could not check WinHTTP proxy: $($_.Exception.Message)" "WARNING"
        }

        # Check environment variables
        try {
            $HttpProxy = [System.Environment]::GetEnvironmentVariable('HTTP_PROXY', 'User')
            $HttpsProxy = [System.Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'User')

            if ($HttpProxy -or $HttpsProxy) {
                Add-Finding -Severity "Warning" -Category "Proxy Configuration" `
                    -Finding "Proxy environment variables detected" `
                    -Details "HTTP_PROXY: $HttpProxy, HTTPS_PROXY: $HttpsProxy" `
                    -Recommendation "These may affect some applications but should not impact RDP"
            }
        } catch {
            Write-Log "Could not check proxy environment variables: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Proxy Configuration test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-CertificateTrust {
    <#
    .SYNOPSIS
        Tests for certificate trust issues
    #>
    param([string]$Target)

    Write-Log "Starting Certificate Trust diagnostics"

    try {
        # Check for certificate warnings in event logs (covered in event log check)
        # Check RDP certificate configuration
        try {
            $RdpCertPath = "HKCU:\Software\Microsoft\Terminal Server Client\LocalDevices"
            if (Test-Path $RdpCertPath) {
                $CertEntries = Get-ChildItem -Path $RdpCertPath -ErrorAction SilentlyContinue
                if ($CertEntries) {
                    Add-Finding -Severity "Info" -Category "Certificate Trust" `
                        -Finding "RDP certificate trust data found" `
                        -Details "Certificates stored for $($CertEntries.Count) servers"
                }
            }
        } catch {
            Write-Log "Could not check RDP certificate registry: $($_.Exception.Message)" "WARNING"
        }

        # Check for certificate errors in recent events
        try {
            $CertErrorEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Schannel'
                StartTime = (Get-Date).AddHours(-24)
                Level = 2  # Error
            } -MaxEvents 10 -ErrorAction SilentlyContinue

            if ($CertErrorEvents) {
                Add-Finding -Severity "Warning" -Category "Certificate Trust" `
                    -Finding "Recent certificate validation errors detected" `
                    -Details "Found $($CertErrorEvents.Count) Schannel errors in last 24 hours" `
                    -Recommendation "May indicate untrusted or expired certificates on RDP server"

                foreach ($Event in ($CertErrorEvents | Select-Object -First 2)) {
                    Write-Log "Certificate error: Event ID $($Event.Id) - $($Event.Message.Substring(0, [Math]::Min(150, $Event.Message.Length)))" "WARNING"
                }
            } else {
                Add-Finding -Severity "Info" -Category "Certificate Trust" `
                    -Finding "No recent certificate validation errors" `
                    -Details "No Schannel errors in last 24 hours"
            }
        } catch {
            Write-Log "Could not check for certificate errors: $($_.Exception.Message)" "WARNING"
        }

        # Check certificate stores
        try {
            $PersonalCerts = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue
            $TrustedCerts = Get-ChildItem -Path Cert:\CurrentUser\Root -ErrorAction SilentlyContinue

            Add-Finding -Severity "Info" -Category "Certificate Trust" `
                -Finding "Certificate store status" `
                -Details "Personal: $($PersonalCerts.Count) certs, Trusted Root: $($TrustedCerts.Count) certs"
        } catch {
            Write-Log "Could not enumerate certificate stores: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Certificate Trust test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ClientGroupPolicy {
    <#
    .SYNOPSIS
        Tests Group Policy settings affecting RDP client
    #>

    Write-Log "Starting Client Group Policy diagnostics"

    try {
        # Check Terminal Services client policies
        try {
            $TsClientPolicyPaths = @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
                'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            )

            foreach ($Path in $TsClientPolicyPaths) {
                if (Test-Path $Path) {
                    $Policies = Get-ItemProperty -Path $Path -ErrorAction Stop
                    $Scope = if ($Path -match 'HKLM') { 'Computer' } else { 'User' }

                    # Check for policies that block RDP client
                    if ($Policies.fDisableClip -eq 1) {
                        Add-Finding -Severity "Warning" -Category "Client Group Policy" `
                            -Finding "$Scope policy blocks clipboard redirection" `
                            -Details "Registry: $Path\fDisableClip = 1"
                    }

                    if ($Policies.fDisableCdm -eq 1) {
                        Add-Finding -Severity "Warning" -Category "Client Group Policy" `
                            -Finding "$Scope policy blocks drive redirection" `
                            -Details "Registry: $Path\fDisableCdm = 1"
                    }

                    # Check CredSSP settings
                    if ($Policies.PSObject.Properties.Name -contains 'fAllowUnsecuredGuest') {
                        Add-Finding -Severity "Info" -Category "Client Group Policy" `
                            -Finding "$Scope CredSSP policy configured" `
                            -Details "fAllowUnsecuredGuest = $($Policies.fAllowUnsecuredGuest)"
                    }

                    # Report all policies found
                    $PolicyCount = ($Policies.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'}).Count
                    if ($PolicyCount -gt 0) {
                        Add-Finding -Severity "Info" -Category "Client Group Policy" `
                            -Finding "$Scope Terminal Services policies detected" `
                            -Details "Found $PolicyCount policy settings at $Path"
                    }
                }
            }
        } catch {
            Write-Log "Could not check Terminal Services policies: $($_.Exception.Message)" "WARNING"
        }

        # Check CredSSP delegation settings
        try {
            $CredSspPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            if (Test-Path $CredSspPath) {
                $CredSsp = Get-ItemProperty -Path $CredSspPath -ErrorAction Stop

                if ($CredSsp.AllowDefaultCredentials -eq 1) {
                    Add-Finding -Severity "Info" -Category "Client Group Policy" `
                        -Finding "CredSSP default credential delegation enabled" `
                        -Details "Policy allows credential delegation to configured servers"
                }

                if ($CredSsp.AllowFreshCredentials -eq 1) {
                    Add-Finding -Severity "Info" -Category "Client Group Policy" `
                        -Finding "CredSSP fresh credential delegation enabled" `
                        -Details "Policy allows fresh credentials to configured servers"
                }
            }
        } catch {
            Write-Log "Could not check CredSSP policies: $($_.Exception.Message)" "WARNING"
        }

        # Check for RDP client restrictions
        try {
            $RdpRestrictionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktop'
            if (Test-Path $RdpRestrictionPath) {
                $RdpRestrictions = Get-ItemProperty -Path $RdpRestrictionPath -ErrorAction Stop

                if ($RdpRestrictions.fBlockRDP -eq 1) {
                    Add-Finding -Severity "Critical" -Category "Client Group Policy" `
                        -Finding "Group Policy blocks RDP client usage" `
                        -Details "Registry: $RdpRestrictionPath\fBlockRDP = 1" `
                        -Recommendation "Contact IT to modify Group Policy or grant exception"
                }
            }
        } catch {
            Write-Log "Could not check RDP restrictions: $($_.Exception.Message)" "WARNING"
        }

        # Check last GPUpdate
        try {
            $GpResultFile = "$env:TEMP\gpresult_temp.txt"
            gpresult /R /SCOPE:USER > $GpResultFile 2>&1

            if (Test-Path $GpResultFile) {
                $GpContent = Get-Content $GpResultFile -ErrorAction Stop
                $LastGpUpdate = $GpContent | Where-Object {$_ -match 'Group Policy was applied'}

                if ($LastGpUpdate) {
                    Add-Finding -Severity "Info" -Category "Client Group Policy" `
                        -Finding "Last Group Policy update" `
                        -Details "$LastGpUpdate"
                }

                Remove-Item -Path $GpResultFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Could not retrieve GPResult: $($_.Exception.Message)" "WARNING"
        }

    } catch {
        Write-Log "Client Group Policy test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-NetworkQuality {
    <#
    .SYNOPSIS
        Tests network quality with extended ping test
    #>
    param([string]$Target)

    Write-Log "Starting Network Quality diagnostics"

    try {
        Write-Log "Running extended ping test (20 packets) to $Target"

        try {
            $PingResults = Test-Connection -ComputerName $Target -Count 20 -ErrorAction Stop

            $SuccessCount = ($PingResults | Where-Object {$_.StatusCode -eq 0}).Count
            $FailCount = 20 - $SuccessCount
            $PacketLoss = ($FailCount / 20) * 100

            if ($SuccessCount -gt 0) {
                $ResponseTimes = ($PingResults | Where-Object {$_.StatusCode -eq 0}).ResponseTime
                $AvgRtt = ($ResponseTimes | Measure-Object -Average).Average
                $MinRtt = ($ResponseTimes | Measure-Object -Minimum).Minimum
                $MaxRtt = ($ResponseTimes | Measure-Object -Maximum).Maximum

                # Calculate jitter (standard deviation)
                $SumSquaredDiff = ($ResponseTimes | ForEach-Object { [Math]::Pow($_ - $AvgRtt, 2) } | Measure-Object -Sum).Sum
                $Jitter = [Math]::Sqrt($SumSquaredDiff / $SuccessCount)

                # Determine severity
                $QualitySeverity = "Info"
                if ($PacketLoss -gt 5 -or $AvgRtt -gt 150 -or $Jitter -gt 50) {
                    $QualitySeverity = "Warning"
                }
                if ($PacketLoss -gt 15 -or $AvgRtt -gt 300) {
                    $QualitySeverity = "Critical"
                }

                Add-Finding -Severity $QualitySeverity -Category "Network Quality" `
                    -Finding "Extended ping test completed" `
                    -Details "Success: $SuccessCount/20, Loss: $([math]::Round($PacketLoss, 1))%, Avg RTT: $([math]::Round($AvgRtt, 2))ms, Min: ${MinRtt}ms, Max: ${MaxRtt}ms, Jitter: $([math]::Round($Jitter, 2))ms"

                # Specific quality warnings
                if ($PacketLoss -gt 5) {
                    Add-Finding -Severity "Warning" -Category "Network Quality" `
                        -Finding "Significant packet loss detected" `
                        -Details "$([math]::Round($PacketLoss, 1))% packet loss (threshold: 5%)" `
                        -Recommendation "Investigate network stability - may cause RDP disconnections"
                }

                if ($AvgRtt -gt 150) {
                    Add-Finding -Severity "Warning" -Category "Network Quality" `
                        -Finding "High average latency" `
                        -Details "$([math]::Round($AvgRtt, 2))ms average RTT (threshold: 150ms)" `
                        -Recommendation "RDP may be slow or laggy due to high latency"
                }

                if ($Jitter -gt 50) {
                    Add-Finding -Severity "Warning" -Category "Network Quality" `
                        -Finding "High network jitter detected" `
                        -Details "$([math]::Round($Jitter, 2))ms jitter (threshold: 50ms)" `
                        -Recommendation "Unstable network connection may cause intermittent RDP issues"
                }

                if ($PacketLoss -eq 0 -and $AvgRtt -lt 50 -and $Jitter -lt 20) {
                    Add-Finding -Severity "Info" -Category "Network Quality" `
                        -Finding "Excellent network quality" `
                        -Details "Low latency, no packet loss, minimal jitter - optimal for RDP"
                }
            } else {
                Add-Finding -Severity "Critical" -Category "Network Quality" `
                    -Finding "100% packet loss" `
                    -Details "All 20 ping packets lost - complete network failure" `
                    -Recommendation "Verify target is online and network connectivity exists"
            }

        } catch {
            Add-Finding -Severity "Critical" -Category "Network Quality" `
                -Finding "Extended ping test failed" `
                -Details "Error: $($_.Exception.Message)" `
                -Recommendation "Verify network connectivity and target availability"
        }

    } catch {
        Write-Log "Network Quality test failed: $($_.Exception.Message)" "ERROR"
    }
}

#endregion

#region Report Generation

function New-DiagnosticReport {
    <#
    .SYNOPSIS
        Generates comprehensive diagnostic report
    #>
    param([string]$Target)

    Write-Log "Generating diagnostic report"

    try {
        $Report = @()
        $Report += "=" * 80
        $Report += "RDP CLIENT CONNECTIVITY DIAGNOSTIC REPORT"
        $Report += "=" * 80
        $Report += ""
        $Report += "Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $Report += "Client Computer: $env:COMPUTERNAME"
        $Report += "Target Computer: $Target"
        $Report += "Current User: $env:USERNAME"
        $Report += "Diagnostic Duration: $((New-TimeSpan -Start $Global:DiagnosticStartTime -End (Get-Date)).TotalSeconds) seconds"
        $Report += ""

        # Executive Summary
        $Report += "=" * 80
        $Report += "EXECUTIVE SUMMARY"
        $Report += "=" * 80
        $Report += ""

        $CriticalCount = ($Global:Findings | Where-Object {$_.Severity -eq 'Critical'}).Count
        $WarningCount = ($Global:Findings | Where-Object {$_.Severity -eq 'Warning'}).Count
        $InfoCount = ($Global:Findings | Where-Object {$_.Severity -eq 'Info'}).Count

        $Report += "Critical Issues: $CriticalCount"
        $Report += "Warnings: $WarningCount"
        $Report += "Informational: $InfoCount"
        $Report += "Total Findings: $($Global:Findings.Count)"
        $Report += ""

        # Connectivity Status
        $CanReachServer = ($Global:Findings | Where-Object {
            $_.Category -eq 'Network Connectivity' -and
            $_.Finding -match 'RDP port 3389 is reachable'
        }).Count -gt 0

        $CanResolveDns = ($Global:Findings | Where-Object {
            $_.Category -eq 'DNS Resolution' -and
            $_.Finding -match 'Successfully resolved'
        }).Count -gt 0

        $Report += "CONNECTIVITY STATUS:"
        $Report += "  DNS Resolution: $(if ($CanResolveDns) { 'SUCCESS' } else { 'FAILED' })"
        $Report += "  RDP Port 3389: $(if ($CanReachServer) { 'REACHABLE' } else { 'UNREACHABLE' })"
        $Report += ""

        if ($CriticalCount -gt 0) {
            $Report += "OVERALL STATUS: CRITICAL - RDP connection will likely fail"
        } elseif ($WarningCount -gt 0) {
            $Report += "OVERALL STATUS: WARNING - RDP may work but with issues"
        } else {
            $Report += "OVERALL STATUS: HEALTHY - Client-side connectivity appears normal"
        }
        $Report += ""

        # Critical Findings
        if ($CriticalCount -gt 0) {
            $Report += "=" * 80
            $Report += "CRITICAL ISSUES (IMMEDIATE ATTENTION REQUIRED)"
            $Report += "=" * 80
            $Report += ""

            $CriticalFindings = $Global:Findings | Where-Object {$_.Severity -eq 'Critical'}
            foreach ($Finding in $CriticalFindings) {
                $Report += "[$($Finding.Category)] $($Finding.Finding)"
                if ($Finding.Details) { $Report += "  Details: $($Finding.Details)" }
                if ($Finding.Recommendation) { $Report += "  Action: $($Finding.Recommendation)" }
                $Report += ""
            }
        }

        # Warnings
        if ($WarningCount -gt 0) {
            $Report += "=" * 80
            $Report += "WARNINGS (REVIEW RECOMMENDED)"
            $Report += "=" * 80
            $Report += ""

            $WarningFindings = $Global:Findings | Where-Object {$_.Severity -eq 'Warning'}
            foreach ($Finding in $WarningFindings) {
                $Report += "[$($Finding.Category)] $($Finding.Finding)"
                if ($Finding.Details) { $Report += "  Details: $($Finding.Details)" }
                if ($Finding.Recommendation) { $Report += "  Recommendation: $($Finding.Recommendation)" }
                $Report += ""
            }
        }

        # Detailed Findings by Category
        $Report += "=" * 80
        $Report += "DETAILED FINDINGS BY CATEGORY"
        $Report += "=" * 80
        $Report += ""

        $Categories = $Global:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object
        foreach ($Category in $Categories) {
            $Report += "-" * 80
            $Report += "$Category"
            $Report += "-" * 80

            $CategoryFindings = $Global:Findings | Where-Object {$_.Category -eq $Category}
            foreach ($Finding in $CategoryFindings) {
                $Report += "  [$($Finding.Severity)] $($Finding.Finding)"
                if ($Finding.Details) { $Report += "    $($Finding.Details)" }
                if ($Finding.Recommendation) { $Report += "    >> $($Finding.Recommendation)" }
            }
            $Report += ""
        }

        # Root Cause Analysis
        $Report += "=" * 80
        $Report += "ROOT CAUSE ANALYSIS"
        $Report += "=" * 80
        $Report += ""

        if (-not $CanResolveDns) {
            $Report += "PRIMARY ISSUE: DNS resolution failure"
            $Report += "  The client cannot resolve the hostname '$Target' to an IP address."
            $Report += "  This will prevent any RDP connection attempt."
            $Report += ""
        } elseif (-not $CanReachServer) {
            $Report += "PRIMARY ISSUE: Network connectivity failure"
            $Report += "  The client can resolve '$Target' but cannot reach port 3389."
            $Report += "  Possible causes:"
            $Report += "    - Target computer is offline or unreachable"
            $Report += "    - Firewall blocking port 3389"
            $Report += "    - Network routing issue"
            $Report += "    - VPN not connected (if required)"
            $Report += ""
        } elseif ($CriticalCount -eq 0 -and $WarningCount -eq 0) {
            $Report += "CLIENT-SIDE DIAGNOSTICS: All checks passed"
            $Report += "  The client can successfully reach the RDP port on '$Target'."
            $Report += "  If RDP still fails, the issue is likely on the SERVER side."
            $Report += "  Run the server-side diagnostic script on '$Target' for further investigation."
            $Report += ""
        } else {
            $Report += "MULTIPLE ISSUES DETECTED"
            $Report += "  Review the critical issues and warnings sections above."
            $Report += "  Address critical issues first, then investigate warnings."
            $Report += ""
        }

        # Recommended Actions
        $Report += "=" * 80
        $Report += "RECOMMENDED ACTIONS (PRIORITY ORDER)"
        $Report += "=" * 80
        $Report += ""

        $ActionsAdded = @()

        # Add critical recommendations first
        $CriticalWithRecommendations = $Global:Findings |
            Where-Object {$_.Severity -eq 'Critical' -and $_.Recommendation} |
            Select-Object -ExpandProperty Recommendation -Unique

        foreach ($Action in $CriticalWithRecommendations) {
            if ($Action -notin $ActionsAdded) {
                $Report += "  [HIGH PRIORITY] $Action"
                $ActionsAdded += $Action
            }
        }

        # Add warning recommendations
        $WarningWithRecommendations = $Global:Findings |
            Where-Object {$_.Severity -eq 'Warning' -and $_.Recommendation} |
            Select-Object -ExpandProperty Recommendation -Unique

        foreach ($Action in $WarningWithRecommendations) {
            if ($Action -notin $ActionsAdded) {
                $Report += "  [MEDIUM PRIORITY] $Action"
                $ActionsAdded += $Action
            }
        }

        if ($ActionsAdded.Count -eq 0) {
            $Report += "  No specific actions required - client-side connectivity is healthy."
            $Report += "  If RDP still fails, investigate server-side configuration."
        }
        $Report += ""

        # Troubleshooting Commands
        $Report += "=" * 80
        $Report += "TROUBLESHOOTING COMMANDS"
        $Report += "=" * 80
        $Report += ""
        $Report += "Manual connectivity tests:"
        $Report += "  nslookup $Target"
        $Report += "  ping $Target"
        $Report += "  Test-NetConnection -ComputerName $Target -Port 3389"
        $Report += ""
        $Report += "Clear RDP cache:"
        $Report += "  cmdkey /list"
        $Report += "  cmdkey /delete:TERMSRV/$Target"
        $Report += "  Remove-Item `"`$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache\*`" -Force"
        $Report += ""
        $Report += "View RDP client events:"
        $Report += "  Get-WinEvent -LogName Microsoft-Windows-TerminalServices-ClientActiveXCore/Operational -MaxEvents 20"
        $Report += ""
        $Report += "Test RDP connection:"
        $Report += "  mstsc /v:$Target"
        $Report += ""

        # Footer
        $Report += "=" * 80
        $Report += "END OF REPORT"
        $Report += "=" * 80
        $Report += ""
        $Report += "For support, contact IT with this report and log file:"
        $Report += "  Report: $ReportPath"
        $Report += "  Log: $LogPath"
        $Report += ""

        # Write report to file
        $Report | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
        Write-Log "Diagnostic report saved to $ReportPath" "SUCCESS"

        return $CanReachServer

    } catch {
        Write-Log "Failed to generate report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Main Execution

try {
    Write-Log "========================================" "INFO"
    Write-Log "RDP Client Diagnostics Started" "INFO"
    Write-Log "Target Computer: $TargetComputer" "INFO"
    Write-Log "Client Computer: $env:COMPUTERNAME" "INFO"
    Write-Log "User: $env:USERNAME" "INFO"
    Write-Log "========================================" "INFO"

    # Run all diagnostic tests
    Test-DNSResolution -Target $TargetComputer
    Test-NetworkConnectivity -Target $TargetComputer
    Test-VPNStatus
    Test-RDPClient
    Test-CredentialManager -Target $TargetComputer
    Test-ClientFirewall
    Test-NetworkConfiguration
    Test-ClientEventLogs -Target $TargetComputer
    Test-ProxyConfiguration
    Test-CertificateTrust -Target $TargetComputer
    Test-ClientGroupPolicy
    Test-NetworkQuality -Target $TargetComputer

    # Generate report and determine exit code
    $CanReachServer = New-DiagnosticReport -Target $TargetComputer

    Write-Log "========================================" "INFO"
    Write-Log "RDP Client Diagnostics Completed" "SUCCESS"
    Write-Log "Total Findings: $($Global:Findings.Count)" "INFO"
    Write-Log "Report: $ReportPath" "INFO"
    Write-Log "Log: $LogPath" "INFO"
    Write-Log "========================================" "INFO"

    # Determine exit code
    $CriticalIssues = ($Global:Findings | Where-Object {$_.Severity -eq 'Critical'}).Count

    if ($CriticalIssues -gt 0 -or -not $CanReachServer) {
        Write-Log "Exiting with code 1 - Connectivity issues detected" "WARNING"
        exit 1
    } else {
        Write-Log "Exiting with code 0 - Client can reach server" "SUCCESS"
        exit 0
    }

} catch {
    Write-Log "FATAL ERROR: Script execution failed" "ERROR"
    Write-Log "Error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "Exiting with code 2 - Script execution error" "ERROR"
    exit 2
}

#endregion
