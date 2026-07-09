<#
.SYNOPSIS
    Comprehensive connectivity diagnostic for LOB application servers

.DESCRIPTION
    Tests network connectivity to line-of-business application servers:
    - Active network adapters
    - IPv4 addressing
    - DNS resolution
    - ICMP ping
    - TCP port connectivity tests

    Returns detailed output for troubleshooting application-layer connectivity issues.

.PARAMETER Server
    Target server hostname or IP address

.PARAMETER Ports
    Array of TCP ports to test. Defaults to common application ports.

.EXAMPLE
    Test-ApplicationServerDiagnostic.ps1 -Server "app-server.domain.local" -Ports 80,443,8080

.NOTES
    Context: RMM (PS 5.1, SYSTEM)
    Exit Codes: 0 = all ports open | 112 = partial/no connectivity | 1 = error
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [int[]]$Ports = @(80,443,1433,8080,9000)
)

$ErrorActionPreference = "Stop"

function Test-Port {
    param(
        [string]$Server,
        [int]$Port
    )

    $result = Test-NetConnection -ComputerName $Server -Port $Port -WarningAction SilentlyContinue

    [PSCustomObject]@{
        Server = $Server
        Port = $Port
        TcpTestSucceeded = $result.TcpTestSucceeded
        RemoteAddress = $result.RemoteAddress
        PingSucceeded = $result.PingSucceeded
    }
}

try {
    Write-Output "INFO: Starting application server diagnostics."
    Write-Output "INFO: Server=$Server Ports=$($Ports -join ',')"

    Write-Output "INFO: Hostname=$env:COMPUTERNAME User=$env:USERNAME Date=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    Write-Output "INFO: Active adapters:"
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed |
        Format-Table -AutoSize | Out-String | Write-Output

    Write-Output "INFO: IPv4 addresses:"
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength |
        Format-Table -AutoSize | Out-String | Write-Output

    Write-Output "INFO: DNS resolution:"
    try {
        $dns = Resolve-DnsName -Name $Server -ErrorAction Stop
        Write-Output "INFO: Resolved $Server -> $($dns.IPAddress -join ', ')"
    } catch {
        Write-Output "WARN: DNS resolution failed for ${Server}: $($_.Exception.Message)"
    }

    Write-Output "INFO: Ping test:"
    $ping = Test-Connection -ComputerName $Server -Count 2 -ErrorAction SilentlyContinue
    if ($ping) {
        $avg = ($ping | Measure-Object -Property ResponseTime -Average).Average
        Write-Output "INFO: Ping OK, avg ms = $([math]::Round($avg,2))"
    } else {
        Write-Output "WARN: Ping failed or ICMP blocked."
    }

    Write-Output "INFO: Port tests:"
    $results = foreach ($p in $Ports) { Test-Port -Server $Server -Port $p }
    $results | Select-Object Server, Port, TcpTestSucceeded | Format-Table -AutoSize | Out-String | Write-Output

    $open = ($results | Where-Object { $_.TcpTestSucceeded }).Count
    $total = $results.Count

    if ($open -eq 0) {
        Write-Output "WARN: No tested ports reachable. Likely VPN split tunnel or firewall block."
        exit 112
    }

    if ($open -lt $total) {
        Write-Output "WARN: Partial connectivity ($open/$total ports open)."
        exit 112
    }

    Write-Output "SUCCESS: All tested ports reachable."
    exit 0
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
