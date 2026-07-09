<#
.SYNOPSIS
    Gathers Cisco Secure Client (AnyConnect) VPN diagnostics from a Windows endpoint.

.DESCRIPTION
    Read-only. Collects:
      - VPN profile XML state: file list, sizes, timestamps, and SHA256 hashes
      - Cisco Secure Client service status and installed package version
      - Recent Cisco log files (last 7 days) from configurable log root paths
      - Cisco-related Windows Application and System events (last 24 hours)
      - Pre-tunnel client DNS server configuration
      - Name resolution probes for a configurable list of FQDNs
      - Cisco virtual adapter state

    Copies profile XMLs and log files into a bundle directory under
    C:\Windows\Temp for pickup via remote file transfer.

.PARAMETER ProfileDir
    Path to the Cisco VPN profile directory.
    Default: "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile"

.PARAMETER LogRoots
    Array of root paths to search for recent Cisco log files.
    Default: standard Cisco Secure Client and Public Documents paths.

.PARAMETER NameResolutionTargets
    Array of FQDNs to probe for pre-tunnel DNS resolution. Include the VPN gateway,
    internal domain hosts, and a public internet name (e.g., google.com).

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1)
    Platform: Windows 10/11 with Cisco Secure Client or AnyConnect installed
    PS 5.1 compatible.

.KEYWORDS
    Cisco, AnyConnect, Secure Client, VPN, profile, DNS, logs, diagnostics, csc_vpn
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ProfileDir = 'C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile',

    [string[]]$LogRoots = @(
        'C:\ProgramData\Cisco\Cisco Secure Client',
        'C:\Users\Public\Documents\Cisco\Cisco Secure Client',
        'C:\Windows\Temp'
    ),

    [string[]]$NameResolutionTargets = @(
        'google.com'
        # Add site-specific VPN gateway and internal domain targets before deployment.
        # Example: 'sslvpn.example.com', 'dc1.corp.example.com'
    )
)

$ts  = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "C:\Windows\Temp\vpn-diag-$ts"
New-Item -ItemType Directory -Path $out -Force | Out-Null

Write-Output "=== Cisco VPN Client Diagnostic -- $(Get-Date) ==="
Write-Output "Bundle: $out"

# --- Profile XML state + hash ---
Write-Output "`n--- Profile XML ($ProfileDir) ---"
if (Test-Path $ProfileDir) {
    $xmls = Get-ChildItem -Path $ProfileDir -Filter *.xml -ErrorAction SilentlyContinue
    if ($xmls) {
        foreach ($x in $xmls) {
            $hash = (Get-FileHash $x.FullName -Algorithm SHA256).Hash
            Write-Output ("  {0}  {1} bytes  {2}  SHA256={3}" -f $x.Name, $x.Length, $x.LastWriteTime, $hash)
            Copy-Item $x.FullName -Destination (Join-Path $out $x.Name) -ErrorAction SilentlyContinue
        }
    } else {
        Write-Output "  EMPTY -- profile missing"
    }
} else {
    Write-Output "  Profile directory missing -- Cisco Secure Client may not be installed"
}

# --- Service + package state ---
Write-Output "`n--- Cisco Secure Client services ---"
Get-Service -Name 'csc_*' -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType |
    Format-Table -AutoSize | Out-String | Write-Output

Write-Output "--- Installed package ---"
$pkg = Get-Package -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Cisco Secure*' -or $_.Name -like 'Cisco AnyConnect*' }
if ($pkg) {
    $pkg | Select-Object Name, Version | Format-Table -AutoSize | Out-String | Write-Output
} else {
    Write-Output "  No Cisco Secure Client / AnyConnect package registered"
}

# --- Cisco log files (last 7 days) ---
Write-Output "`n--- Cisco logs (last 7 days) ---"
$cutoff    = (Get-Date).AddDays(-7)
$foundLogs = @()
foreach ($root in $LogRoots) {
    if (Test-Path $root) {
        $logs = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -gt $cutoff -and
                $_.Extension -in '.log','.txt' -and
                ($_.Name -match 'anyconnect|cisco|csc|vpn|secureclient' -or $root -match 'Cisco Secure Client')
            }
        foreach ($h in $logs) {
            Write-Output ("  {0}  {1} bytes  {2}" -f $h.FullName, $h.Length, $h.LastWriteTime)
            $foundLogs += $h
            Copy-Item $h.FullName -Destination (Join-Path $out ("log-" + $h.Name)) -ErrorAction SilentlyContinue
        }
    }
}
if (-not $foundLogs) { Write-Output "  No recent Cisco log files found in candidate paths" }

# --- Cisco-related Windows events (last 24h) ---
Write-Output "`n--- Cisco events (Application + System, last 24h) ---"
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = @('Application','System')
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction Stop | Where-Object {
        $_.ProviderName -match 'Cisco|csc_|AnyConnect|Secure Client' -or
        $_.Message -match 'AnyConnect|Secure Client|csc_vpn'
    }
    if ($events) {
        $events |
            Select-Object TimeCreated, LevelDisplayName, Id, ProviderName,
                @{n='FirstLine'; e={ ($_.Message -split "`r?`n")[0] }} |
            Format-Table -AutoSize -Wrap | Out-String | Write-Output
        $events | Export-Csv -Path (Join-Path $out 'events-cisco.csv') -NoTypeInformation -ErrorAction SilentlyContinue
    } else {
        Write-Output "  No Cisco-related events in the last 24h"
    }
} catch {
    Write-Output "  Event query failed: $($_.Exception.Message)"
}

# --- Client DNS state ---
Write-Output "`n--- Client DNS state (pre-tunnel) ---"
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
    Format-Table -AutoSize | Out-String | Write-Output

# --- Name resolution probes ---
Write-Output "`n--- Name resolution probes (pre-tunnel) ---"
foreach ($n in $NameResolutionTargets) {
    try {
        $r   = Resolve-DnsName -Name $n -Type A -ErrorAction Stop -DnsOnly
        $ips = ($r | Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress) -join ','
        Write-Output ("  {0} -> {1}" -f $n, $ips)
    } catch {
        Write-Output ("  {0} -> FAIL: {1}" -f $n, $_.Exception.Message)
    }
}

# --- Cisco virtual adapter state ---
Write-Output "`n--- Cisco virtual adapters ---"
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'Cisco|AnyConnect|VPN' } |
    Select-Object Name, InterfaceDescription, Status, MacAddress |
    Format-Table -AutoSize | Out-String | Write-Output

Write-Output "`n=== END  bundle: $out ==="
