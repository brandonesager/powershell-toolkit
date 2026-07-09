<#
.SYNOPSIS
    SMB printer and scanner connectivity diagnostic with explicit Win11 24H2
    SMB-signing-enforced check.

.DESCRIPTION
    Covers the root causes of intermittent or broken SMB-based scan-to-folder and
    printer connectivity on Windows 10/11 workstations:
      - Installed printers and port IPs
      - SMB client and server configuration (signing requirement, guest logons)
      - Active SMB connections
      - Win11 24H2 explicit check: BuildNumber >= 26100 = SMB signing enforced by default
      - Per-printer-IP port tests: 445 (SMB), 9100 (raw print), 80 (MFP web UI)
      - Firewall rules (File and Printer Sharing group)
      - Network profile (Public = SMB blocked inbound)
      - DNS resolution for non-IP printer ports

    Read-only. No writes.

.PARAMETER PrinterIPs
    Optional array of specific MFP IPs to test. If empty, uses IPs from installed
    printer ports automatically.

.NOTES
    Created: 2026-05-29
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1)

.KEYWORDS
    SMB, scanner, MFP, printer, 445, 9100, firewall, signing, Win11, 24H2, Konica,
    network profile, scan-to-folder
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string[]]$PrinterIPs = @()
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-SmbScannerDiag"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# --- OS + Win11 24H2 flag ---
Sec "OS / BUILD"
$os = Get-CimInstance Win32_OperatingSystem
W ("OS: {0}  Build: {1}" -f $os.Caption, $os.BuildNumber)
if ([int]$os.BuildNumber -ge 26100) {
    W ">> WIN11 24H2+ DETECTED (build >= 26100)."
    W "   SMB signing is ENFORCED by default on this build."
    W "   Konica / Kyocera MFPs that cannot negotiate signed SMB will fail."
    W "   Fix: Set-SmbServerConfiguration -RequireSecuritySignature `$false -Force"
} elseif ([int]$os.BuildNumber -ge 22000) {
    W ">> Win11 pre-24H2. SMB signing not enforced by default at OS level."
}

# --- Installed printers ---
Sec "INSTALLED PRINTERS"
Get-Printer | Select-Object Name, PortName, DriverName, PrinterStatus, Shared |
    Format-Table -AutoSize | Out-String | W

# --- Printer ports ---
Sec "PRINTER PORTS WITH IPs"
$ports = Get-PrinterPort | Where-Object { $_.PortName -match '\d+\.\d+\.\d+\.\d+|TCP|WSD' }
$ports | Select-Object Name, PrinterHostAddress, PortNumber, Protocol | Format-Table -AutoSize | Out-String | W

# Collect IPs to test
$testIPs = if ($PrinterIPs.Count -gt 0) {
    $PrinterIPs
} else {
    @(Get-PrinterPort | Where-Object { $_.PrinterHostAddress -match '^\d+\.\d+\.\d+\.\d+$' } |
      Select-Object -ExpandProperty PrinterHostAddress -Unique)
}

# --- SMB client config ---
Sec "SMB CLIENT CONFIGURATION"
$smbClient = Get-SmbClientConfiguration
W ("EnableSecuritySignature    : {0}" -f $smbClient.EnableSecuritySignature)
W ("RequireSecuritySignature   : {0}{1}" -f $smbClient.RequireSecuritySignature, $(if ($smbClient.RequireSecuritySignature) { '  << client requires signed SMB' } else { '' }))
W ("EnableInsecureGuestLogons  : {0}" -f $smbClient.EnableInsecureGuestLogons)

# --- SMB server config ---
Sec "SMB SERVER CONFIGURATION"
$smbServer = Get-SmbServerConfiguration
W ("EnableSecuritySignature    : {0}" -f $smbServer.EnableSecuritySignature)
W ("RequireSecuritySignature   : {0}{1}" -f $smbServer.RequireSecuritySignature, $(if ($smbServer.RequireSecuritySignature) { '  << MFP cannot negotiate signed SMB; scan will fail' } else { '' }))
W ("EncryptData                : {0}" -f $smbServer.EncryptData)

# --- Active SMB connections ---
Sec "ACTIVE SMB CONNECTIONS"
$conns = Get-SmbConnection
if ($conns) {
    $conns | Select-Object ServerName, ShareName, UserName, Dialect, Signed, Encrypted |
        Format-Table -AutoSize | Out-String | W
} else { W "No active SMB connections." }

# --- Network profile ---
Sec "NETWORK PROFILE"
$profiles = Get-NetConnectionProfile
$profiles | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity |
    Format-Table -AutoSize | Out-String | W
$pub = $profiles | Where-Object { $_.NetworkCategory -eq 'Public' }
if ($pub) {
    W ">> PUBLIC profile detected. SMB inbound is blocked on Public networks."
    $pub | ForEach-Object { W ("   Interface: {0}  Category: {1}" -f $_.InterfaceAlias, $_.NetworkCategory) }
    W "   Fix: Set-NetConnectionProfile -InterfaceAlias '<adapter>' -NetworkCategory Private"
}

# --- Firewall rules ---
Sec "FIREWALL - FILE AND PRINTER SHARING"
$fwRules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq 'Inbound' }
if ($fwRules) {
    $fwRules | Select-Object DisplayName, Enabled, Action, Profile | Format-Table -AutoSize | Out-String | W
    $disabled = $fwRules | Where-Object { $_.Enabled -eq $false }
    if ($disabled) { W (">> {0} inbound rules are DISABLED. Enable with: Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'" -f $disabled.Count) }
} else { W "No File and Printer Sharing rules found." }

# --- Port reachability per MFP IP ---
Sec "MFP PORT REACHABILITY"
if ($testIPs.Count -eq 0) {
    W "No MFP IPs found in printer ports and none provided via -PrinterIPs."
} else {
    foreach ($ip in $testIPs) {
        W ""
        W ("Testing: {0}" -f $ip)
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet
        W ("  Ping       : {0}" -f $(if ($ping) { 'OK' } else { 'FAILED' }))
        foreach ($port in @(445, 9100, 80)) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $tcp.Connect($ip, $port)
                $status = 'OK'
            } catch {
                $status = 'FAILED'
            } finally {
                $tcp.Dispose()
            }
            $label = switch ($port) {
                445  { 'SMB (445)  ' }
                9100 { 'Raw (9100) ' }
                80   { 'HTTP (80)  ' }
            }
            W ("  {0}: {1}" -f $label, $status)
        }
    }
}

# --- DNS for hostname-based ports ---
Sec "DNS RESOLUTION (hostname-based printer ports)"
$hostPorts = Get-PrinterPort | Where-Object { $_.PrinterHostAddress -and $_.PrinterHostAddress -notmatch '^\d+\.\d+\.\d+\.\d+$' }
if ($hostPorts) {
    foreach ($port in $hostPorts) {
        $h = $port.PrinterHostAddress
        W ("Resolving: {0}" -f $h)
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($h) | Select-Object -First 1
            W ("  -> {0}" -f $resolved.IPAddressToString)
        } catch {
            W ("  -> FAILED TO RESOLVE")
        }
    }
} else { W "All printer ports use IP addresses directly (no DNS-dependent ports)." }

W ""
W "===== END Get-SmbScannerDiag ====="
