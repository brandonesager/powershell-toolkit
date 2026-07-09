<#
.SYNOPSIS
    Read-only health check for the ConnectWise RMM (ITSPlatform / SAAZOD) agent.

.DESCRIPTION
    Reports the state of all ITSPlatform and SAAZOD services, the EndpointID registry
    value, install directory presence, and stale MSI registrations in Add/Remove Programs.
    No writes. Use for diagnosing "agent offline" or "agent not checking in" symptoms
    before deciding whether to repair or reinstall.

.NOTES
    Created: 2026-05-29
    Category: Diagnostics
    Context: RMM | Commands (SYSTEM, PS 5.1)

.KEYWORDS
    ConnectWise RMM, ITSPlatform, SAAZOD, SAAZWatchDog, EndpointID, agent health,
    MSI, offline
#>
#!ps
#maxlength=100000
#timeout=60000
#Requires -Version 5.1

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "Get-CWRMMAgentHealth"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ""

# --- Services ---
Write-Output "=== SERVICES ==="
$svcNames = @('ITSPlatform', 'ITSPlatformManager', 'SAAZWatchDog', 'SAAZScheduler', 'SAAZappr')
foreach ($name in $svcNames) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($s) {
        Write-Output ("{0,-25} Status: {1,-12} StartType: {2}" -f $s.Name, $s.Status, $s.StartType)
    } else {
        Write-Output ("{0,-25} NOT FOUND" -f $name)
    }
}

# --- EndpointID ---
Write-Output ""
Write-Output "=== ENDPOINTID ==="
$ep64 = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\SAAZOD' -Name EndpointID -ErrorAction SilentlyContinue).EndpointID
$ep32 = (Get-ItemProperty 'HKLM:\SOFTWARE\SAAZOD'             -Name EndpointID -ErrorAction SilentlyContinue).EndpointID
if ($ep64) { Write-Output ("EndpointID (WOW64): {0}" -f $ep64) }
elseif ($ep32) { Write-Output ("EndpointID (native): {0}" -f $ep32) }
else { Write-Output "EndpointID: MISSING (agent likely not registered)" }

# --- Install directories ---
Write-Output ""
Write-Output "=== INSTALL DIRECTORIES ==="
$dirs = @(
    'C:\Program Files (x86)\ITSPlatform',
    'C:\Program Files\ITSPlatform',
    'C:\Program Files (x86)\SAAZOD',
    'C:\Program Files\SAAZOD'
)
foreach ($d in $dirs) {
    Write-Output ("{0}: {1}" -f $d, $(if (Test-Path $d) { 'Present' } else { 'MISSING' }))
}

# --- Stale MSI registrations ---
Write-Output ""
Write-Output "=== MSI REGISTRATIONS (Uninstall keys) ==="
$uninst = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$found = Get-ItemProperty $uninst -ErrorAction SilentlyContinue |
         Where-Object { $_.DisplayName -match 'ITSPlatform|SAAZ|ConnectWise RMM' } |
         Select-Object DisplayName, DisplayVersion, InstallLocation, UninstallString
if ($found) {
    $found | ForEach-Object {
        Write-Output ("{0}  v{1}" -f $_.DisplayName, $_.DisplayVersion)
        if ($_.InstallLocation) { Write-Output ("  InstallLocation: {0}" -f $_.InstallLocation) }
    }
} else {
    Write-Output "No ITSPlatform/SAAZ/ConnectWise RMM entries in Uninstall keys."
}

# --- Network connectivity to ITSPlatform cloud ---
Write-Output ""
Write-Output "=== NETWORK REACHABILITY (ITSPlatform cloud) ==="
$targets = @('gateway.itsupport247.com', 'portal.itsupport247.com')
foreach ($t in $targets) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($t, 443)
        Write-Output ("{0}:443  OK" -f $t)
    } catch {
        Write-Output ("{0}:443  FAILED" -f $t)
    } finally { $tcp.Dispose() }
}

# --- Summary ---
Write-Output ""
Write-Output "=== SUMMARY ==="
$watchdog = Get-Service -Name SAAZWatchDog -ErrorAction SilentlyContinue
$platform = Get-Service -Name ITSPlatform  -ErrorAction SilentlyContinue
$hasEP    = [bool]($ep64 -or $ep32)

if ($platform -and $platform.Status -eq 'Running' -and $watchdog -and $watchdog.Status -eq 'Running' -and $hasEP) {
    Write-Output "HEALTHY: ITSPlatform running, SAAZWatchDog running, EndpointID present."
} else {
    Write-Output "DEGRADED or OFFLINE:"
    if (-not ($platform -and $platform.Status -eq 'Running')) { Write-Output "  ITSPlatform service not running" }
    if (-not ($watchdog -and $watchdog.Status -eq 'Running')) { Write-Output "  SAAZWatchDog service not running" }
    if (-not $hasEP) { Write-Output "  EndpointID missing" }
    Write-Output "  Next step: attempt repair via RMM console, or run Remove-RMMStaleMSI + reinstall."
}
