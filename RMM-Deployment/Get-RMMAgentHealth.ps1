<#
.SYNOPSIS
    Reports RMM (ITSPlatform/SAAZ) agent health on an endpoint.

.DESCRIPTION
    Checks service status for ITSPlatform, ITSPlatformManager, SAAZWatchDog, and
    SAAZScheduler, reads the EndpointID from registry, verifies install directories
    are present, and scans for stale MSI registrations that would block reinstall.
    Read-only. Safe for CW RMM deployment in SYSTEM context.

    Output is line-delimited key: value pairs for easy parsing in RMM job results.

.NOTES
    Context:  RMM (SYSTEM, PS 5.1)
    Platform: Windows 10/11/Server 2019+
    PS 5.1 compatible.

.KEYWORDS
    ITSPlatform, SAAZ, RMM, agent health, EndpointID, diagnostics
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

$ErrorActionPreference = "Stop"

$results = [ordered]@{}

# Services
$services = @('ITSPlatform', 'ITSPlatformManager', 'SAAZWatchDog', 'SAAZScheduler')
foreach ($svc in $services) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    $results[$svc] = if ($s) { $s.Status } else { 'NOT FOUND' }
}

# EndpointID
$ep = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\SAAZOD" -Name EndpointID -ErrorAction SilentlyContinue
$results['EndpointID'] = if ($ep -and $ep.EndpointID) { $ep.EndpointID } else { 'MISSING' }

# Install directories
$results['ITSPlatform dir'] = if (Test-Path "C:\Program Files (x86)\ITSPlatform") { 'Present' } else { 'MISSING' }
$results['SAAZOD dir']      = if (Test-Path "C:\Program Files (x86)\SAAZOD") { 'Present' } else { 'MISSING' }

# Stale MSI registrations
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$stale = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'ITSPlatform|SAAZ|RMM' } |
    Select-Object DisplayName, DisplayVersion
$results['Stale MSI'] = if ($stale) {
    ($stale | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" }) -join '; '
} else {
    'None'
}

$results.GetEnumerator() | ForEach-Object { Write-Output "$($_.Key): $($_.Value)" }
exit 0
