#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Get-UsbPowerDiag — Check USB power management, Selective Suspend, and NIC power settings for docking station issues

.DESCRIPTION
    Pre-remediation diagnostic for docking station NIC dropout after sleep.
    Reports DisplayLink NIC power management, USB Selective Suspend state,
    and all USB Root Hub power-saving settings.

.EXAMPLE
    .\Get-UsbPowerDiag.ps1
    Run from SYSTEM remote session on affected machine

.NOTES
    Date: 2026-02-17
    Category: Diagnostics

.KEYWORDS
    diagnose, USB, power management, sleep, dock, DisplayLink, NIC, selective suspend
#>

[CmdletBinding()]
param()

Write-Host "`n=== DisplayLink NIC Power Management ===" -ForegroundColor Cyan

$dlAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*DisplayLink*' }
if ($dlAdapters) {
    foreach ($adapter in $dlAdapters) {
        Write-Host "`nAdapter: $($adapter.Name) ($($adapter.InterfaceDescription))"
        Write-Host "Status:  $($adapter.Status)"
        Write-Host "MAC:     $($adapter.MacAddress)"

        $pnpDev = Get-PnpDevice -FriendlyName $adapter.InterfaceDescription -Class Net -ErrorAction SilentlyContinue
        if ($pnpDev) {
            # Check WMI power management
            $wmPower = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root/wmi -ErrorAction SilentlyContinue |
                Where-Object { $_.InstanceName -like "*$($pnpDev.InstanceId.Replace('\','_'))*" }
            if ($wmPower) {
                $enabled = if ($wmPower.Enable) { 'YES — device can be powered off to save power' } else { 'No — power saving disabled' }
                Write-Host "Power Management: $enabled"
            }
            else {
                Write-Host "Power Management: Unable to query (WMI MSPower_DeviceEnable not found)"
            }

            # Check wake capability
            $wmWake = Get-CimInstance -ClassName MSPower_DeviceWakeEnable -Namespace root/wmi -ErrorAction SilentlyContinue |
                Where-Object { $_.InstanceName -like "*$($pnpDev.InstanceId.Replace('\','_'))*" }
            if ($wmWake) {
                Write-Host "Wake Enabled:     $($wmWake.Enable)"
            }
        }
    }
}
else {
    Write-Host "No DisplayLink network adapters found." -ForegroundColor Yellow
}

Write-Host "`n=== USB Selective Suspend ===" -ForegroundColor Cyan

$ssOutput = powercfg /query SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 2>&1
$acMatch = $ssOutput | Select-String 'Current AC Power Setting Index:\s+0x(\d+)'
$dcMatch = $ssOutput | Select-String 'Current DC Power Setting Index:\s+0x(\d+)'

if ($acMatch) {
    $acVal = if ($acMatch.Matches[0].Groups[1].Value -eq '00000001') { 'Enabled' } else { 'Disabled' }
    Write-Host "AC (plugged in): $acVal"
}
if ($dcMatch) {
    $dcVal = if ($dcMatch.Matches[0].Groups[1].Value -eq '00000001') { 'Enabled' } else { 'Disabled' }
    Write-Host "DC (battery):    $dcVal"
}
if (-not $acMatch -and -not $dcMatch) {
    Write-Host "Unable to parse Selective Suspend setting. Raw output:"
    $ssOutput | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`n=== USB Hub Power Management ===" -ForegroundColor Cyan

$hubs = Get-PnpDevice -Class USB -Status OK | Where-Object {
    $_.FriendlyName -like '*USB Root Hub*' -or
    $_.FriendlyName -like '*Generic USB Hub*' -or
    $_.FriendlyName -like '*USB Composite*'
}

$hubCount = 0
$psEnabledCount = 0

foreach ($hub in $hubs) {
    $hubCount++
    $wmHub = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root/wmi -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceName -like "*$($hub.InstanceId.Replace('\','_'))*" }

    $psEnabled = if ($wmHub -and $wmHub.Enable) { $true } else { $false }
    if ($psEnabled) { $psEnabledCount++ }

    Write-Host ("  {0,-45} PowerSave: {1}" -f $hub.FriendlyName, $(if ($psEnabled) { 'ON' } else { 'off' }))
}

Write-Host "`nTotal USB hubs: $hubCount | Power saving enabled: $psEnabledCount" -ForegroundColor $(if ($psEnabledCount -gt 0) { 'Yellow' } else { 'Green' })

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$issues = @()
if ($dlAdapters) {
    foreach ($a in $dlAdapters) {
        if ($a.Status -ne 'Up') { $issues += "DisplayLink adapter '$($a.Name)' status: $($a.Status)" }
    }
}
if ($acMatch -and $acMatch.Matches[0].Groups[1].Value -eq '00000001') { $issues += 'USB Selective Suspend enabled (AC)' }
if ($dcMatch -and $dcMatch.Matches[0].Groups[1].Value -eq '00000001') { $issues += 'USB Selective Suspend enabled (DC)' }
if ($psEnabledCount -gt 0) { $issues += "$psEnabledCount USB hub(s) with power saving enabled" }

if ($issues.Count -gt 0) {
    Write-Host "Issues found:" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
else {
    Write-Host "No USB power management issues detected." -ForegroundColor Green
}
