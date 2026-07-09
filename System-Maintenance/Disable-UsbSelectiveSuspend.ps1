#Requires -Version 5.1

<#
.SYNOPSIS
    Disable-UsbSelectiveSuspend -- Disable USB Selective Suspend on AC and DC power plans

.DESCRIPTION
    Sets USB Selective Suspend to Disabled for both AC (plugged in) and DC (battery)
    on the active power scheme. Prevents docking station NIC dropouts after sleep/resume.

.EXAMPLE
    .\Disable-UsbSelectiveSuspend.ps1
    Run from SYSTEM remote session on affected machine

.NOTES
    Date: 2026-02-24
    Category: System-Maintenance

.KEYWORDS
    remediate, USB, selective suspend, sleep, dock, power management
#>

[CmdletBinding()]
param()

$subgroup = '2a737441-1930-4402-8d77-b2bebba308a3'
$setting  = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'

Write-Host "Disabling USB Selective Suspend (AC)..."
powercfg /setacvalueindex SCHEME_CURRENT $subgroup $setting 0

Write-Host "Disabling USB Selective Suspend (DC)..."
powercfg /setdcvalueindex SCHEME_CURRENT $subgroup $setting 0

Write-Host "Applying active power scheme..."
powercfg /setactive SCHEME_CURRENT

# Verify
$ssOutput = powercfg /query SCHEME_CURRENT $subgroup $setting 2>&1
$acMatch = $ssOutput | Select-String 'Current AC Power Setting Index:\s+0x(\d+)'
$dcMatch = $ssOutput | Select-String 'Current DC Power Setting Index:\s+0x(\d+)'

$acVal = if ($acMatch) { $acMatch.Matches[0].Groups[1].Value } else { 'unknown' }
$dcVal = if ($dcMatch) { $dcMatch.Matches[0].Groups[1].Value } else { 'unknown' }

Write-Host ""
Write-Host "Verification:"
Write-Host "  AC: 0x$acVal $(if ($acVal -eq '00000000') { '(Disabled - OK)' } else { '(STILL ENABLED - check manually)' })"
Write-Host "  DC: 0x$dcVal $(if ($dcVal -eq '00000000') { '(Disabled - OK)' } else { '(STILL ENABLED - check manually)' })"
