<#
.SYNOPSIS
    Removes a ROOT-enumerated Panini phantom device and rescans hardware to bind the driver to the physical USB scanner.

.DESCRIPTION
    When a Panini scanner driver installs a software device node (ROOT\PANINI\0000) instead of binding
    to the physical USB hardware, CHECKscan cannot open the scanner even though the hardware is present.
    This script disables and removes the phantom device, then triggers a PnP hardware rescan so the
    driver binds to the physical Panini Vision X device (VID_121F&PID_0002).

    Run AFTER disconnecting the scanner USB cable and BEFORE reinstalling the driver.
    Run in SYSTEM remote session (SYSTEM context) — Remove-PnpDevice may not be available on PS 5.1; uses pnputil instead.

.NOTES
    Context:  SYSTEM (SYSTEM remote session)
    PS Ver:   5.1+
    Category: System-Maintenance

#>

# Disable the phantom device
Write-Host "Checking for ROOT\PANINI\0000 phantom device..." -ForegroundColor Yellow
$panini = Get-PnpDevice | Where-Object { $_.InstanceId -eq 'ROOT\PANINI\0000' }
if ($panini) {
    $panini | Disable-PnpDevice -Confirm:$false
    Write-Host "Disabled ROOT\PANINI\0000" -ForegroundColor Green
} else {
    Write-Host "ROOT\PANINI\0000 not found — may already be removed or never present" -ForegroundColor Yellow
}

# Remove via pnputil (Remove-PnpDevice not available in PS 5.1 on all systems)
Write-Host "Removing phantom device via pnputil..." -ForegroundColor Yellow
pnputil /remove-device "ROOT\PANINI\0000"

# Rescan hardware — driver should bind to physical VID_121F device after USB reconnect
Write-Host "Scanning for hardware changes..." -ForegroundColor Yellow
pnputil /scan-devices

# Verify result
Write-Host "`n=== Post-Fix Panini Enumeration ===" -ForegroundColor Cyan
Get-PnpDevice -FriendlyName '*Panini*' | Select-Object Status, Class, InstanceId, FriendlyName | Format-Table -AutoSize
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '121F' } | Select-Object Status, FriendlyName, InstanceId | Format-Table -AutoSize
