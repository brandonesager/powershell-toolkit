<#
.SYNOPSIS
    Panini check scanner diagnostic — device enumeration, DisplayLink version, USB bus, services, events.

.DESCRIPTION
    Checks Panini device enumeration type (ROOT = phantom software node vs USB = physical hardware),
    DisplayLink driver version, Panini VID_121F presence on USB bus, scanner-related services,
    and recent scanner events. Run in SYSTEM remote session (SYSTEM context).

.NOTES
    Context:  SYSTEM (SYSTEM remote session)
    PS Ver:   5.1+
    Category: Diagnostics

#>

# 1. Panini device enumeration (ROOT = software-only phantom, USB = physical hardware binding)
Write-Host "`n=== Panini Device Enumeration ===" -ForegroundColor Cyan
Get-PnpDevice -FriendlyName '*Panini*' | Select-Object Status, Class, InstanceId, FriendlyName | Format-Table -AutoSize

# 2. DisplayLink driver version (minimum recommended: 12.1 M2)
Write-Host "=== DisplayLink Devices ===" -ForegroundColor Cyan
Get-PnpDevice -FriendlyName '*DisplayLink*' | Select-Object Status, FriendlyName, InstanceId | Format-Table -AutoSize
Write-Host "=== DisplayLink Driver Versions ===" -ForegroundColor Cyan
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like '*DisplayLink*' } | Select-Object DeviceName, DriverVersion | Format-Table -AutoSize

# 3. Panini physical USB device (VID_121F = Panini Vision X scanner)
Write-Host "=== Panini USB Device (VID_121F) ===" -ForegroundColor Cyan
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '121F' } | Select-Object Status, FriendlyName, InstanceId | Format-Table -AutoSize

# 4. Scanner-related services
Write-Host "=== Scanner Services ===" -ForegroundColor Cyan
Get-Service | Where-Object { $_.Name -match 'Panini|WIA|STISvc|Scanner' } | Select-Object Status, StartType, Name, DisplayName | Format-Table -AutoSize

# 5. Recent Panini/scanner events (last 24h)
Write-Host "=== Recent Scanner Events (24h) ===" -ForegroundColor Cyan
$cutoff = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Panini|scanner|USB.*remov|USB.*connect' } |
    Select-Object -First 10 TimeCreated, Id, Message | Format-List
