<#
.SYNOPSIS
    Diagnose docking station connectivity and driver issues.

.DESCRIPTION
    Collects comprehensive diagnostics for USB-C/Thunderbolt/DisplayLink docking stations.
    Identifies dock type, connection method, network routing, driver versions, and connected displays.
    Useful for troubleshooting Ethernet drops, video issues, or USB device problems related to docking.

.PARAMETER OutputPath
    Optional path to save diagnostic report. Defaults to desktop.

.EXAMPLE
    .\Get-DockingStationDiag.ps1
    Runs diagnostics and displays results in console.

.EXAMPLE
    .\Get-DockingStationDiag.ps1 -OutputPath "C:\temp\dock-diag.txt"
    Saves diagnostic report to specified path.

.NOTES
    Date: 2026-02-11
    Context: SYSTEM remote session (PS 7+)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Continue'
$report = @()

function Add-Section {
    param([string]$Title, [object]$Content)
    $script:report += "`n=== $Title ===`n"
    $script:report += $Content | Out-String
}

# Header
$report += "Docking Station Diagnostics Report"
$report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Computer: $env:COMPUTERNAME"
$report += "="*60

# 1. Dock Device Detection
Write-Host "Checking for docking station devices..." -ForegroundColor Cyan
$dockDevices = Get-PnpDevice -PresentOnly | Where-Object {
    $_.FriendlyName -match 'dock|hub|billboard|thunderbolt|displaylink'
} | Select-Object Class, FriendlyName, Manufacturer, InstanceId, Status

Add-Section "Dock Devices Detected" $dockDevices

# 2. USB-C Billboard Devices (dock branding)
$billboardDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
    $_.Name -match 'billboard'
} | Select-Object Name, Manufacturer, DeviceID

if ($billboardDevices) {
    Add-Section "USB-C Billboard Devices (Dock Branding)" $billboardDevices
}

# 3. Thunderbolt Controllers
Write-Host "Checking for Thunderbolt support..." -ForegroundColor Cyan
$thunderbolt = Get-PnpDevice -PresentOnly | Where-Object {
    $_.Class -eq 'Thunderbolt' -or $_.FriendlyName -match 'Thunderbolt'
} | Select-Object FriendlyName, InstanceId, Status

if ($thunderbolt) {
    Add-Section "Thunderbolt Controllers" $thunderbolt
    $script:report += "`nDock Type: Likely Thunderbolt dock`n"
} else {
    $script:report += "`nNo Thunderbolt controllers detected — likely USB-C or USB 3.0 dock`n"
}

# 4. USB Host Controllers
$usbControllers = Get-PnpDevice -Class USB -PresentOnly | Where-Object {
    $_.FriendlyName -match 'xHCI|Type-C|UCSI|USB.*3'
} | Select-Object FriendlyName, Status

Add-Section "USB Host Controllers" $usbControllers

# 5. DisplayLink Devices and Drivers
Write-Host "Checking DisplayLink drivers..." -ForegroundColor Cyan
$displayLinkDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object {
    $_.DeviceName -match 'DisplayLink'
} | Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer

if ($displayLinkDrivers) {
    Add-Section "DisplayLink Drivers" $displayLinkDrivers

    # Flag old drivers
    foreach ($driver in $displayLinkDrivers) {
        $driverDate = [datetime]$driver.DriverDate.ToString().Substring(0, 8)
        $ageMonths = [math]::Round(((Get-Date) - $driverDate).TotalDays / 30)

        if ($ageMonths -gt 12) {
            $script:report += "`n[WARNING] DisplayLink driver '$($driver.DeviceName)' is $ageMonths months old (dated $($driverDate.ToString('yyyy-MM-dd')))`n"
            $script:report += "Consider updating from: https://www.synaptics.com/products/displaylink-graphics/downloads`n"
        }
    }
} else {
    $script:report += "`nNo DisplayLink drivers detected — not a DisplayLink dock`n"
}

# 6. Network Adapters
Write-Host "Checking network adapters..." -ForegroundColor Cyan
$netAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed

Add-Section "Network Adapters" $netAdapters

# Identify which adapter is routing internet
$activeAdapter = $netAdapters | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if ($activeAdapter) {
    $script:report += "`nActive Network Adapter: $($activeAdapter.Name) ($($activeAdapter.InterfaceDescription))`n"

    if ($activeAdapter.InterfaceDescription -match 'DisplayLink|USB|Dock') {
        $script:report += "[INFO] Internet is routing through dock's Ethernet adapter`n"
    }
}

# 7. Connected Monitors
Write-Host "Checking connected displays..." -ForegroundColor Cyan
try {
    $monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Monitor = ($_.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ''
            Serial = ($_.SerialNumberID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ''
        }
    }

    if ($monitors) {
        Add-Section "Connected Monitors" $monitors
        $script:report += "`nTotal Displays: $($monitors.Count)`n"
    }
} catch {
    $script:report += "`n[ERROR] Could not enumerate monitors: $($_.Exception.Message)`n"
}

# 8. USB Power Management Settings
Write-Host "Checking USB power management..." -ForegroundColor Cyan
$usbHubs = Get-CimInstance MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue | Where-Object {
    $_.InstanceName -match 'USB'
}

if ($usbHubs) {
    $hubsWithPowerSave = $usbHubs | Where-Object { $_.Enable -eq $true }
    if ($hubsWithPowerSave) {
        $script:report += "`n[WARNING] $($hubsWithPowerSave.Count) USB hubs have 'Allow computer to turn off device' enabled`n"
        $script:report += "This can cause dock disconnections. Disable in Device Manager > USB Root Hub > Power Management`n"
    } else {
        $script:report += "`n[OK] USB power saving appears disabled for all hubs`n"
    }
}

# Summary and Recommendations
$script:report += "`n" + "="*60
$script:report += "`n=== Recommendations ==="
$script:report += "`n1. If Ethernet drops occur when connecting displays:"
$script:report += "`n   - Update DisplayLink drivers if outdated (>12 months old)"
$script:report += "`n   - Disable USB Selective Suspend in power plan"
$script:report += "`n   - Disable 'Allow computer to turn off device' for USB Root Hubs"
$script:report += "`n2. If dock not detected:"
$script:report += "`n   - Try different USB port"
$script:report += "`n   - Check dock firmware updates from manufacturer"
$script:report += "`n   - Test dock on different computer to isolate hardware failure"
$script:report += "`n3. If video flickering or resolution issues:"
$script:report += "`n   - Update DisplayLink drivers"
$script:report += "`n   - Check display cable quality"
$script:report += "`n   - Reduce number of connected displays to test bandwidth limits"

# Output
$reportText = $report -join "`n"

if ($OutputPath) {
    $reportText | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "`nDiagnostic report saved to: $OutputPath" -ForegroundColor Green
} else {
    Write-Output $reportText
}
