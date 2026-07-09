<#
.SYNOPSIS
    Diagnoses DisplayLink dock status for RMM deployment.

.DESCRIPTION
    Checks all DisplayLink PnP devices for Unknown status, driver version,
    and connected display count. Exits 1 if any device reports Unknown status
    (driver update required). Exits 0 if all devices are healthy.

.NOTES
    RMM-compatible: no elevation prompts, no user interaction, SYSTEM-safe.
    Tested against DisplayLink driver v9.3.3324.0 (failing) and v11.4 M1+ (passing).
    Exit codes: 0 = healthy, 1 = Unknown status detected (driver action required),
                2 = no DisplayLink devices found.
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

function Get-DisplayLinkDevices {
    Get-PnpDevice | Where-Object { $_.FriendlyName -like '*DisplayLink*' -or $_.HardwareID -like '*DisplayLink*' }
}

function Get-DisplayLinkDriverVersion {
    $driverKey = 'HKLM:\SOFTWARE\DisplayLink\Core'
    if (Test-Path $driverKey) {
        try {
            (Get-ItemProperty -Path $driverKey -Name 'ProductVersion' -ErrorAction Stop).ProductVersion
        } catch {
            'Unknown'
        }
    } else {
        'Not found'
    }
}

function Get-ConnectedDisplayCount {
    try {
        $displays = Get-CimInstance -ClassName Win32_DesktopMonitor -ErrorAction Stop |
            Where-Object { $_.PNPDeviceID -like '*DISPLAY*' }
        $displays.Count
    } catch {
        -1
    }
}

# --- Main ---

Write-Host "=== DisplayLink Dock Status Diagnostic ==="
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

$driverVersion = Get-DisplayLinkDriverVersion
Write-Host "DisplayLink driver version: $driverVersion"

$displayCount = Get-ConnectedDisplayCount
if ($displayCount -ge 0) {
    Write-Host "Connected displays detected: $displayCount"
} else {
    Write-Host "Connected displays: unable to query"
}

Write-Host ""

$devices = Get-DisplayLinkDevices

if (-not $devices) {
    Write-Host "RESULT: No DisplayLink devices found on this system."
    Write-Host "EXIT: 2"
    exit 2
}

Write-Host "DisplayLink devices found: $($devices.Count)"
Write-Host ""

$unknownCount = 0

foreach ($device in $devices) {
    $status = $device.Status
    $name   = $device.FriendlyName
    $id     = $device.InstanceId

    Write-Host "Device : $name"
    Write-Host "Status : $status"
    Write-Host "ID     : $id"
    Write-Host ""

    if ($status -eq 'Unknown' -or $status -eq 'Error') {
        $unknownCount++
    }
}

if ($unknownCount -gt 0) {
    Write-Host "RESULT: $unknownCount device(s) report Unknown/Error status."
    Write-Host "ACTION: Update DisplayLink driver to v11.4 M1 or later."
    Write-Host "        Download: https://www.synaptics.com/products/displaylink-graphics/downloads"
    Write-Host "EXIT: 1"
    exit 1
}

Write-Host "RESULT: All DisplayLink devices healthy."
Write-Host "EXIT: 0"
exit 0
