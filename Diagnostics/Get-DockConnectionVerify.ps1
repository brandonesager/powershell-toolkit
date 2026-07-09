<#
.SYNOPSIS
    Get-DockConnectionVerify — Verify docking station connection and device health for RMM.

.DESCRIPTION
    Detects USB-C, Thunderbolt, and DisplayLink docking stations via PnP device enumeration.
    Reports device health, connection type, DisplayLink driver version, dock-routed network
    adapters, connected displays, and USB power management warnings. RMM-compatible: SYSTEM
    context, Write-Output only, structured exit codes.

.EXAMPLE
    .\Get-DockConnectionVerify.ps1
    Returns dock status summary with exit code 0 (healthy) or 1 (no dock or unhealthy).

.NOTES
    Date: 2026-04-02
    Category: Diagnostics
    Context: RMM (PS 5.1, SYSTEM)

.KEYWORDS
    dock, docking station, USB-C, Thunderbolt, DisplayLink, hub, verify, diagnose, RMM, SYSTEM
#>

$ErrorActionPreference = 'Stop'

try {
    # Detect dock-related PnP devices
    $dockDevices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
        $_.FriendlyName -match 'dock|hub|billboard|thunderbolt|displaylink' -and
        $_.Class -notmatch 'PrintQueue|Image'
    })

    if ($dockDevices.Count -eq 0) {
        Write-Output "NO DOCK DETECTED"
        Write-Output "No docking station, USB hub, or Thunderbolt devices found."
        exit 1
    }

    Write-Output "DOCK DEVICES: $($dockDevices.Count) found"
    Write-Output ""

    $unhealthy = 0
    foreach ($dev in $dockDevices) {
        $status = if ($dev.Status -eq 'OK') { 'OK' } else { "PROBLEM: $($dev.Status)" }
        Write-Output "  [$status] $($dev.FriendlyName)"
        if ($dev.Status -ne 'OK') { $unhealthy++ }
    }

    # Thunderbolt check
    $tbDevices = @($dockDevices | Where-Object { $_.FriendlyName -match 'Thunderbolt' })
    if ($tbDevices.Count -gt 0) {
        Write-Output ""
        Write-Output "CONNECTION TYPE: Thunderbolt"
    }

    # DisplayLink driver version
    $dlKey = 'HKLM:\SOFTWARE\DisplayLink\Core'
    if (Test-Path $dlKey) {
        try {
            $dlVersion = (Get-ItemProperty -Path $dlKey -Name 'ProductVersion' -ErrorAction Stop).ProductVersion
            Write-Output ""
            Write-Output "DISPLAYLINK DRIVER: v$dlVersion"
        } catch {}
    }

    # Network adapters through dock
    Write-Output ""
    Write-Output "NETWORK ADAPTERS:"
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceDescription -match 'DisplayLink|USB|Dock|Realtek.*USB|ASIX'
    })
    if ($adapters.Count -gt 0) {
        foreach ($a in $adapters) {
            Write-Output "  [$($a.Status)] $($a.InterfaceDescription) ($($a.LinkSpeed))"
        }
    } else {
        Write-Output "  No dock-routed network adapters detected"
    }

    # Connected displays
    Write-Output ""
    Write-Output "DISPLAYS:"
    try {
        $monitors = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue)
        Write-Output "  $($monitors.Count) display(s) connected"
        foreach ($mon in $monitors) {
            $name = ($mon.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ''
            if ($name) { Write-Output "  - $name" }
        }
    } catch {
        Write-Output "  Unable to enumerate displays"
    }

    # USB power management warning
    $usbPowerSave = @(Get-CimInstance MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceName -match 'USB' -and $_.Enable -eq $true })
    if ($usbPowerSave.Count -gt 0) {
        Write-Output ""
        Write-Output "WARNING: $($usbPowerSave.Count) USB hub(s) have power saving enabled (can cause dock disconnects)"
    }

    # Summary
    Write-Output ""
    if ($unhealthy -gt 0) {
        Write-Output "RESULT: Dock connected but $unhealthy device(s) reporting problems"
        exit 1
    } else {
        Write-Output "RESULT: Dock connected, all devices healthy"
        exit 0
    }
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
