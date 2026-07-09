<#
.SYNOPSIS
    Fleet audit: report machines where CSC Offline Files is enabled (Start=2).

.DESCRIPTION
    Reads the CSC service Start value from the registry and reports the Offline
    Files state on the local machine. Designed for RMM deployment to run across
    a fleet so you can identify workstations where Offline Files (Client-Side
    Caching) is active.

    Offline Files enabled (Start=2) can cause repeated mapped drive reconnection
    events as Windows attempts to sync cached copies when the network share
    becomes available or changes. On Windows 11 with updated SMB behavior this
    manifests as mid-session drive drops.

    Also checks for a GPO override via the NetCache policy key. If a GPO forces
    Offline Files on, disabling the service key alone will not stick.

    Exit codes:
      0  - Offline Files is disabled or not configured
      1  - Script error
      2  - Offline Files is ENABLED (Start=2) - remediation needed

    Read-only. No changes to any registry value.

.NOTES
    Created: 2026-05-29
    Category: RMM-Deployment
    Context: RMM (SYSTEM, PS 5.1, fleet deployment)

.KEYWORDS
    offline files, CSC, NetCache, mapped drives, drive drops, fleet audit, RMM
#>
#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

try {
    $machine   = $env:COMPUTERNAME
    $cscKey    = 'HKLM:\SYSTEM\CurrentControlSet\Services\CSC'
    $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetCache'

    $cscStart = $null
    if (Test-Path $cscKey) {
        $cscStart = (Get-ItemProperty $cscKey -Name Start -ErrorAction SilentlyContinue).Start
    }

    $statusText = switch ($cscStart) {
        1       { 'System-managed (Start=1)' }
        2       { 'ENABLED (Start=2) - offline files active' }
        3       { 'Manual (Start=3)' }
        4       { 'Disabled (Start=4) - offline files off' }
        $null   { 'CSC registry key not found' }
        default { "Unknown (Start=$cscStart)" }
    }

    Write-Output ("=== Offline Files State: {0} ===" -f $machine)
    Write-Output ("CSC Start value : {0}" -f $(if ($null -eq $cscStart) { '(key absent)' } else { $cscStart }))
    Write-Output ("Status          : {0}" -f $statusText)

    # GPO override check
    if (Test-Path $policyKey) {
        $policyEnabled = (Get-ItemProperty $policyKey -Name Enabled -ErrorAction SilentlyContinue).Enabled
        Write-Output ("GPO NetCache    : Enabled=$policyEnabled  (GPO override present)")
        if ($policyEnabled -eq 1) {
            Write-Output "NOTE: GPO is forcing Offline Files on. Registry Start value change will not persist."
        }
    } else {
        Write-Output "GPO NetCache    : key absent (no override)"
    }

    if ($cscStart -eq 2) {
        Write-Output ""
        Write-Output ("ACTION NEEDED: {0} has Offline Files ENABLED. Set CSC Start=4 and reboot to disable." -f $machine)
        exit 2
    } else {
        Write-Output ""
        Write-Output ("No action needed: {0} Offline Files is not enabled." -f $machine)
        exit 0
    }
}
catch {
    Write-Output ("ERROR: {0}" -f $_)
    exit 1
}
