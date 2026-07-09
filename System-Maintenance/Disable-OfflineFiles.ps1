<#
.SYNOPSIS
    Audits and disables Offline Files (CSC) if enabled.
.DESCRIPTION
    Checks whether Client-Side Caching (Offline Files) is enabled via the CSC
    service Start registry value and any GPO policy override. If enabled
    (Start=2), sets Start=4 to disable it. A reboot is required for the
    disable to take effect.

    Offline Files can cause mapped drives to repeatedly reconnect mid-session,
    producing intermittent drop symptoms. This script reports current state and
    disables if warranted.
.EXAMPLE
    .\Disable-OfflineFiles.ps1
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=No action needed (already disabled or not configured),
                1=Error, 112=Disabled successfully (reboot required)
    PS 5.1 compatible.
.KEYWORDS
    offline files, CSC, client-side caching, mapped drives, drops, reboot
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

try {
    $machine   = $env:COMPUTERNAME
    $cscKey    = "HKLM:\SYSTEM\CurrentControlSet\Services\CSC"
    $paramKey  = "$cscKey\Parameters"
    $policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetCache"

    $cscStart = $null
    if (Test-Path $cscKey) {
        $cscStart = (Get-ItemProperty $cscKey -Name Start -ErrorAction SilentlyContinue).Start
    }

    Write-Output "=== Offline Files (CSC) Audit: $machine ==="
    Write-Output "CSC service Start value: $cscStart"

    switch ($cscStart) {
        1 { Write-Output "Status: System-managed (Start=1)" }
        2 { Write-Output "Status: ENABLED (Start=2) - offline files active" }
        3 { Write-Output "Status: Manual (Start=3)" }
        4 { Write-Output "Status: Disabled (Start=4) - offline files off" }
        $null { Write-Output "Status: CSC registry key not found" }
        default { Write-Output "Status: Unknown Start value ($cscStart)" }
    }

    if (Test-Path $policyKey) {
        $policyEnabled = (Get-ItemProperty $policyKey -Name Enabled -ErrorAction SilentlyContinue).Enabled
        Write-Output "Policy NetCache\Enabled: $policyEnabled"
    } else {
        Write-Output "Policy NetCache key: not present (no GPO override)"
    }

    if (Test-Path $paramKey) {
        Write-Output "CSC Parameters found (FormatDatabase, etc. present)"
    }

    if ($cscStart -eq 2) {
        Write-Output ""
        Write-Output "Offline Files is ENABLED. Disabling now..."
        Set-ItemProperty -Path $cscKey -Name Start -Value 4 -Type DWord
        $verify = (Get-ItemProperty $cscKey -Name Start).Start
        if ($verify -eq 4) {
            Write-Output "CSC Start set to 4 (Disabled). REBOOT REQUIRED to take effect."
            exit 112
        } else {
            Write-Output "ERROR: Failed to set Start=4 (current value: $verify)"
            exit 1
        }
    } elseif ($cscStart -eq 4 -or $null -eq $cscStart) {
        Write-Output "Offline Files is already disabled or not configured. No action needed."
        exit 0
    } else {
        Write-Output "Start=$cscStart - no action taken. Review manually if drops persist."
        exit 0
    }
} catch {
    Write-Output "ERROR: $_"
    exit 1
}
