#Requires -Version 5.1

<#
.SYNOPSIS
    Invoke-SFCDISMRepair — Run SFC and DISM RestoreHealth as routine maintenance

.DESCRIPTION
    Performs a two-phase Windows component repair:
    1. SFC /scannow — scans and repairs protected system files
    2. DISM /RestoreHealth — repairs the Windows component store from Windows Update

    Designed for RMM deployment or RMM shell execution. Logs all output to a
    timestamped file. Total runtime: 10-20 minutes depending on system state.

    Safe to run as preventive maintenance. No reboot required unless repairs are made
    to in-use files (rare). Does not modify Windows Update settings or install updates.

.PARAMETER LogPath
    Base directory for log output. Default: C:\Windows\Temp

.EXAMPLE
    .\Invoke-SFCDISMRepair.ps1
    Run with default log path (C:\Windows\Temp\sfc-dism-repair-YYYYMMDD.log)

.EXAMPLE
    .\Invoke-SFCDISMRepair.ps1 -LogPath "C:\temp"
    Run with custom log path

.NOTES
    Date: 2026-03-23
    Category: System-Maintenance
    Notes: Precautionary maintenance after Windows Update driver install

.KEYWORDS
    SFC, DISM, RestoreHealth, repair, maintenance, component-store, SYSTEM
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$LogPath = 'C:\Windows\Temp'
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $LogPath "sfc-dism-repair-$timestamp.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $entry | Out-File $logFile -Append
    Write-Output $entry
}

Write-Log "=== SFC/DISM Repair Started ==="
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"

# Phase 1: SFC
Write-Log "--- Phase 1: SFC /scannow ---"
$sfcOutput = sfc /scannow 2>&1 | Out-String
$sfcOutput | Out-File $logFile -Append

if ($sfcOutput -match 'did not find any integrity violations') {
    Write-Log "SFC: No integrity violations found"
} elseif ($sfcOutput -match 'successfully repaired') {
    Write-Log "SFC: Repairs made successfully"
} elseif ($sfcOutput -match 'unable to fix') {
    Write-Log "SFC: Found issues but unable to fix — DISM may resolve"
} else {
    Write-Log "SFC: Check log for details"
}

# Phase 2: DISM RestoreHealth
Write-Log "--- Phase 2: DISM /Online /Cleanup-Image /RestoreHealth ---"
$dismOutput = DISM /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
$dismOutput | Out-File $logFile -Append

if ($dismOutput -match 'The restore operation completed successfully') {
    Write-Log "DISM: Restore completed successfully"
} elseif ($dismOutput -match 'No component store corruption detected') {
    Write-Log "DISM: No corruption detected"
} else {
    Write-Log "DISM: Check log for details"
}

# Summary
Write-Log "=== Repair Complete ==="
Write-Log "Log file: $logFile"

# Check if reboot is advisable
$pending = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
Write-Log "Reboot pending: $pending"

exit 0
