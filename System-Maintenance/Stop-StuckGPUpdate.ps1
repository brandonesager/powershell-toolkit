#Requires -Version 5.1

<#
.SYNOPSIS
    Stop-StuckGPUpdate — Kill accumulated gpupdate.exe processes causing high CPU

.DESCRIPTION
    Identifies and terminates stuck gpupdate.exe processes that accumulate when
    the Software Installation CSE hangs during background Group Policy refresh.
    Each background refresh spawns a new gpupdate.exe that never exits when the
    CSE requires synchronous foreground processing. On a 4-core server, four
    accumulated processes saturate CPU at 100%.

    Reports process details before kill (PID, CPU time, age, threads), terminates
    all instances, and verifies CPU recovery. Safe for SYSTEM remote session execution on
    affected servers.

.EXAMPLE
    .\Stop-StuckGPUpdate.ps1
    Lists all gpupdate.exe processes with diagnostics, kills them, reports CPU after

.NOTES
    Date: 2026-02-26
    Category: System-Maintenance
    Context: SYSTEM remote session (SYSTEM), also safe for RMM

.KEYWORDS
    cleanup, remediate, group-policy, gpupdate, CPU, software-installation, CSE

.ERRORCODES
    Event 4016, Event 6035, Event 7016, Event 8016
#>

$ErrorActionPreference = "Stop"

Write-Host "=== GPUPDATE PROCESS CLEANUP ===" -ForegroundColor Cyan
Write-Host "Server: $($env:COMPUTERNAME)"
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# Check for stuck gpupdate processes
$gpProcs = Get-Process -Name gpupdate -ErrorAction SilentlyContinue
if (-not $gpProcs) {
    Write-Host "No gpupdate.exe processes found." -ForegroundColor Green
    return
}

Write-Host "Found $($gpProcs.Count) gpupdate process(es):" -ForegroundColor Yellow
Write-Host ""
foreach ($p in $gpProcs) {
    $age = (New-TimeSpan -Start $p.StartTime -End (Get-Date))
    $cpuSec = [math]::Round($p.CPU, 1)
    Write-Host "  PID $($p.Id) | CPU: ${cpuSec}s | Age: $($age.ToString('d\.hh\:mm\:ss')) | Threads: $($p.Threads.Count)"
}
Write-Host ""

# Kill all gpupdate processes
$killed = 0
foreach ($p in $gpProcs) {
    try {
        Stop-Process -Id $p.Id -Force
        Write-Host "Killed PID $($p.Id)" -ForegroundColor Green
        $killed++
    }
    catch {
        Write-Host "Failed to kill PID $($p.Id): $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host ""
Write-Host "Result: $killed of $($gpProcs.Count) processes killed" -ForegroundColor Cyan

# Verify CPU recovery
Start-Sleep -Seconds 2
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
Write-Host "Current CPU: ${cpu}%" -ForegroundColor $(if ($cpu -lt 50) { 'Green' } else { 'Yellow' })
