<#
.SYNOPSIS
    Stop-StuckGPUpdate-RMM — Kill accumulated gpupdate.exe processes causing high CPU

.DESCRIPTION
    Identifies and terminates stuck gpupdate.exe processes that accumulate when
    the Software Installation CSE hangs during background Group Policy refresh.
    Each background refresh spawns a new gpupdate.exe that never exits when the
    CSE requires synchronous foreground processing. On a 4-core server, four
    accumulated processes saturate CPU at 100%.

    Reports process details before kill (PID, CPU time, age, threads), terminates
    all instances, and verifies CPU recovery. RMM-safe with proper exit codes.

.EXAMPLE
    .\Stop-StuckGPUpdate-RMM.ps1
    Lists all gpupdate.exe processes with diagnostics, kills them, reports CPU after

.NOTES
    Date: 2026-02-26
    Category: RMM-Deployment
    Context: RMM (SYSTEM)

.KEYWORDS
    cleanup, remediate, group-policy, gpupdate, CPU, software-installation, CSE, RMM

.ERRORCODES
    Event 4016, Event 6035, Event 7016, Event 8016
#>

$ErrorActionPreference = "Stop"

Write-Output "=== GPUPDATE PROCESS CLEANUP ==="
Write-Output "Server: $($env:COMPUTERNAME)"
Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

# Check for stuck gpupdate processes
$gpProcs = Get-Process -Name gpupdate -ErrorAction SilentlyContinue
if (-not $gpProcs) {
    Write-Output "No gpupdate.exe processes found."
    exit 0
}

Write-Output "Found $($gpProcs.Count) gpupdate process(es):"
Write-Output ""
foreach ($p in $gpProcs) {
    $age = (New-TimeSpan -Start $p.StartTime -End (Get-Date))
    $cpuSec = [math]::Round($p.CPU, 1)
    Write-Output "  PID $($p.Id) | CPU: ${cpuSec}s | Age: $($age.ToString('d\.hh\:mm\:ss')) | Threads: $($p.Threads.Count)"
}
Write-Output ""

# Kill all gpupdate processes
$killed = 0
$failed = 0
foreach ($p in $gpProcs) {
    try {
        Stop-Process -Id $p.Id -Force
        Write-Output "Killed PID $($p.Id)"
        $killed++
    }
    catch {
        Write-Output "FAILED to kill PID $($p.Id): $($_.Exception.Message)"
        $failed++
    }
}
Write-Output ""
Write-Output "Result: $killed of $($gpProcs.Count) processes killed"

# Verify CPU recovery
Start-Sleep -Seconds 2
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
Write-Output "Current CPU: ${cpu}%"

if ($failed -gt 0 -and $killed -gt 0) {
    exit 112
}
elseif ($failed -gt 0) {
    exit 1
}
exit 0
