#!ps
#maxlength=100000
#timeout=90000
$ErrorActionPreference = "Stop"
Write-Output "=== GPUPDATE PROCESS CLEANUP ==="
Write-Output "Server: $($env:COMPUTERNAME)"
Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""
$gpProcs = Get-Process -Name gpupdate -ErrorAction SilentlyContinue
if (-not $gpProcs) {
    Write-Output "No gpupdate.exe processes found."
} else {
    Write-Output "Found $($gpProcs.Count) gpupdate process(es):"
    Write-Output ""
    foreach ($p in $gpProcs) {
        $age = (New-TimeSpan -Start $p.StartTime -End (Get-Date))
        $cpuSec = [math]::Round($p.CPU, 1)
        Write-Output "  PID $($p.Id) | CPU: ${cpuSec}s | Age: $($age.ToString('d\.hh\:mm\:ss')) | Threads: $($p.Threads.Count)"
    }
    Write-Output ""
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
    Start-Sleep -Seconds 2
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    Write-Output "Current CPU: ${cpu}%"
}
