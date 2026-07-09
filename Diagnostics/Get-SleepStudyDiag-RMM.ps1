<#
.SYNOPSIS
    Generates and parses a Sleep Study report, outputting key power behavior metrics.

.DESCRIPTION
    Runs powercfg /sleepstudy, extracts session activity, battery state, sleep
    architecture, and longest awake duration. Use to confirm whether a machine
    was sleeping or active during a given period.

.OUTPUTS
    Plain-text summary of sleep architecture, session counts, activity breakdown,
    longest session duration, and battery delta.

.NOTES
    Context:    RMM (SYSTEM)
    Version:    1.0 - 2026-03-09
    .KEYWORDS   sleep study, powercfg, modern standby, S3, connected standby,
                battery, power, activity, audit
#>

$ErrorActionPreference = "Stop"

$reportPath = Join-Path $env:TEMP "sleepstudy-rmm.html"

try {
    # Generate report
    $null = & powercfg /sleepstudy /output $reportPath /duration 7
    if (-not (Test-Path $reportPath)) {
        Write-Output "ERROR: sleepstudy report not generated. Modern Standby may not be supported on this platform."
        exit 1
    }

    $content = [System.IO.File]::ReadAllText($reportPath)

    # --- System info ---
    $computer = if ($content -match '"ComputerName":"([^"]+)"') { $Matches[1] } else { $env:COMPUTERNAME }
    $model    = if ($content -match '"SystemProductName":"([^"]+)"') { $Matches[1] } else { "Unknown" }
    $cs       = if ($content -match '"ConnectedStandby":(true|false)') { $Matches[1] } else { "unknown" }
    $startT   = if ($content -match '"ReportStartTimeLocal":"([^"]+)"') { $Matches[1] } else { "?" }
    $endT     = if ($content -match '"ScanTimeLocal":"([^"]+)"') { $Matches[1] } else { "?" }

    # --- Durations (100ns units -> hours) ---
    $durations = [regex]::Matches($content, '"Duration":(\d+)') |
        ForEach-Object { [long]$_.Groups[1].Value / 10000000 / 3600 }
    $longestHrs    = if ($durations) { [math]::Round(($durations | Measure-Object -Maximum).Maximum, 2) } else { 0 }
    $totalSessions = $durations.Count

    # --- Activity breakdown ---
    $activityValues = [regex]::Matches($content, '"Activity":(\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value }
    $zeroCount    = ($activityValues | Where-Object { $_ -eq 0 }).Count
    $nonZeroCount = ($activityValues | Where-Object { $_ -gt 0 }).Count

    # --- Battery ---
    $startCaps = [regex]::Matches($content, '"StartChargeCapcity":(\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value }
    $endCaps   = [regex]::Matches($content, '"EndChargeCapacity":(\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value }
    $fullCaps  = [regex]::Matches($content, '"StartFullChargeCapacity":(\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value }

    $batteryLine = "N/A (plugged in or no battery data)"
    if ($startCaps.Count -gt 0 -and $endCaps.Count -gt 0 -and $fullCaps.Count -gt 0) {
        $full     = $fullCaps[0]
        $startPct = [math]::Round($startCaps[0] / $full * 100, 1)
        $endPct   = [math]::Round($endCaps[$endCaps.Count - 1] / $full * 100, 1)
        $batteryLine = "$startPct% -> $endPct% (full charge = $full mWh)"
    }

    # --- Sleep architecture label ---
    $archLabel = if ($cs -eq "true") {
        "Modern Standby (S0ix) - system stays in S0, never fully powers down"
    } elseif ($cs -eq "false") {
        "Traditional S3 - system fully powers down during sleep"
    } else {
        "Unknown"
    }

    # --- Output ---
    Write-Output "=== Sleep Study Summary ==="
    Write-Output "Computer     : $computer"
    Write-Output "Model        : $model"
    Write-Output "Report period: $startT to $endT"
    Write-Output ""
    Write-Output "Sleep architecture : $archLabel"
    Write-Output ""
    Write-Output "Sessions total     : $totalSessions"
    Write-Output "  Zero activity    : $zeroCount  (fully idle/sleeping)"
    Write-Output "  Non-zero activity: $nonZeroCount  (background work or user activity)"
    Write-Output "Longest session    : $longestHrs hrs"
    Write-Output ""
    Write-Output "Battery            : $batteryLine"
    Write-Output ""

    # --- Verdict ---
    if ($totalSessions -gt 0) {
        $idlePct = [math]::Round($zeroCount / $totalSessions * 100, 0)
        Write-Output "Idle rate: $idlePct% of sessions showed zero activity."
        if ($idlePct -ge 90) {
            Write-Output "Verdict: Machine was predominantly sleeping. Consistent with an unattended, inactive device."
        } elseif ($idlePct -ge 60) {
            Write-Output "Verdict: Mixed activity. Some background wake events present."
        } else {
            Write-Output "Verdict: High activity rate. Machine was regularly active or prevented from sleeping."
        }
    }

    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
finally {
    if (Test-Path $reportPath) { Remove-Item $reportPath -Force -ErrorAction SilentlyContinue }
}
