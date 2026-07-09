<#
.SYNOPSIS
    Gathers ScreenConnect agent diagnostics on a managed endpoint.

.DESCRIPTION
    Read-only diagnostics for a ScreenConnect agent that is stuck on "Waiting for guest"
    or otherwise unresponsive. Checks:
      - ScreenConnect service status and process list
      - ConnectWise RMM (ITSPlatform) service health
      - Recent ScreenConnect entries from the Application event log

    Bulk event detail routes to a temp file; stdout receives a summary count and the
    most recent error message. Safe for CW RMM deployment (SYSTEM, PS 5.1, non-interactive).

.PARAMETER OutFilePrefix
    Prefix for the diagnostics output file written to $env:TEMP.
    Default: "sc-diag". Full path: "$env:TEMP\<prefix>-<timestamp>.txt"

.NOTES
    Context:  Commands (SYSTEM, PS 5.1, ScreenConnect Commands Tab)
    Platform: Windows 10/11/Server 2019+
    PS 5.1 compatible.

.KEYWORDS
    ScreenConnect, RMM, SYSTEM, service, waiting for guest, agent, diagnostics
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutFilePrefix = 'sc-diag'
)

$ErrorActionPreference = "Stop"
$outFile = "$env:TEMP\$OutFilePrefix-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"

# --- ScreenConnect services ---
$scSvcs = Get-Service | Where-Object { $_.DisplayName -like '*ScreenConnect*' }
if ($scSvcs) {
    Write-Output "SC Services ($($scSvcs.Count) found):"
    $scSvcs | ForEach-Object {
        Write-Output "  $($_.DisplayName) | Status=$($_.Status) | StartType=$($_.StartType)"
    }
} else {
    Write-Output "SC Services: NONE found -- ScreenConnect may not be installed"
}

# --- ScreenConnect processes ---
$scProcs = Get-Process | Where-Object { $_.Name -like '*ScreenConnect*' } -ErrorAction SilentlyContinue
if ($scProcs) {
    Write-Output "SC Processes ($($scProcs.Count) running):"
    $scProcs | ForEach-Object {
        Write-Output "  $($_.Name) | PID=$($_.Id) | CPU=$($_.CPU)"
    }
} else {
    Write-Output "SC Processes: 0 running"
}

# --- RMM agent health ---
$rmmSvcs = Get-Service ITSPlatform, ITSPlatformManager -ErrorAction SilentlyContinue
if ($rmmSvcs) {
    $rmmSvcs | ForEach-Object { Write-Output "RMM svc $($_.Name): $($_.Status)" }
} else {
    Write-Output "RMM svcs: not found"
}

# --- Event log (route bulk to file, emit summary) ---
$events = $null
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application' } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -like '*ScreenConnect*' } |
        Select-Object -First 20
} catch { $events = $null }

if ($events) {
    $events | Select-Object TimeCreated, LevelDisplayName, Message |
        Format-List | Out-File -FilePath $outFile -Encoding ASCII
    $errCount  = ($events | Where-Object { $_.Level -le 2 }).Count
    $warnCount = ($events | Where-Object { $_.Level -eq 3 }).Count
    Write-Output "Event log (last 20 SC entries): $errCount errors, $warnCount warnings -- detail: $outFile"
    $latest = $events | Where-Object { $_.Level -le 2 } | Select-Object -First 1
    if ($latest) {
        $msg = $latest.Message
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
        Write-Output "  Latest error ($($latest.TimeCreated)): $msg"
    }
} else {
    Write-Output "Event log: no ScreenConnect entries found in last 500 Application events"
}

exit 0
