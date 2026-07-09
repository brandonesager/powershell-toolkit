<#
.SYNOPSIS
    Diagnose high Pages Output/sec or memory-pressure alerts on a Windows endpoint
    and surface the most likely root cause in a single read-only run.

.DESCRIPTION
    Designed for RMM RMM shell (SYSTEM, PS 5.1, plain-text output).
    Captures a 30-second Performance Monitor sample of memory and paging counters,
    enumerates top working-set processes, scores commit pressure, page-file sizing,
    nonpaged pool growth, browser/Teams cumulative footprint, and recent
    Resource-Exhaustion events, then prints a ranked flag list and a confidence
    tag for the likely root cause.

    Counter rationale per Microsoft Learn:
      - Pages Output/sec: pages written to pagefile to free RAM (the alert source).
        High value alone is not conclusive; correlate with Available MBytes and
        Committed Bytes vs Commit Limit.
      - Committed Bytes >= installed RAM with sustained Pages Output/sec indicates
        true memory pressure.
      - Pool Nonpaged Bytes elevated above expected baseline suggests a driver leak.
      - Paging File % Usage sustained >75% indicates an undersized or fixed pagefile.

    References:
      https://learn.microsoft.com/troubleshoot/windows-server/performance/ram-virtual-memory-pagefile-management
      https://learn.microsoft.com/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows
      https://learn.microsoft.com/biztalk/technical-guides/system-level-bottlenecks

.NOTES
    Context:  RMM RMM shell (SYSTEM, PS 5.1, non-interactive). Runs
              equally well in SYSTEM remote session or any elevated PS 5.1 session. Read-only.
    Runtime:  ~35 seconds (30s counter sample + enumeration)
    Output:   Plain text, capped well under 10K chars

.KEYWORDS
    paging, memory pressure, pages output, working set, commit charge, pagefile,
    pool nonpaged, leak, slow performance, diagnostic, RMM alert, perfmon
#>

#timeout=60000
#maxlength=20000

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$line     = ('=' * 72)
$flags    = New-Object System.Collections.Generic.List[string]

function Add-Flag { param($Severity, $Text) $flags.Add("[$Severity] $Text") }

# 1. System snapshot
$os    = Get-CimInstance Win32_OperatingSystem
$cs    = Get-CimInstance Win32_ComputerSystem
$bios  = Get-CimInstance Win32_BIOS
$totalRamGB   = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$availMB      = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
$availPct     = [math]::Round(($availMB / ($totalRamGB * 1024)) * 100, 1)
$commitMB     = [math]::Round(($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1KB, 0)
$commitLimMB  = [math]::Round($os.TotalVirtualMemorySize / 1KB, 0)
$commitPct    = [math]::Round(($commitMB / $commitLimMB) * 100, 1)
$uptimeHours  = [math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours, 1)

"$line"
"Paging Pressure Diagnostic — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"$line"
"Host        : $($cs.Name)"
"Model       : $($cs.Manufacturer) $($cs.Model)"
"BIOS        : $($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate.ToString('yyyy-MM-dd')))"
"OS          : $($os.Caption) $($os.Version)"
"Uptime      : $uptimeHours hours since $($os.LastBootUpTime)"
"Installed   : $totalRamGB GB RAM"
"Available   : $availMB MB ($availPct%)"
"Commit      : $commitMB MB / $commitLimMB MB ($commitPct%)"

if ($availPct -lt 10)  { Add-Flag 'HIGH' "Available memory under 10% ($availPct%)" }
if ($commitPct -gt 90) { Add-Flag 'HIGH' "Commit charge over 90% of limit ($commitPct%)" }
if ($uptimeHours -gt 168) { Add-Flag 'INFO' "Uptime exceeds 7 days; reboot may release standby leaks" }

# 2. Page file configuration
""
"$line"
"PAGE FILE CONFIGURATION"
"$line"
$pfAuto = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
"Auto-managed: $pfAuto"
$pfSettings = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
if ($pfSettings) {
    foreach ($pf in $pfSettings) {
        "  Path: $($pf.Name)  Initial: $($pf.InitialSize) MB  Max: $($pf.MaximumSize) MB"
        if ($pf.MaximumSize -gt 0 -and $pf.MaximumSize -lt ($totalRamGB * 1024)) {
            Add-Flag 'MED' "Page file max ($($pf.MaximumSize) MB) is smaller than installed RAM"
        }
    }
} else {
    "  (system-managed, no static entries)"
}
$pfUsage = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
if ($pfUsage) {
    foreach ($pu in $pfUsage) {
        $pct = if ($pu.AllocatedBaseSize -gt 0) { [math]::Round(($pu.CurrentUsage / $pu.AllocatedBaseSize) * 100, 1) } else { 0 }
        "  In-use: $($pu.Name)  $($pu.CurrentUsage) / $($pu.AllocatedBaseSize) MB ($pct%)  Peak $($pu.PeakUsage) MB"
        if ($pct -gt 75) { Add-Flag 'HIGH' "Page file $pct% in use (Microsoft Learn flags >75% as undersized)" }
    }
}

# 3. Counter sample (30 seconds, 6 samples at 5s)
""
"$line"
"COUNTER SAMPLE (30s, 6 samples @ 5s)"
"$line"
$counters = @(
    '\Memory\Pages Output/sec',
    '\Memory\Pages Input/sec',
    '\Memory\Page Reads/sec',
    '\Memory\Page Faults/sec',
    '\Memory\Available MBytes',
    '\Memory\Committed Bytes',
    '\Memory\Commit Limit',
    '\Memory\Pool Nonpaged Bytes',
    '\Memory\Pool Paged Bytes',
    '\Memory\Modified Page List Bytes',
    '\Memory\Standby Cache Normal Priority Bytes',
    '\Paging File(_Total)\% Usage',
    '\Processor(_Total)\% Processor Time',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer'
)
$sample = Get-Counter -Counter $counters -SampleInterval 5 -MaxSamples 6 -ErrorAction SilentlyContinue
if (-not $sample) {
    "ERROR: Get-Counter returned no data. Check Performance Logs and Alerts service."
    Add-Flag 'HIGH' "Performance counter collection failed"
} else {
    $agg = @{}
    foreach ($s in $sample) {
        foreach ($c in $s.CounterSamples) {
            if (-not $agg.ContainsKey($c.Path)) { $agg[$c.Path] = New-Object System.Collections.Generic.List[double] }
            $agg[$c.Path].Add([double]$c.CookedValue)
        }
    }
    $rows = foreach ($k in $agg.Keys) {
        $vals = $agg[$k]
        [pscustomobject]@{
            Counter = ($k -replace '^\\\\[^\\]+', '')
            Avg     = [math]::Round(($vals | Measure-Object -Average).Average, 1)
            Max     = [math]::Round(($vals | Measure-Object -Maximum).Maximum, 1)
        }
    }
    $rows | Sort-Object Counter | Format-Table -AutoSize | Out-String -Width 120

    $pgOutAvg = ($rows | Where-Object Counter -like '*Pages Output/sec*').Avg
    $availAvg = ($rows | Where-Object Counter -like '*Available MBytes*').Avg
    $commitAvg = ($rows | Where-Object Counter -like '*Committed Bytes*').Avg
    $commitLim = ($rows | Where-Object Counter -like '*Commit Limit*').Avg
    $nonpaged  = ($rows | Where-Object Counter -like '*Pool Nonpaged Bytes*').Avg
    $diskSec   = ($rows | Where-Object Counter -like '*Avg. Disk sec/Transfer*').Avg
    $pfPct     = ($rows | Where-Object Counter -like '*Paging File*% Usage*').Avg

    "Live Pages Output/sec average: $pgOutAvg (RMM alert threshold typically 2925)"
    if ($pgOutAvg -gt 2925) { Add-Flag 'HIGH' "Pages Output/sec still above alert threshold ($pgOutAvg avg)" }
    elseif ($pgOutAvg -gt 500) { Add-Flag 'MED' "Pages Output/sec elevated but below alert threshold ($pgOutAvg avg)" }
    else { Add-Flag 'INFO' "Pages Output/sec returned to baseline ($pgOutAvg avg) — alert may be stale" }

    if ($commitLim -gt 0 -and $commitAvg -gt 0) {
        $commitRatio = [math]::Round(($commitAvg / $commitLim) * 100, 1)
        "Live Commit ratio       : $commitRatio%"
        if ($commitRatio -gt 90) { Add-Flag 'HIGH' "Commit ratio $commitRatio% — true memory exhaustion" }
    }
    if ($nonpaged -gt 600MB) { Add-Flag 'MED' "Pool Nonpaged Bytes $([math]::Round($nonpaged/1MB,0)) MB — possible driver leak" }
    if ($diskSec -gt 0.025)  { Add-Flag 'MED' "Avg disk latency $([math]::Round($diskSec*1000,1)) ms — paging amplifies on slow disk" }
}

# 4. Top working-set processes
""
"$line"
"TOP 10 PROCESSES BY WORKING SET"
"$line"
$procs = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10
$procRows = foreach ($p in $procs) {
    [pscustomobject]@{
        PID      = $p.Id
        Name     = $p.ProcessName
        WS_MB    = [math]::Round($p.WorkingSet64 / 1MB, 0)
        Priv_MB  = [math]::Round($p.PrivateMemorySize64 / 1MB, 0)
        Handles  = $p.HandleCount
        Threads  = $p.Threads.Count
    }
}
$procRows | Format-Table -AutoSize | Out-String -Width 120

$topWS = ($procRows | Select-Object -First 1)
if ($topWS.WS_MB -gt ($totalRamGB * 1024 * 0.4)) {
    Add-Flag 'HIGH' "Process '$($topWS.Name)' (PID $($topWS.PID)) holds $($topWS.WS_MB) MB working set (>40% of RAM)"
}

# Browser/Teams cumulative footprint (common culprit on 16 GB workstations)
$browserNames = 'chrome','msedge','firefox','brave','opera','vivaldi'
$teamsNames   = 'ms-teams','Teams','Outlook'
$browserMB = (Get-Process -Name $browserNames -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum / 1MB
$teamsMB   = (Get-Process -Name $teamsNames   -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum / 1MB
"Browser footprint total : $([math]::Round($browserMB,0)) MB"
"Teams/Outlook footprint : $([math]::Round($teamsMB,0)) MB"
if ($browserMB -gt 4096) { Add-Flag 'MED' "Browser working set exceeds 4 GB (cumulative tabs)" }

# 5. Recent memory-related events (last 24h)
""
"$line"
"RECENT MEMORY/RESOURCE EVENTS (24h)"
"$line"
$since = (Get-Date).AddHours(-24)
$evtIds = 2004, 333, 51, 41, 1001  # Resource-Exhaustion-Detector, paging IO, BugCheck, app crash
$events = Get-WinEvent -FilterHashtable @{ LogName = 'System','Application'; StartTime = $since } -MaxEvents 400 -ErrorAction SilentlyContinue |
    Where-Object { $evtIds -contains $_.Id -or $_.ProviderName -match 'Resource-Exhaustion|Memory Diagnostic' }
if ($events) {
    $events | Sort-Object TimeCreated -Descending | Select-Object -First 8 TimeCreated, Id, ProviderName, LevelDisplayName |
        Format-Table -AutoSize | Out-String -Width 120
    if ($events | Where-Object Id -eq 2004) {
        Add-Flag 'HIGH' "Windows Resource-Exhaustion-Detector (Event 2004) fired in last 24h — confirms low-memory condition"
    }
} else {
    "No memory-related events recorded in the last 24h."
}

# 6. Likely root cause synthesis
""
"$line"
"LIKELY ROOT CAUSE"
"$line"
$ranked = $flags | Where-Object { $_ -match '^\[HIGH\]' }
if (-not $ranked) { $ranked = $flags | Where-Object { $_ -match '^\[MED\]' } }
if (-not $ranked) { $ranked = $flags | Where-Object { $_ -match '^\[INFO\]' } }

if ($ranked) {
    foreach ($f in $flags) { $f }
    ""
    "Confidence: $(if ($flags | Where-Object { $_ -match '^\[HIGH\]' }) { 'HIGH — multiple corroborating indicators' } elseif ($flags | Where-Object { $_ -match '^\[MED\]' }) { 'MEDIUM — single suggestive indicator' } else { 'LOW — alert may be stale, recommend follow-up sample' })"
} else {
    "No pressure indicators detected at sample time. Alert was likely transient — recommend a second pass during business hours or correlate with user-reported slowdown window."
}

""
"$line"
"END OF REPORT"
"$line"
