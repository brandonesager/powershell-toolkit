<#
.SYNOPSIS
    GP Operational log pull with CSE 4016/5016 hang detection
.DESCRIPTION
    Queries the Microsoft-Windows-GroupPolicy/Operational event log for CSE
    start (4016) and end (5016) events. Unmatched 4016 entries identify
    Client-Side Extensions that hung during background policy refresh.
    Also reports GP scheduled task state and gpresult computer summary.
.NOTES
    Date: 2026-02-25
    Context: SYSTEM (RMM) or interactive
    Module: None required
.KEYWORDS
    diagnostic, group-policy, cse, gpupdate, software-installation
#>

$ErrorActionPreference = "Stop"

try {
    Write-Output "=== GP OPERATIONAL LOG - CSE HANG DETECTION ==="
    Write-Output "Server: $($env:COMPUTERNAME)"
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    # Check for stuck CSEs: Event 4016 (start) without matching 5016 (end)
    Write-Output "=== CSE PROCESSING (Event 4016/5016) - Last 24 Hours ==="
    $dayAgo = (Get-Date).AddHours(-24)
    $cseEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-GroupPolicy/Operational'
        Id        = 4016, 5016
        StartTime = $dayAgo
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated

    if ($cseEvents) {
        $startCount  = ($cseEvents | Where-Object Id -eq 4016).Count
        $endCount    = ($cseEvents | Where-Object Id -eq 5016).Count
        $unmatched   = $startCount - $endCount
        Write-Output "CSE-START events (4016): $startCount"
        Write-Output "CSE-END   events (5016): $endCount"
        Write-Output "Unmatched (hung CSE sessions): $unmatched"
        Write-Output ""

        foreach ($evt in $cseEvents) {
            $time = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $type = if ($evt.Id -eq 4016) { "CSE-START" } else { "CSE-END  " }
            $msg  = ($evt.Message -split "`n")[0].Trim()
            Write-Output "[$time] $type $msg"
        }
    }
    else {
        Write-Output "No CSE processing events in last 24 hours"
    }

    # GP Operational log - recent window for incident triage
    Write-Output ""
    Write-Output "=== GP OPERATIONAL LOG - LAST 2 HOURS ==="
    $twoHoursAgo = (Get-Date).AddHours(-2)
    $recentEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-GroupPolicy/Operational'
        StartTime = $twoHoursAgo
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated

    if ($recentEvents) {
        Write-Output "Found $($recentEvents.Count) events"
        Write-Output ""
        foreach ($evt in $recentEvents) {
            $time = $evt.TimeCreated.ToString('HH:mm:ss')
            Write-Output "[$time] ID:$($evt.Id) Level:$($evt.LevelDisplayName) Task:$($evt.TaskDisplayName)"
            Write-Output "  $(($evt.Message -split "`n" | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | ')"
            Write-Output ""
        }
    }
    else {
        Write-Output "No GP events in last 2 hours"
    }

    # GP scheduled task status
    Write-Output "=== GP SCHEDULED TASKS ==="
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\GroupPolicy\' -ErrorAction SilentlyContinue |
        Select-Object TaskName, State,
            @{N='LastRun';E={$_.LastRunTime}},
            @{N='LastResult';E={$_.LastTaskResult}} |
        Format-Table -AutoSize | Out-String | Write-Output

    # gpresult summary
    Write-Output "=== GPRESULT COMPUTER SUMMARY ==="
    gpresult /r /scope:computer 2>&1 | Write-Output

    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
