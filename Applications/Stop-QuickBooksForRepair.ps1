<#
.SYNOPSIS
    Stop all QuickBooks processes and lock-holding services before running a repair.

.DESCRIPTION
    Stops interactive QB processes (qbw, qbw32, qbmapi64, QBDBMgr, QBDBMgr64) plus
    the two services that hold file locks during a running session
    (QBCFMonitorService and QBDBMgrN) so that an Apps and Features Repair or MSI
    repair can proceed without a file-in-use error.

    Output lists every process and service stopped. If interactive QB sessions are
    detected on any active RDS or console session, the script aborts rather than
    terminating live user work.

    Intended to run immediately before the repair action. Pair with
    Confirm-QbCefPairMatch.ps1 after the repair completes.

.PARAMETER Force
    Suppress the interactive-session abort guard and stop processes regardless.
    Use only when all users are confirmed away from QuickBooks.

.NOTES
    Created: 2026-05-29
    Category: Applications
    Context: RMM shell (SYSTEM, PS 5.1 on QB host)

.KEYWORDS
    QuickBooks, repair, CefAdapter, libcef, QBCFMonitorService, QBDBMgrN,
    stop, RDS, pre-repair
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [switch]$Force
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== Stop-QuickBooksForRepair ==="
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ""

# --- Guard: active interactive QB sessions ---
$interactiveProcs = @('qbw', 'qbw32', 'qbmapi64')
$liveQb = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $interactiveProcs -contains $_.Name -and $_.SessionId -ne 0
}

if ($liveQb -and -not $Force) {
    Write-Output "ABORT: QuickBooks is open in one or more user sessions."
    Write-Output "       Have all users close QuickBooks before running this script."
    Write-Output "       To override, re-run with -Force (confirm no active user work first)."
    Write-Output ""
    $liveQb | ForEach-Object {
        Write-Output ("  PID {0,6}  Name {1,-16}  Session {2}  Started {3}" -f $_.Id, $_.Name, $_.SessionId, $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
    }
    exit 1
}

# --- Stop interactive QB processes ---
Write-Output "=== Stopping QB processes ==="
$allProcNames = @('qbw', 'qbw32', 'qbmapi64', 'QBDBMgr', 'QBDBMgr64', 'qbupdate', 'QBWebConnector', 'QBIDPService')
$stopped = 0

foreach ($name in $allProcNames) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        Write-Output ("  Stopping {0} (PID {1}, Session {2})" -f $p.Name, $p.Id, $p.SessionId)
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $stopped++
    }
}

if ($stopped -eq 0) {
    Write-Output "  No QB processes running."
} else {
    Write-Output ("  Stopped {0} process(es)." -f $stopped)
}

Start-Sleep -Seconds 2

# --- Stop lock-holding services ---
Write-Output ""
Write-Output "=== Stopping QB services ==="

$svcNames = @('QBCFMonitorService', 'QBDBMgrN')
foreach ($svcName in $svcNames) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Output ("  {0}: not installed" -f $svcName)
        continue
    }
    if ($svc.Status -eq 'Stopped') {
        Write-Output ("  {0}: already stopped" -f $svcName)
        continue
    }
    Write-Output ("  Stopping {0} (Status: {1})" -f $svcName, $svc.Status)
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $svc.Refresh()
    Write-Output ("  {0}: {1}" -f $svcName, $svc.Status)
}

# --- Verify no QB procs remain ---
Write-Output ""
Write-Output "=== Post-stop verification ==="
$remaining = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^QB|quickbooks' }
if ($remaining) {
    Write-Output "WARNING: QB processes still running:"
    $remaining | ForEach-Object {
        Write-Output ("  PID {0,6}  {1}  Session {2}" -f $_.Id, $_.Name, $_.SessionId)
    }
    Write-Output "Repair may fail if these hold file locks. Investigate before proceeding."
    exit 2
} else {
    Write-Output "  No QB processes remain. Safe to proceed with repair."
}

Write-Output ""
Write-Output "=== Ready for repair ==="
Write-Output "Run: Apps and Features > QuickBooks Enterprise Solutions > Change > Repair"
Write-Output "After repair completes, run Confirm-QbCefPairMatch.ps1 to verify CEF pair."
