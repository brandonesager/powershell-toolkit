<#
.SYNOPSIS
    Local Software Installation CSE state check on an affected server
.DESCRIPTION
    Examines AppMgmt registry for orphaned product entries, checks the local
    GP cache and state for the Software Installation CSE, reports pending
    reboot indicators, and counts active gpupdate processes. Use after
    identifying a GP Software Installation CSE hang (Events 7016/6035/8016)
    to confirm root cause and scope on the affected machine.
.NOTES
    Date: 2026-02-25
    Context: SYSTEM (RMM) or interactive
    Module: None required
.KEYWORDS
    diagnostic, group-policy, software-installation, cse, gpupdate, pending-reboot
#>

$ErrorActionPreference = "Stop"

Write-Output "=== LOCAL SOFTWARE INSTALLATION CSE CHECK ==="
Write-Output "Server: $($env:COMPUTERNAME)"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

# Active gpupdate processes
Write-Output "=== GPUPDATE PROCESSES ==="
$gpProcs = Get-Process -Name gpupdate -ErrorAction SilentlyContinue
if ($gpProcs) {
    Write-Output "ACTIVE gpupdate processes: $($gpProcs.Count)"
    foreach ($p in $gpProcs) {
        Write-Output "  PID: $($p.Id) | CPU: $([math]::Round($p.CPU, 1))s | Start: $($p.StartTime) | Threads: $($p.Threads.Count)"
    }
}
else {
    Write-Output "No gpupdate processes running"
}
Write-Output ""

# Pending reboot check
Write-Output "=== PENDING REBOOT CHECK ==="
$rebootKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)
$pendingFound = $false
foreach ($rk in $rebootKeys) {
    if (Test-Path $rk) {
        Write-Output "PENDING REBOOT: $rk exists"
        $pendingFound = $true
    }
}
$pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($pfro.PendingFileRenameOperations) {
    Write-Output "PENDING REBOOT: PendingFileRenameOperations exists ($($pfro.PendingFileRenameOperations.Count) entries)"
    $pendingFound = $true
}
if (-not $pendingFound) {
    Write-Output "No pending reboot detected"
}
Write-Output ""

# AppMgmt registry — orphaned Software Installation product entries
Write-Output "=== APPMGMT REGISTRY (Software Installation Products) ==="
$appMgmt = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\AppMgmt'
if (Test-Path $appMgmt) {
    $subkeys = Get-ChildItem $appMgmt -ErrorAction SilentlyContinue
    Write-Output "Product entries found: $($subkeys.Count)"
    foreach ($sk in $subkeys) {
        Write-Output ""
        Write-Output "  Product: $($sk.PSChildName)"
        $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
        if ($props.'Deployment Name') { Write-Output "    Deployment Name: $($props.'Deployment Name')" }
        if ($props.'GPO Name')        { Write-Output "    GPO Name:        $($props.'GPO Name')" }
        if ($props.'Product ID')      { Write-Output "    Product ID:      $($props.'Product ID')" }
        if ($null -ne $props.State)   { Write-Output "    State:           $($props.State)" }
    }
}
else {
    Write-Output "No AppMgmt key found — no Software Installation GPOs applied to this machine"
}
Write-Output ""

# Software Installation CSE GP history and state
$cseGuid = '{C6DC5466-785A-11D2-84D0-00C04FB169F7}'
Write-Output "=== GP HISTORY - SOFTWARE INSTALLATION CSE ==="
$gpHistory = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\$cseGuid"
if (Test-Path $gpHistory) {
    Write-Output "CSE history exists (GP has applied this CSE before)"
    Get-ChildItem $gpHistory -ErrorAction SilentlyContinue | ForEach-Object {
        $hp = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        Write-Output "  GPO: $($hp.DisplayName) | GUID: $($hp.GPOName) | Link: $($hp.Link)"
    }
}
else {
    Write-Output "No Software Installation CSE history in registry (CSE has not successfully completed)"
}
Write-Output ""

Write-Output "=== GP STATE - SOFTWARE INSTALLATION CSE ==="
$gpState = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\$cseGuid"
if (Test-Path $gpState) {
    Write-Output "CSE state entry EXISTS — GP engine considers this CSE active"
    Get-ChildItem $gpState -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  $($_.PSChildName)"
    }
}
else {
    Write-Output "No CSE state entry found"
}
Write-Output ""

# Last boot time
Write-Output "=== LAST BOOT TIME ==="
$os = Get-CimInstance Win32_OperatingSystem
$uptime = New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)
Write-Output "Last Boot: $($os.LastBootUpTime)"
Write-Output "Uptime: $($uptime.ToString('d\.hh\:mm\:ss'))"
Write-Output ""

Write-Output "=== DONE ==="
exit 0
