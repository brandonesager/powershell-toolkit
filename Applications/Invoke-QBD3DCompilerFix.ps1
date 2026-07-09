<#
.SYNOPSIS
    Hash-verified swap of QuickBooks 2024 R19/R20 bundled D3DCOMPILER_47.dll with
    the Windows System32 copy on Server 2019 RDS hosts.

.DESCRIPTION
    QuickBooks Enterprise 2024 R19+ ships a stale D3DCOMPILER_47.dll inside the QB
    install folder. qbmapi64.exe (and qbw.exe) resolve the bundled copy via DLL search
    order, then fail with "Entry Point Not Found __CxxFrameHandler4" because that export
    exists only in the System32 build shipped with current Windows.

    This script:
      1. Aborts if any interactive QB process (qbw, qbmapi64) is running.
      2. Stops QB background processes (qbupdate, QBWebConnector) and the
         QBUpdateMonitorService.
      3. Compares SHA256 of the QB-folder DLL vs the System32 copy.
      4. If they differ, renames the QB copy to .bak-D3D and copies System32 over it.
      5. Verifies the post-copy hash matches System32.
      6. Restarts QBUpdateMonitorService.

    The fix must be repeated after any future QB 2024 update that re-ships the bad DLL
    (Intuit has not published a clean R-release as of 2026-05-29). Safe to run idempotent:
    if hashes already match, the script exits early with no changes.

.PARAMETER QbInstallDir
    Path to the QuickBooks install directory. Defaults to
    "C:\Program Files\Intuit\QuickBooks 2024". Adjust for QB Enterprise paths, e.g.
    "C:\Program Files\Intuit\QuickBooks Enterprise Solutions 24.0".

.NOTES
    Created: 2026-05-29
    Category: Applications
    Context: RMM shell (SYSTEM, PS 5.1)

.KEYWORDS
    QuickBooks, D3DCOMPILER, DLL, qbmapi64, __CxxFrameHandler4, RDS, Server 2019, fix
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$QbInstallDir = 'C:\Program Files\Intuit\QuickBooks 2024'
)

$ErrorActionPreference = 'Stop'

$qbDll  = Join-Path $QbInstallDir 'D3DCOMPILER_47.dll'
$qbBak  = Join-Path $QbInstallDir 'D3DCOMPILER_47.dll.bak-D3D'
$sysDll = 'C:\Windows\System32\D3DCOMPILER_47.dll'

Write-Output "=== Invoke-QBD3DCompilerFix ==="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "QB dir    : $QbInstallDir"
Write-Output ""

# --- Guard: interactive QB procs ---
$blockers = Get-Process -Name 'qbw', 'qbmapi64' -ErrorAction SilentlyContinue
if ($blockers) {
    Write-Output "ABORT: Interactive QuickBooks process running. Close all QB sessions first."
    $blockers | ForEach-Object {
        Write-Output ("  PID {0}  {1}  Session {2}  Start {3}" -f $_.Id, $_.Name, $_.SessionId, $_.StartTime)
    }
    exit 1
}

# --- Stop background QB procs ---
Write-Output "=== Stopping QB background processes ==="
foreach ($n in @('qbupdate', 'QBWebConnector', 'QBCFMonitorService', 'QBIDPService')) {
    $p = Get-Process -Name $n -ErrorAction SilentlyContinue
    if ($p) {
        Write-Output ("Stopping {0} (PID {1})" -f $p.Name, $p.Id)
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
}

$svc = Get-Service -Name 'QBUpdateMonitorService' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Output "Stopping QBUpdateMonitorService"
    Stop-Service -Name 'QBUpdateMonitorService' -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 3

# --- Validate paths ---
if (-not (Test-Path $qbDll)) {
    Write-Output "ABORT: QB DLL not found at $qbDll"
    Write-Output "       Set -QbInstallDir to the correct QB install folder."
    exit 1
}
if (-not (Test-Path $sysDll)) {
    Write-Output "ABORT: System32 DLL not found at $sysDll"
    exit 1
}

# --- Hash compare ---
Write-Output ""
Write-Output "=== Hash comparison ==="
$qbHash  = (Get-FileHash $qbDll  -Algorithm SHA256).Hash
$sysHash = (Get-FileHash $sysDll -Algorithm SHA256).Hash
Write-Output ("QB DLL SHA256  : {0}" -f $qbHash)
Write-Output ("Sys DLL SHA256 : {0}" -f $sysHash)

if ($qbHash -eq $sysHash) {
    Write-Output "Hashes already match. No change needed."
    if ($svc) { Start-Service -Name 'QBUpdateMonitorService' -ErrorAction SilentlyContinue }
    exit 0
}

# --- Replace DLL ---
Write-Output ""
Write-Output "=== Replacing DLL ==="
if (Test-Path $qbBak) {
    Write-Output "Removing old backup: $qbBak"
    Remove-Item $qbBak -Force
}
Rename-Item -Path $qbDll -NewName (Split-Path $qbBak -Leaf)
Write-Output "Renamed QB DLL to $(Split-Path $qbBak -Leaf)"

Copy-Item -Path $sysDll -Destination $qbDll -Force
Write-Output "Copied System32 DLL to $qbDll"

# --- Verify ---
$newHash = (Get-FileHash $qbDll -Algorithm SHA256).Hash
Write-Output ("Post-copy SHA256: {0}" -f $newHash)
if ($newHash -eq $sysHash) {
    Write-Output "OK: QB DLL hash matches System32. Fix applied."
} else {
    Write-Output "FAIL: Hash mismatch after copy. Restore backup and investigate."
    exit 1
}

# --- Restart service ---
if ($svc) {
    Start-Service -Name 'QBUpdateMonitorService' -ErrorAction SilentlyContinue
    $svcAfter = Get-Service -Name 'QBUpdateMonitorService' -ErrorAction SilentlyContinue
    Write-Output ("QBUpdateMonitorService: {0}" -f $svcAfter.Status)
}

Write-Output ""
Write-Output "=== Done ==="
Write-Output "Have the user relaunch QuickBooks and reopen the company file."
Write-Output "Note: this fix reverts on any QB 2024 update that re-ships the bad DLL."
Write-Output "Backup preserved at: $qbBak"
