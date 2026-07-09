<#
.SYNOPSIS
    Re-enable NTFS inheritance on every item in a deep folder tree using icacls.

.DESCRIPTION
    Runs icacls /inheritance:e /T /C /Q against the root path to restore ACL
    inheritance propagation across all subfolders and files that had it disabled.

    Sequence:
      1. ACL backup via icacls /save to a timestamped file (restoreable with
         icacls <parent> /restore <backup> /C). Aborts if backup fails.
      2. icacls /inheritance:e /T /C /Q to re-enable inheritance on all items.
      3. PowerShell-level verification: counts folders still showing
         AreAccessRulesProtected = true and lists them for follow-up.

    Reports: item count processed, failures from icacls, folders still protected
    post-fix, verification errors, and the backup file path for restore.

    Safe to re-run: /inheritance:e on an already-inheriting item is a no-op.

    Root-level folder is not touched (icacls targets $RootPath\* via the wildcard).
    If the root itself has inheritance disabled, fix it separately with:
    icacls <RootPath> /inheritance:e

    Companion script: Invoke-DeepAclAudit.ps1 (read-only audit before this fix).

.PARAMETER RootPath
    Root folder whose contents will have inheritance re-enabled. All subfolders
    and files underneath are processed recursively.

.PARAMETER BackupPath
    Where to save the icacls /save backup file.
    Default: same directory as RootPath, named acl-backup-<FolderName>-<timestamp>.txt

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1 on file server)

.KEYWORDS
    ACL, inheritance, icacls, NTFS, permissions, folder, repair, deep tree,
    inheritance restore, file server
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$RootPath,

    [string]$BackupPath = ''
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $RootPath)) {
    Write-Output ("ABORT: RootPath not found: {0}" -f $RootPath)
    exit 1
}

if (-not $BackupPath) {
    $leaf = Split-Path $RootPath -Leaf
    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupPath = Join-Path (Split-Path $RootPath -Parent) ("acl-backup-{0}-{1}.txt" -f $leaf, $ts)
}

Write-Output "=== Repair-DeepInheritance ==="
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("RootPath  : {0}" -f $RootPath)
Write-Output ("BackupPath: {0}" -f $BackupPath)
Write-Output ""

# --- Phase 1: ACL backup ---
Write-Output "=== Phase 1: ACL Backup ==="
$null = & icacls $RootPath /save $BackupPath /T /C /Q 2>&1
if (Test-Path $BackupPath) {
    $sz = [math]::Round((Get-Item $BackupPath).Length / 1KB, 1)
    Write-Output ("Backup saved : {0}  ({1} KB)" -f $BackupPath, $sz)
    Write-Output ("Restore cmd  : icacls `"{0}`" /restore `"{1}`" /C" -f (Split-Path $RootPath -Parent), $BackupPath)
} else {
    Write-Output ("ABORT: icacls /save did not produce a file at {0}" -f $BackupPath)
    Write-Output "Repair cancelled. Investigate backup path permissions before retrying."
    exit 1
}
Write-Output ""

# --- Phase 2: Re-enable inheritance ---
Write-Output "=== Phase 2: Enabling inheritance (icacls /inheritance:e /T /C /Q) ==="
Write-Output ("Target: {0}\*" -f $RootPath)
$fixOutput = & icacls ("$RootPath\*") /inheritance:e /T /C /Q 2>&1
$processed = 0
$failed    = 0
$failLines = [System.Collections.ArrayList]::new()

foreach ($line in $fixOutput) {
    $lineStr = "$line"
    if ($lineStr -match 'processed file:' -or $lineStr -match 'processed') {
        if ($lineStr -match '(\d+) file\(s\) processed') { $processed = [int]$Matches[1] }
        Write-Output ("  {0}" -f $lineStr)
    } elseif ($lineStr -match 'failed|error|access denied' -and $lineStr.Trim()) {
        $failed++
        $null = $failLines.Add($lineStr)
    } elseif ($lineStr.Trim()) {
        Write-Output ("  {0}" -f $lineStr)
    }
}
Write-Output ""

# --- Phase 3: PowerShell-level verification ---
Write-Output "=== Phase 3: Verification ==="
$stillProtected = 0
$verified       = 0
$verifyErrors   = 0
$protList       = [System.Collections.ArrayList]::new()

foreach ($dir in (Get-ChildItem -LiteralPath $RootPath -Directory -Recurse -Force -ErrorAction SilentlyContinue)) {
    try {
        $acl = Get-Acl -LiteralPath $dir.FullName -ErrorAction Stop
        if ($acl.AreAccessRulesProtected) {
            $stillProtected++
            $rel = $dir.FullName.Replace($RootPath, '.')
            $null = $protList.Add($rel)
        } else {
            $verified++
        }
    } catch {
        $verifyErrors++
    }
}

Write-Output ("Folders verified inheriting : {0}" -f $verified)
Write-Output ("Folders still protected     : {0}" -f $stillProtected)
Write-Output ("Verification errors         : {0}" -f $verifyErrors)
Write-Output ("icacls failures             : {0}" -f $failed)
Write-Output ("ACL backup                  : {0}" -f $BackupPath)

if ($stillProtected -gt 0) {
    Write-Output ""
    Write-Output ("STILL PROTECTED ({0}):" -f $stillProtected)
    $shown = 0
    foreach ($p in $protList) {
        if ($shown -ge 50) {
            Write-Output ("  ... and {0} more. Run Invoke-DeepAclAudit.ps1 for full list." -f ($stillProtected - 50))
            break
        }
        Write-Output ("  {0}" -f $p)
        $shown++
    }
}

if ($failLines.Count -gt 0) {
    Write-Output ""
    Write-Output ("icacls FAILURES ({0}):" -f $failLines.Count)
    $failLines | Select-Object -First 20 | ForEach-Object { Write-Output ("  {0}" -f $_) }
    if ($failLines.Count -gt 20) { Write-Output ("  ... and {0} more." -f ($failLines.Count - 20)) }
}

Write-Output ""
if ($stillProtected -eq 0 -and $failed -eq 0) {
    Write-Output "=== COMPLETE: All directories now inherit from parent. ==="
} elseif ($stillProtected -gt 0) {
    Write-Output "=== COMPLETE with residual protected items. Review the list above. ==="
    Write-Output "Long file paths and junctions can survive icacls /T. Run Invoke-DeepAclAudit.ps1 to investigate."
} else {
    Write-Output "=== COMPLETE. Review failures above. ==="
}
