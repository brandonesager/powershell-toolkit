<#
.SYNOPSIS
    Full-tree icacls /save backup of a folder tree's ACLs, with item count and
    a PowerShell-level report of all items with inheritance disabled.

.DESCRIPTION
    Produces two outputs:
      1. icacls /save backup file at -BackupPath (default: alongside root folder).
         Restore command is printed to output.
      2. A structured PowerShell-level report:
         - Total folders and files scanned
         - Items with inheritance disabled (AreAccessRulesProtected = true)
         - Critical: items with disabled inheritance where target identity is absent
         - Warning: items with Deny ACEs
         - Per-folder listing with [NO-USER] and [DENY] flags

    Intended as the first step before Repair-DeepInheritance.ps1 to understand
    the scope of ACL breakage before making any changes.

    Read-only. No ACL modifications.

.PARAMETER RootPath
    Root folder to audit. All subfolders and files are scanned recursively.

.PARAMETER IdentityPattern
    Regex pattern matching the identity that SHOULD have access. Items where no
    ACE matches this pattern are flagged [NO-USER]. Default: match any identity
    (no flagging). Set to a SamAccountName or group name to flag missing access.

.PARAMETER BackupPath
    Path for the icacls /save backup file. Default: parent of RootPath with
    a timestamped name.

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1, RMM RMM shell on file server)

.KEYWORDS
    ACL, inheritance, icacls, audit, folder, permissions, NTFS, protection,
    deep scan, backup
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$RootPath,

    [string]$IdentityPattern = '',

    [string]$BackupPath = ''
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $RootPath)) {
    Write-Output ("ABORT: RootPath not found: {0}" -f $RootPath)
    exit 1
}
if (-not $BackupPath) {
    $BackupPath = Join-Path (Split-Path $RootPath -Parent) ("acl-backup-{0}-{1}.txt" -f (Split-Path $RootPath -Leaf), (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

Write-Output "Invoke-DeepAclAudit"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("RootPath  : {0}" -f $RootPath)
Write-Output ("BackupPath: {0}" -f $BackupPath)
Write-Output ""

# --- Phase 1: icacls backup ---
Write-Output "=== Phase 1: ACL Backup (icacls /save) ==="
$null = & icacls $RootPath /save $BackupPath /T /C /Q 2>&1
if (Test-Path $BackupPath) {
    $sz = [math]::Round((Get-Item $BackupPath).Length / 1KB, 1)
    Write-Output ("Backup saved: {0}  ({1} KB)" -f $BackupPath, $sz)
    Write-Output ("Restore cmd : icacls `"{0}`" /restore `"{1}`" /C" -f (Split-Path $RootPath -Parent), $BackupPath)
} else {
    Write-Output ("WARNING: Backup file not created at {0}" -f $BackupPath)
}
Write-Output ""

# --- Phase 2: PowerShell ACL scan ---
Write-Output "=== Phase 2: Inheritance Audit ==="
$protDirs  = [System.Collections.ArrayList]::new()
$protFiles = [System.Collections.ArrayList]::new()
$errList   = [System.Collections.ArrayList]::new()
$totalDirs = 0
$totalFiles= 0

$allItems = Get-ChildItem -LiteralPath $RootPath -Recurse -Force
foreach ($item in $allItems) {
    if ($item.PSIsContainer) { $totalDirs++ } else { $totalFiles++ }
    try {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if ($acl.AreAccessRulesProtected) {
            $rel       = $item.FullName.Replace($RootPath, '.')
            $aceStr    = $acl.Access | ForEach-Object { "$($_.IdentityReference)($($_.AccessControlType)/$($_.FileSystemRights))" }
            $hasTarget = -not $IdentityPattern -or ($acl.Access | Where-Object { $_.IdentityReference -match $IdentityPattern })
            $hasDeny   = [bool]($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
            $info      = [PSCustomObject]@{
                Path      = $rel
                HasTarget = [bool]$hasTarget
                HasDeny   = $hasDeny
                ACEs      = $aceStr -join ' | '
            }
            if ($item.PSIsContainer) { $null = $protDirs.Add($info) }
            else { $null = $protFiles.Add($info) }
        }
    } catch {
        $null = $errList.Add(("{0}: {1}" -f $item.FullName, $_.Exception.Message))
    }
}

Write-Output ("  Folders scanned  : {0}" -f $totalDirs)
Write-Output ("  Files scanned    : {0}" -f $totalFiles)
Write-Output ("  Total            : {0}" -f ($totalDirs + $totalFiles))
Write-Output ("  Inheritance OFF  : {0} folders, {1} files" -f $protDirs.Count, $protFiles.Count)
Write-Output ("  Errors           : {0}" -f $errList.Count)
Write-Output ""

# Critical: no target access
if ($IdentityPattern) {
    $noAccess = @(($protDirs + $protFiles) | Where-Object { -not $_.HasTarget })
    if ($noAccess.Count -gt 0) {
        Write-Output ("CRITICAL: {0} item(s) with inheritance disabled AND no ACE matching '{1}':" -f $noAccess.Count, $IdentityPattern)
        $shown = 0
        foreach ($item in $noAccess) {
            if ($shown -ge 100) { Write-Output ("  ... and {0} more" -f ($noAccess.Count - 100)); break }
            Write-Output ("  {0}" -f $item.Path)
            Write-Output ("    {0}" -f $item.ACEs)
            $shown++
        }
        Write-Output ""
    }
}

# Deny ACEs
$denyItems = @(($protDirs + $protFiles) | Where-Object { $_.HasDeny })
if ($denyItems.Count -gt 0) {
    Write-Output ("WARNING: {0} item(s) with Deny ACEs:" -f $denyItems.Count)
    $denyItems | ForEach-Object { Write-Output ("  {0}" -f $_.Path) }
    Write-Output ""
}

# Folder listing
if ($protDirs.Count -gt 0) {
    Write-Output ("FOLDERS WITH INHERITANCE DISABLED ({0}):" -f $protDirs.Count)
    foreach ($d in $protDirs) {
        $tag = ''
        if (-not $d.HasTarget -and $IdentityPattern) { $tag += ' [NO-TARGET]' }
        if ($d.HasDeny) { $tag += ' [DENY]' }
        Write-Output ("  {0}{1}" -f $d.Path, $tag)
    }
    Write-Output ""
}

if ($protFiles.Count -gt 0) {
    Write-Output ("FILES WITH INHERITANCE DISABLED ({0})" -f $protFiles.Count)
    $shown = 0
    $groups = @{}
    foreach ($f in $protFiles) {
        $parent = Split-Path $f.Path -Parent
        if (-not $parent) { $parent = '.' }
        if (-not $groups.ContainsKey($parent)) { $groups[$parent] = [System.Collections.ArrayList]::new() }
        $null = $groups[$parent].Add($f)
    }
    foreach ($key in ($groups.Keys | Sort-Object)) {
        $grp = $groups[$key]
        Write-Output ("  {0}/ ({1} files)" -f $key, $grp.Count)
        foreach ($f in $grp) {
            if ($shown -ge 500) { Write-Output ("  ... truncated at 500. {0} more." -f ($protFiles.Count - 500)); break }
            $name = Split-Path $f.Path -Leaf
            $tag  = ''
            if (-not $f.HasTarget -and $IdentityPattern) { $tag += ' [NO-TARGET]' }
            if ($f.HasDeny) { $tag += ' [DENY]' }
            Write-Output ("    {0}{1}" -f $name, $tag)
            $shown++
        }
        if ($shown -ge 500) { break }
    }
    Write-Output ""
}

if ($errList.Count -gt 0) {
    Write-Output ("ERRORS ({0}):" -f $errList.Count)
    $errList | ForEach-Object { Write-Output ("  {0}" -f $_) }
    Write-Output ""
}

Write-Output "=== AUDIT COMPLETE ==="
Write-Output ""
Write-Output "If inheritance repair is needed, run Repair-DeepInheritance.ps1 with the same -RootPath."
Write-Output ("Backup for restore: {0}" -f $BackupPath)
