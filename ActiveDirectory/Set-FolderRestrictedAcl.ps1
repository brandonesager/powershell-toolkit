<#
.SYNOPSIS
    Break folder inheritance and restrict access to a named list of accounts.

.DESCRIPTION
    Applies a closed ACL to a folder:
      1. Audits and reports the current ACL.
      2. Disables inheritance and converts inherited ACEs to explicit entries.
      3. Removes Domain Users and BUILTIN\Users ACEs (all rights levels).
      4. Grants FullControl (OI)(CI) via icacls to each account in -AllowedAccounts,
         propagating to all subfolders and files.
      5. Verifies child propagation: spot-checks subfolders to confirm each allowed
         account appears and Domain Users is absent.

    Designed for folder restriction requests where a set of named users or groups
    need exclusive access and broad groups (Domain Users, BUILTIN\Users) must be
    removed. Does not touch SYSTEM, Domain Admins, or Administrators ACEs.

    REVIEW BEFORE RUNNING. This script modifies NTFS permissions. Run
    Get-Acl or Invoke-DeepAclAudit.ps1 first to capture the baseline.

.PARAMETER Path
    Local path to the folder to restrict. Use the local path on the file server,
    not the UNC path (e.g., D:\Shares\Restricted, not \\server\share\Restricted).

.PARAMETER AllowedAccounts
    Array of account identifiers to grant FullControl. Accepts any format icacls
    accepts: SamAccountName, DOMAIN\SamAccountName, or built-in SID strings.
    Example: @('CONTOSO\jdoe', 'CONTOSO\jsmith', 'CONTOSO\auser', 'CONTOSO\buser')

.PARAMETER DomainPrefix
    NetBIOS domain prefix used when removing Domain Users. Default: BUILTIN for
    the Users group. Override if your domain has a custom Users group in a domain
    rather than BUILTIN (rare). Also used to qualify Domain Users removal if needed.

.EXAMPLE
    Set-FolderRestrictedAcl.ps1 -Path 'D:\Shares\Restricted\ProjectData' `
        -AllowedAccounts @('CONTOSO\jdoe','CONTOSO\jsmith','CONTOSO\auser','CONTOSO\buser')

.NOTES
    Created: 2026-05-29
    Category: ActiveDirectory
    Context: RMM shell (SYSTEM, PS 5.1 on file server)

.KEYWORDS
    ACL, permissions, NTFS, folder restriction, inheritance, Domain Users, icacls,
    FullControl, file server, restrict access
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string[]]$AllowedAccounts,

    [string]$DomainPrefix = ''
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== Set-FolderRestrictedAcl ==="
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("Path      : {0}" -f $Path)
Write-Output ("Accounts  : {0}" -f ($AllowedAccounts -join ', '))
Write-Output ""

if (-not (Test-Path $Path)) {
    Write-Output ("ABORT: Path not found: {0}" -f $Path)
    exit 1
}

# --- Phase 1: Baseline audit ---
Write-Output "=== Phase 1: Current ACL ==="
$aclBefore = Get-Acl -LiteralPath $Path -ErrorAction Stop
Write-Output ("Owner: {0}" -f $aclBefore.Owner)
Write-Output ("Inheritance protected: {0}" -f $aclBefore.AreAccessRulesProtected)
Write-Output "Access entries:"
$aclBefore.Access | ForEach-Object {
    Write-Output ("  [{0}] {1,-40} {2}" -f $(if ($_.IsInherited) {'inherited'} else {'explicit '}), $_.IdentityReference, $_.FileSystemRights)
}
Write-Output ""

# --- Phase 2: Disable inheritance, preserve existing explicit ACEs ---
Write-Output "=== Phase 2: Disabling inheritance ==="
$acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -LiteralPath $Path -AclObject $acl
Write-Output "Inheritance disabled. Inherited ACEs converted to explicit."
Write-Output ""

# --- Phase 3: Remove Domain Users and BUILTIN\Users ---
Write-Output "=== Phase 3: Removing broad-access groups ==="
$removeTargets = @('BUILTIN\Users')

# Detect domain name if not provided and Domain Users might be present
if (-not $DomainPrefix) {
    $detectedDomain = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name Domain -ErrorAction SilentlyContinue).Domain
    if (-not $detectedDomain) { $detectedDomain = $env:USERDOMAIN }
    if ($detectedDomain) { $DomainPrefix = $detectedDomain.Split('.')[0].ToUpper() }
}
if ($DomainPrefix) {
    $removeTargets += ("{0}\Domain Users" -f $DomainPrefix)
}

foreach ($target in $removeTargets) {
    $null = & icacls $Path /remove:g $target /T /C /Q 2>&1
    $null = & icacls $Path /remove:d $target /T /C /Q 2>&1
    Write-Output ("  Removed: {0}" -f $target)
}
Write-Output ""

# --- Phase 4: Grant FullControl to allowed accounts ---
Write-Output "=== Phase 4: Granting FullControl to allowed accounts ==="
foreach ($account in $AllowedAccounts) {
    $result = & icacls $Path /grant "${account}:(OI)(CI)F" /T /C /Q 2>&1
    $summary = $result | Where-Object { "$_" -match 'processed|failed|error' } | Select-Object -First 1
    Write-Output ("  Granted FullControl to {0}  ({1})" -f $account, "$summary".Trim())
}
Write-Output ""

# --- Phase 5: Verify final ACL on root ---
Write-Output "=== Phase 5: Root ACL verification ==="
$aclAfter = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
if ($aclAfter) {
    Write-Output ("Owner: {0}" -f $aclAfter.Owner)
    Write-Output ("Inheritance protected: {0}" -f $aclAfter.AreAccessRulesProtected)
    Write-Output "Access entries:"
    $aclAfter.Access | ForEach-Object {
        Write-Output ("  [{0}] {1,-40} {2}" -f $(if ($_.IsInherited) {'inherited'} else {'explicit '}), $_.IdentityReference, $_.FileSystemRights)
    }
    # Flag if broad groups survived
    $broadStill = $aclAfter.Access | Where-Object { $_.IdentityReference -match 'Domain Users|BUILTIN\\Users' }
    if ($broadStill) {
        Write-Output ""
        Write-Output "WARNING: Broad-access group still present in root ACL:"
        $broadStill | ForEach-Object { Write-Output ("  {0}" -f $_.IdentityReference) }
    }
}
Write-Output ""

# --- Phase 6: Child propagation spot-check ---
Write-Output "=== Phase 6: Child propagation spot-check ==="
$subDirs = Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue | Select-Object -First 5
if (-not $subDirs) {
    Write-Output "  No subdirectories to verify."
} else {
    foreach ($sub in $subDirs) {
        $subAcl = Get-Acl -LiteralPath $sub.FullName -ErrorAction SilentlyContinue
        $allowedPresent = @()
        $broadPresent   = @()
        foreach ($acct in $AllowedAccounts) {
            $shortName = $acct.Split('\')[-1]
            if ($subAcl.Access | Where-Object { $_.IdentityReference -match [regex]::Escape($shortName) }) {
                $allowedPresent += $shortName
            }
        }
        if ($subAcl.Access | Where-Object { $_.IdentityReference -match 'Domain Users|BUILTIN\\Users' }) {
            $broadPresent += 'broad-group'
        }
        $rel = $sub.FullName.Replace($Path, '.')
        Write-Output ("  {0}" -f $rel)
        Write-Output ("    Allowed accounts present : {0}" -f $(if ($allowedPresent) { $allowedPresent -join ', ' } else { '(none matched)' }))
        Write-Output ("    Broad group present      : {0}" -f $(if ($broadPresent) { 'YES - investigate' } else { 'none' }))
    }
    if ((Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue).Count -gt 5) {
        Write-Output "  (spot-check of first 5 subdirs only)"
    }
}

Write-Output ""
Write-Output "=== Complete ==="
Write-Output "Have an allowed user confirm access. Verify a non-listed user is blocked."
