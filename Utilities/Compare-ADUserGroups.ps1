<#
.SYNOPSIS
    Compares AD group membership between two users.

.DESCRIPTION
    Shows groups unique to User1, groups unique to User2, and groups common
    to both. Useful for identifying missing group assignments when mirroring
    permissions or troubleshooting access gaps.

.PARAMETER User1
    SAMAccountName of the first user.

.PARAMETER User2
    SAMAccountName of the second user (the reference/mirror source).

.EXAMPLE
    .\Compare-ADUserGroups.ps1 -User1 user1 -User2 user2

.NOTES
    RMM-compatible: no elevation prompts, no user interaction, SYSTEM-safe.
    Requires RSAT ActiveDirectory module or execution on a domain controller.
    Exit codes: 0 = success, 1 = error (user not found or AD unavailable).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$User1,

    [Parameter(Mandatory)]
    [string]$User2
)

$ErrorActionPreference = 'Stop'

function Get-UserGroups {
    param([string]$SAMAccountName)
    try {
        $user = Get-ADUser -Identity $SAMAccountName -Properties MemberOf -ErrorAction Stop
        $groups = $user.MemberOf | ForEach-Object {
            (Get-ADGroup -Identity $_ -ErrorAction Stop).Name
        }
        $groups | Sort-Object
    } catch {
        Write-Host "ERROR: Could not retrieve groups for '$SAMAccountName': $_"
        exit 1
    }
}

Write-Host "=== AD Group Comparison ==="
Write-Host "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "User1     : $User1"
Write-Host "User2     : $User2"
Write-Host ""

$groups1 = Get-UserGroups -SAMAccountName $User1
$groups2 = Get-UserGroups -SAMAccountName $User2

$onlyUser1  = $groups1 | Where-Object { $_ -notin $groups2 }
$onlyUser2  = $groups2 | Where-Object { $_ -notin $groups1 }
$common     = $groups1 | Where-Object { $_ -in $groups2 }

Write-Host "--- Only in $User1 ($($onlyUser1.Count)) ---"
if ($onlyUser1) { $onlyUser1 | ForEach-Object { Write-Host "  $_" } }
else            { Write-Host "  (none)" }

Write-Host ""
Write-Host "--- Only in $User2 ($($onlyUser2.Count)) ---"
if ($onlyUser2) { $onlyUser2 | ForEach-Object { Write-Host "  $_" } }
else            { Write-Host "  (none)" }

Write-Host ""
Write-Host "--- Common ($($common.Count)) ---"
if ($common) { $common | ForEach-Object { Write-Host "  $_" } }
else         { Write-Host "  (none)" }

Write-Host ""
Write-Host "Total groups - $User1: $($groups1.Count) | $User2: $($groups2.Count)"
exit 0
