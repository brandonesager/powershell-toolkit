<#
.SYNOPSIS
    Bulk add/remove members from an Exchange Online distribution list, idempotent.

.DESCRIPTION
    Accepts arrays of UPNs or display names to add and remove from a named DL.
    Uses -BypassSecurityGroupManagerCheck on both operations so the script works
    regardless of who owns the group manager attribute. Skips already-members on
    add and not-found-as-members on remove. Prints before/after membership and a
    final count.

    Run from an already-connected Exchange Online PowerShell session (cloud shell,
    no Connect- preamble needed).

.PARAMETER GroupIdentity
    Identity of the distribution group. Accepts display name, alias, or email address.

.PARAMETER AddMembers
    Array of UPNs or display names to add.

.PARAMETER RemoveMembers
    Array of UPNs or display names to remove.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    $add    = @('jane.doe@contoso.com', 'john.smith@contoso.com')
    $remove = @('old.user@contoso.com')
    .\Set-DistributionGroupMembership.ps1 -GroupIdentity 'All Assistant Managers' -AddMembers $add -RemoveMembers $remove

.NOTES
    Created: 2026-05-29
    Category: M365-Exchange
    Context: Cloud

.KEYWORDS
    distribution group, DL, membership, bulk, EXO, BypassSecurityGroupManagerCheck
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$GroupIdentity,

    [string[]]$AddMembers    = @(),
    [string[]]$RemoveMembers = @()
)

$ErrorActionPreference = 'Continue'

# Verify group exists
try {
    $group = Get-DistributionGroup -Identity $GroupIdentity -ErrorAction Stop
} catch {
    Write-Error "Group '$GroupIdentity' not found: $($_.Exception.Message)"
    return
}

Write-Host "`n=== BEFORE ===" -ForegroundColor Cyan
$before = Get-DistributionGroupMember -Identity $group.Identity -ResultSize Unlimited |
    Select-Object Name, PrimarySmtpAddress, RecipientType | Sort-Object Name
$before | Format-Table -AutoSize
Write-Host "Count: $($before.Count)"

# REMOVE
if ($RemoveMembers.Count -gt 0) {
    Write-Host "`n=== REMOVING MEMBERS ===" -ForegroundColor Yellow
    foreach ($m in $RemoveMembers) {
        if ($PSCmdlet.ShouldProcess($m, "Remove from $GroupIdentity")) {
            try {
                Remove-DistributionGroupMember -Identity $group.Identity -Member $m `
                    -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
                Write-Host "[OK]   Removed: $m" -ForegroundColor Green
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match "couldn't be found|not found|does not exist|isn't a member") {
                    Write-Host "[SKIP] $m - Not a member or not found" -ForegroundColor DarkYellow
                } else {
                    Write-Host "[ERR]  $m - $msg" -ForegroundColor Red
                }
            }
        }
    }
}

# ADD
if ($AddMembers.Count -gt 0) {
    Write-Host "`n=== ADDING MEMBERS ===" -ForegroundColor Yellow
    foreach ($m in $AddMembers) {
        if ($PSCmdlet.ShouldProcess($m, "Add to $GroupIdentity")) {
            try {
                Add-DistributionGroupMember -Identity $group.Identity -Member $m `
                    -BypassSecurityGroupManagerCheck -ErrorAction Stop
                Write-Host "[OK]   Added: $m" -ForegroundColor Green
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match 'already a member') {
                    Write-Host "[SKIP] $m - Already a member" -ForegroundColor DarkYellow
                } elseif ($msg -match "couldn't be found|not found") {
                    Write-Host "[ERR]  $m - Not found in directory" -ForegroundColor Red
                } else {
                    Write-Host "[ERR]  $m - $msg" -ForegroundColor Red
                }
            }
        }
    }
}

# AFTER
Write-Host "`n=== AFTER ===" -ForegroundColor Cyan
$after = Get-DistributionGroupMember -Identity $group.Identity -ResultSize Unlimited |
    Select-Object Name, PrimarySmtpAddress, RecipientType | Sort-Object Name
$after | Format-Table -AutoSize
Write-Host "Count: $($after.Count)"
