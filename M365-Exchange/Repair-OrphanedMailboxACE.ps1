<#
.SYNOPSIS
    Remove orphaned SID-based mailbox permission ACEs.

.DESCRIPTION
    Cleans up orphaned SID entries in Exchange Online mailbox permissions that
    block standard Remove-MailboxPermission operations. Uses two approaches:
    1. -BypassMasterAccountSid switch (Microsoft-documented fix)
    2. Raw SID removal for entries not resolved by approach 1

    Common in hybrid AD environments where permissions were granted during sync lag.

.PARAMETER Mailbox
    Identity of the mailbox to repair (UPN, alias, or display name).

.PARAMETER User
    (Optional) Target user identity. If omitted, removes ALL orphaned SID entries.

.EXAMPLE
    .\Repair-OrphanedMailboxACE.ps1 -Mailbox sharedmailbox -User targetuser

.EXAMPLE
    .\Repair-OrphanedMailboxACE.ps1 -Mailbox sharedmailbox

.NOTES
    Context: SYSTEM remote session (PS 7+)
    Requires: ExchangeOnlineManagement module, Connect-ExchangeOnline

    IMPORTANT: Run Get-MailboxPermissionDiag.ps1 first to confirm orphaned entries exist.

#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$Mailbox,

    [Parameter(Mandatory=$false)]
    [string]$User
)

# Ensure connected to Exchange Online
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
} catch {
    Write-Error "Not connected to Exchange Online. Run Connect-ExchangeOnline first."
    exit 1
}

# Attempt 1: -BypassMasterAccountSid (MS documented fix)
Write-Host "`n========== Attempt 1: -BypassMasterAccountSid ==========" -ForegroundColor Yellow

if ($User) {
    Write-Host "Removing $User from $Mailbox..." -ForegroundColor Cyan
    Remove-MailboxPermission -Identity $Mailbox -User $User -AccessRights FullAccess `
        -Confirm:$false -BypassMasterAccountSid `
        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
} else {
    Write-Host "⚠️  No user specified — skipping UPN-based removal" -ForegroundColor Yellow
}

# Attempt 2: Remove any remaining SID-based FullAccess entries
Write-Host "`n========== Attempt 2: Raw SID removal ==========" -ForegroundColor Yellow

$orphaned = Get-MailboxPermission -Identity $Mailbox -IncludeUnresolvedPermissions |
    Where-Object { $_.User -like "S-1-5-21*" -and $_.AccessRights -contains "FullAccess" }

if ($orphaned) {
    foreach ($entry in $orphaned) {
        Write-Host "Removing SID $($entry.User) from $Mailbox" -ForegroundColor Cyan
        Remove-MailboxPermission -Identity $Mailbox -User $entry.User -AccessRights FullAccess `
            -Confirm:$false -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "$Mailbox - no orphaned SID entries found" -ForegroundColor Green
}

# Verify clean
Write-Host "`n========== Verify Clean ==========" -ForegroundColor Yellow
$perms = Get-MailboxPermission -Identity $Mailbox -IncludeUnresolvedPermissions |
    Where-Object { $_.User -ne "NT AUTHORITY\SELF" }

if ($perms) {
    $perms | Format-Table User, AccessRights -AutoSize
} else {
    Write-Host "✓ Clean - no delegated permissions" -ForegroundColor Green
}

Write-Host "`nIf permissions were removed, instruct the user to fully restart Outlook to clear the automap cache." -ForegroundColor Cyan
