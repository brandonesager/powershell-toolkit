<#
.SYNOPSIS
    Diagnose mailbox permissions including hidden SID-based ACEs.

.DESCRIPTION
    Comprehensive diagnostic for Exchange Online mailbox permissions. Surfaces
    orphaned SID entries, unresolved permissions, and SID history that can cause
    Remove-MailboxPermission failures in hybrid AD environments.

    Use this when:
    - Remove-MailboxPermission fails with "ACE doesn't exist"
    - User permissions appear removed but mailbox still auto-maps
    - Investigating permission issues in hybrid AD + Entra environments

.PARAMETER Mailbox
    Identity of the mailbox to diagnose (UPN, alias, or display name).

.PARAMETER User
    (Optional) Specific user to check. If omitted, shows all delegated permissions.

.EXAMPLE
    .\Get-MailboxPermissionDiag.ps1 -Mailbox sharedmailbox

.EXAMPLE
    .\Get-MailboxPermissionDiag.ps1 -Mailbox sharedmailbox -User targetuser

.OUTPUTS
    Formatted table showing User, UserSid, AccessRights, and IsInherited for all
    non-system delegated permissions.

.NOTES
    Context: SYSTEM remote session (PS 7+)
    Requires: ExchangeOnlineManagement module, Connect-ExchangeOnline

.SOURCE
    Date: 2026-02-13
#>

[CmdletBinding()]
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

Write-Host "`n========== Full Permissions (including unresolved) ==========" -ForegroundColor Yellow
Write-Host "Mailbox: $Mailbox`n" -ForegroundColor Cyan

$permissions = Get-MailboxPermission -Identity $Mailbox -IncludeUnresolvedPermissions |
    Where-Object { $_.User -ne "NT AUTHORITY\SELF" }

if ($User) {
    # Filter to specific user (by UPN match or SID match)
    $permissions = $permissions | Where-Object {
        $_.User -eq $User -or $_.User -like "*$User*"
    }
}

if ($permissions) {
    $permissions | Format-Table User, UserSid, AccessRights, IsInherited -AutoSize

    # Highlight orphaned SIDs
    $orphaned = $permissions | Where-Object { $_.User -like "S-1-5-21*" }
    if ($orphaned) {
        Write-Host "`n⚠️  ORPHANED SID ENTRIES DETECTED:" -ForegroundColor Red
        $orphaned | Format-Table User, AccessRights -AutoSize
        Write-Host "These entries may block Remove-MailboxPermission. Use Repair-OrphanedMailboxACE.ps1 to clean up." -ForegroundColor Yellow
    }
} else {
    Write-Host "No delegated permissions found." -ForegroundColor Green
}

# Show user SID info if specific user requested
if ($User) {
    Write-Host "`n========== User SID Info ==========" -ForegroundColor Yellow
    try {
        Get-User $User | Format-List Name, Sid, SidHistory
        Get-Recipient $User | Format-List Name, ExternalDirectoryObjectId
    } catch {
        Write-Warning "Could not retrieve user SID info: $_"
    }
}
