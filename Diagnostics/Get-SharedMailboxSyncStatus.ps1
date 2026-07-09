#Requires -Version 7.0
<#
.SYNOPSIS
    Diagnoses Classic Outlook shared mailbox sync failures via Exchange Online.
.DESCRIPTION
    Checks MAPI, OWA, EWS, and EwsAllowOutlook settings on a shared mailbox.
    Also verifies FullAccess and SendAs permissions for a specified delegate user.
    Run from SYSTEM remote session (PS 7+) or admin workstation with ExchangeOnlineManagement module.
.SOURCE
    claude.ai conversation extraction — Missing emails in classic Outlook
.NOTES
    Context: SYSTEM remote session / admin workstation (PS 7+)
    Requires: Connect-ExchangeOnline session already established
.PARAMETER SharedMailbox
    Identity of the shared mailbox (alias, email, or display name).
.PARAMETER DelegateUser
    UPN or alias of the user who should have access.
.EXAMPLE
    .\Get-SharedMailboxSyncStatus.ps1 -SharedMailbox "sharedbox" -DelegateUser "jdoe"
#>

param(
    [Parameter(Mandatory)]
    [string]$SharedMailbox,

    [Parameter(Mandatory)]
    [string]$DelegateUser
)

$ErrorActionPreference = 'Stop'

try {
    Write-Host "=== CAS MAILBOX SETTINGS ===" -ForegroundColor Cyan
    $cas = Get-CASMailbox -Identity $SharedMailbox
    [PSCustomObject]@{
        MAPIEnabled      = $cas.MAPIEnabled
        OWAEnabled       = $cas.OWAEnabled
        EwsEnabled       = $cas.EwsEnabled
        EwsAllowOutlook  = $cas.EwsAllowOutlook
        ActiveSyncEnabled = $cas.ActiveSyncEnabled
    } | Format-List

    if (-not $cas.EwsAllowOutlook) {
        Write-Warning "EwsAllowOutlook is blank or False — this blocks Classic Outlook sync."
        Write-Host "Fix: Set-CASMailbox -Identity '$SharedMailbox' -EwsAllowOutlook `$true" -ForegroundColor Yellow
    }

    Write-Host "`n=== MAILBOX PERMISSIONS ===" -ForegroundColor Cyan
    Get-MailboxPermission -Identity $SharedMailbox |
        Where-Object { $_.User -like "*$DelegateUser*" -and $_.IsInherited -eq $false } |
        Format-Table User, AccessRights, IsInherited, Deny -AutoSize

    Write-Host "`n=== RECIPIENT PERMISSIONS (SendAs) ===" -ForegroundColor Cyan
    Get-RecipientPermission -Identity $SharedMailbox |
        Where-Object { $_.Trustee -like "*$DelegateUser*" } |
        Format-Table Trustee, AccessRights, AccessControlType -AutoSize

    Write-Host "`n=== SEND ON BEHALF ===" -ForegroundColor Cyan
    (Get-Mailbox -Identity $SharedMailbox).GrantSendOnBehalfTo

    Write-Host "`n=== RECOMMENDED FIXES ===" -ForegroundColor Cyan
    Write-Host @"
If EwsAllowOutlook was blank, run:
  Set-CASMailbox -Identity '$SharedMailbox' -EwsAllowOutlook `$true

To reset all permissions with AutoMapping:
  Remove-MailboxPermission -Identity '$SharedMailbox' -User '$DelegateUser' -AccessRights FullAccess -Confirm:`$false
  Add-MailboxPermission  -Identity '$SharedMailbox' -User '$DelegateUser' -AccessRights FullAccess -AutoMapping:`$true
  Remove-RecipientPermission -Identity '$SharedMailbox' -Trustee '$DelegateUser' -AccessRights SendAs -Confirm:`$false
  Add-RecipientPermission    -Identity '$SharedMailbox' -Trustee '$DelegateUser' -AccessRights SendAs -Confirm:`$false
  Set-Mailbox -Identity '$SharedMailbox' -GrantSendOnBehalfTo @{Add='$DelegateUser'}

After changes: wait 30–60 min for propagation, then clear Outlook cache on workstation.
"@
} catch {
    Write-Error "Error: $($_.Exception.Message)"
    exit 1
}
