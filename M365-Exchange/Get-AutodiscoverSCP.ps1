#Requires -Modules ExchangeOnlineManagement
<#
.SYNOPSIS
    Exchange Online mailbox permission audit between two users.
.DESCRIPTION
    Queries all permission vectors between two mailboxes: FullAccess, SendAs,
    SendOnBehalf, and calendar delegate permissions in both directions.
    Run from an active EXO session.
.PARAMETER SourceUser
    Primary user to audit (email address or UPN).
.PARAMETER TargetUser
    Secondary user to check for permissions relationship (email address or UPN).
.EXAMPLE
    .\Get-AutodiscoverSCP.ps1 -SourceUser "user1" -TargetUser "user2"
.SOURCE
    Date: 2026-02-13
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SourceUser,

    [Parameter(Mandatory = $true)]
    [string]$TargetUser
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "`n=== Autodiscover Permission Audit ===" -ForegroundColor Cyan
Write-Host "Checking: $SourceUser ↔ $TargetUser`n"

# 1. FullAccess on source mailbox (any user)
Write-Host "--- 1. FullAccess on $SourceUser ---" -ForegroundColor Green
Get-MailboxPermission -Identity $SourceUser |
    Where-Object { $_.User -notlike "NT AUTHORITY*" -and $_.IsInherited -eq $false } |
    Format-Table User, AccessRights, IsInherited -AutoSize

# 2. SendAs on source mailbox
Write-Host "--- 2. SendAs on $SourceUser ---" -ForegroundColor Green
Get-RecipientPermission -Identity $SourceUser |
    Where-Object { $_.Trustee -notlike "NT AUTHORITY*" } |
    Format-Table Trustee, AccessRights -AutoSize

# 3. SendOnBehalf on source mailbox
Write-Host "--- 3. SendOnBehalf on $SourceUser ---" -ForegroundColor Green
$sob = (Get-Mailbox -Identity $SourceUser).GrantSendOnBehalfTo
if ($sob) { $sob | ForEach-Object { Write-Host $_ } }
else { Write-Host "None" }

# 4. Calendar delegate on source user
Write-Host "`n--- 4. Calendar Delegates on $SourceUser ---" -ForegroundColor Green
Get-MailboxFolderPermission -Identity "${SourceUser}:\Calendar" -ErrorAction SilentlyContinue |
    Where-Object { $_.User.DisplayName -notmatch "^(Default|Anonymous)$" } |
    Format-Table User, AccessRights -AutoSize

# 5. Reverse: FullAccess on target mailbox granted to source
Write-Host "--- 5. FullAccess on $TargetUser (granted to $SourceUser?) ---" -ForegroundColor Green
Get-MailboxPermission -Identity $TargetUser |
    Where-Object { $_.User -like "*$SourceUser*" } |
    Format-Table User, AccessRights -AutoSize

# 6. Mailbox type check
Write-Host "--- 6. Mailbox Info ---" -ForegroundColor Green
Get-Mailbox -Identity $SourceUser |
    Select-Object DisplayName, RecipientTypeDetails, WhenMailboxCreated, ForwardingSmtpAddress |
    Format-List

Write-Host "=== Audit Complete ===" -ForegroundColor Cyan
