#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    New-SharedMailbox — Creates and configures a new Shared Mailbox in Exchange Online

.DESCRIPTION
    Provisions a new Shared Mailbox and applies user-level and mailbox-level
    configurations using Set-User and Set-Mailbox. Variables at the top of the
    script must be updated per-use for mailbox name, alias, SMTP address,
    description, and GAL visibility.

.EXAMPLE
    .\New-SharedMailbox.ps1

.NOTES
    Category: M365-Exchange
.KEYWORDS
    Exchange, mailbox, shared, provision, permission
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$MailboxName = "SharedMailbox01"
$MailboxAlias = "SharedMailbox01"
$PrimarySmtpAddress = "$MailboxAlias@contoso.com" # Adjust to your domain
$MailboxDescription = "Example Department Mailbox"
$SetHiddenFromGAL = $false # Set to $true to hide, $false to show.

Write-Host "Attempting to create new Shared Mailbox: '$MailboxName'..." -ForegroundColor Yellow

try {

    $newMailbox = New-Mailbox -Shared `
        -Name $MailboxName `
        -Alias $MailboxAlias `
        -PrimarySmtpAddress $PrimarySmtpAddress `
        -ErrorAction Stop

    Write-Host "Successfully created mailbox object: $($newMailbox.DisplayName)" -ForegroundColor Green

    Write-Host "Applying User configurations (Description)..." -ForegroundColor DarkCyan
    Set-User -Identity $newMailbox.Identity `
        -Description $MailboxDescription `
        -ErrorAction Stop

    Write-Host "Applying Mailbox configurations (GAL Visibility)..." -ForegroundColor DarkCyan
    Set-Mailbox -Identity $newMailbox.Identity `
        -HiddenFromAddressListsEnabled $SetHiddenFromGAL `
        -ErrorAction Stop

    Write-Host "New Shared Mailbox '$MailboxName' created and configured successfully." -ForegroundColor Green

    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "Script finished."
    Write-Host "============================================================" -ForegroundColor Green

} catch {
    Write-Error "Script failed: $_"
    exit 1
}
