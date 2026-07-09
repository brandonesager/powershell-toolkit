<#
.SYNOPSIS
    Grant mailbox access with explicit AutoMapping control.

.DESCRIPTION
    Adds Full Access permissions to a mailbox with explicit control over AutoMapping
    behavior. Use when you need to grant access without cluttering the user's Outlook
    sidebar, or when you explicitly want the mailbox to auto-appear.

.PARAMETER Mailbox
    Identity of the target mailbox (UPN, alias, or display name).

.PARAMETER User
    User to grant access to (UPN, alias, or display name).

.PARAMETER AutoMap
    Whether to enable AutoMapping. Default is $false (no automap).
    - $false: User must add mailbox manually via File > Open & Export
    - $true: Mailbox automatically appears in Outlook sidebar

.EXAMPLE
    .\Grant-MailboxAccessWithOptions.ps1 -Mailbox sharedmailbox -User targetuser

.EXAMPLE
    .\Grant-MailboxAccessWithOptions.ps1 -Mailbox sharedmailbox -User targetuser -AutoMap $true

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

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$false)]
    [bool]$AutoMap = $false
)

# Ensure connected to Exchange Online
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
} catch {
    Write-Error "Not connected to Exchange Online. Run Connect-ExchangeOnline first."
    exit 1
}

$automapText = if ($AutoMap) { "WITH AutoMapping" } else { "WITHOUT AutoMapping" }
Write-Host "Granting $User FullAccess on $Mailbox ($automapText)..." -ForegroundColor Cyan

try {
    Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights FullAccess `
        -AutoMapping $AutoMap -ErrorAction Stop | Out-Null
    Write-Host "✓ Permission granted successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to grant permission: $_"
    exit 1
}

# Verify
Write-Host "`n========== Verification ==========" -ForegroundColor Yellow
$perm = Get-MailboxPermission -Identity $Mailbox |
    Where-Object { $_.User -like "*$User*" } |
    Select-Object User, AccessRights, IsInherited

if ($perm) {
    $perm | Format-Table -AutoSize
} else {
    Write-Warning "Permission not found in verification check. May need a moment to replicate."
}

if (-not $AutoMap) {
    Write-Host "`nUser can access the mailbox via:" -ForegroundColor Cyan
    Write-Host "  File > Open & Export > Other User's Folder > type '$Mailbox' > Open" -ForegroundColor White
}
