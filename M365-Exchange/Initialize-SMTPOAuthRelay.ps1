<#
.SYNOPSIS
    Initialize-SMTPOAuthRelay — Configure Exchange Online OAuth SMTP relay for service principal

.DESCRIPTION
    Registers an Entra ID service principal in Exchange Online and grants SendAs permission
    for OAuth-based SMTP relay using client credentials flow.

    PREREQUISITE: Complete Entra ID app registration via portal FIRST (steps in .NOTES).

    This script handles:
    1. Service principal registration in Exchange Online
    2. SendAs permission grant for target mailbox
    3. Configuration output for application handoff

.PARAMETER ApplicationId
    Application (client) ID from Entra ID app registration. Required.

.PARAMETER TenantId
    Directory (tenant) ID from Entra ID. Required.

.PARAMETER EnterpriseAppObjectId
    Object ID from Enterprise Applications blade (NOT App registrations).
    CRITICAL: Using App registrations Object ID causes "535 5.7.3 Authentication unsuccessful".
    Required.

.PARAMETER SenderMailbox
    Primary SMTP address of mailbox that will send emails (must exist with Exchange license).
    Required.

.EXAMPLE
    .\Initialize-SMTPOAuthRelay.ps1 -ApplicationId "abc123..." -TenantId "def456..." `
        -EnterpriseAppObjectId "789xyz..." -SenderMailbox "relay@example.com"

.NOTES
    Category: M365-Exchange
    Requires: ExchangeOnlineManagement module v3.0+
    Reference: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

    SETUP STEPS (must complete in Entra portal before running this script):

    STEP A - Register the Application:
      1. Entra admin center → Entra ID → App registrations → New registration
      2. Name: "[Service] SMTP Relay - [Client]"
      3. Supported account types: "Accounts in this organizational directory only (Single tenant)"
      4. Redirect URI: Leave BLANK (not needed for client credentials flow)
      5. Click [Register]
      6. Copy Application (client) ID and Directory (tenant) ID

    STEP B - Add API Permission:
      1. In the app → API permissions
      2. [+ Add a permission] → "APIs my organization uses"
      3. Search for "Office 365 Exchange Online"
      4. Select "Application permissions" (NOT Delegated)
      5. Expand SMTP → Check "SMTP.SendAsApp"
      6. Click [Add permissions]
      7. [Grant admin consent for <tenant>] → Confirm

    STEP C - Create Client Secret:
      1. In the app → Certificates & secrets
      2. [+ New client secret]
      3. Description: "[Service] SMTP"
      4. Expires: 24 months (or per policy)
      5. Click [Add]
      6. IMMEDIATELY copy the Value (shown only once)

    STEP D - Get Enterprise App Object ID (CRITICAL):
      1. Entra ID → Enterprise applications (NOT App registrations)
      2. Search for app name
      3. Overview → Copy Object ID (this is the parameter you need)

.KEYWORDS
    SMTP, OAuth, service-principal, relay, Exchange-Online
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApplicationId,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$EnterpriseAppObjectId,

    [Parameter(Mandatory = $true)]
    [string]$SenderMailbox
)

$ErrorActionPreference = "Stop"

#region Validation
Write-Host "`n=== Validating Parameters ===" -ForegroundColor Cyan

if ([string]::IsNullOrEmpty($ApplicationId) -or [string]::IsNullOrEmpty($TenantId) -or [string]::IsNullOrEmpty($EnterpriseAppObjectId)) {
    Write-Error "ApplicationId, TenantId, and EnterpriseAppObjectId are required."
    exit 1
}

Write-Host "Application ID: $ApplicationId" -ForegroundColor Gray
Write-Host "Tenant ID: $TenantId" -ForegroundColor Gray
Write-Host "Enterprise App Object ID: $EnterpriseAppObjectId" -ForegroundColor Gray
Write-Host "Sender Mailbox: $SenderMailbox" -ForegroundColor Gray
#endregion

#region Module Check
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop
#endregion

#region Connect to Exchange Online
$exoSession = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' }
if ($exoSession) {
    Write-Host "Exchange Online session already active ($($exoSession.UserPrincipalName))." -ForegroundColor DarkGray
} else {
    Write-Host "`n=== Connecting to Exchange Online ===" -ForegroundColor Cyan
    Connect-ExchangeOnline
}
#endregion

#region Register Service Principal
Write-Host "`n=== Registering Service Principal ===" -ForegroundColor Cyan
# This links the Entra ID app to Exchange Online
# IMPORTANT: ObjectId must be from Enterprise Applications blade
try {
    New-ServicePrincipal -AppId $ApplicationId -ObjectId $EnterpriseAppObjectId -ErrorAction Stop
    Write-Host "Service principal registered successfully." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already exists") {
        Write-Host "Service principal already exists (OK)." -ForegroundColor Yellow
    } else {
        throw
    }
}

# Verify registration
Write-Host "`n=== Registered Service Principals ===" -ForegroundColor Cyan
Get-ServicePrincipal | Where-Object { $_.AppId -eq $ApplicationId } | Format-List AppId, ServiceId, ObjectId, DisplayName
#endregion

#region Get Service Principal Identity
$sp = Get-ServicePrincipal | Where-Object { $_.AppId -eq $ApplicationId }

if (-not $sp) {
    Write-Error "Service principal not found after registration. Verify AppId: $ApplicationId"
    exit 1
}

Write-Host "`n=== Service Principal Details ===" -ForegroundColor Cyan
Write-Host "AppId: $($sp.AppId)"
Write-Host "ServiceId: $($sp.ServiceId)"  # This is the identity for permissions
#endregion

#region Grant SendAs Permission
Write-Host "`n=== Granting SendAs Permission ===" -ForegroundColor Cyan

# Check if permission already exists
$existingPerm = Get-RecipientPermission -Identity $SenderMailbox -ErrorAction SilentlyContinue |
    Where-Object { $_.Trustee -like "*$($sp.ServiceId)*" }

if ($existingPerm) {
    Write-Host "SendAs permission already exists (OK)." -ForegroundColor Yellow
} else {
    Add-RecipientPermission -Identity $SenderMailbox `
        -Trustee $sp.ServiceId `
        -AccessRights SendAs `
        -Confirm:$false
    Write-Host "SendAs permission granted." -ForegroundColor Green
}

Write-Host "`n=== Granted Permissions ===" -ForegroundColor Cyan
Get-RecipientPermission -Identity $SenderMailbox |
    Where-Object { $_.Trustee -like "*$($sp.ServiceId)*" } |
    Format-Table Trustee, AccessRights -AutoSize
#endregion

#region Verify Mailbox
$mailbox = Get-Mailbox -Identity $SenderMailbox -ErrorAction SilentlyContinue
if (-not $mailbox) {
    Write-Warning "Mailbox $SenderMailbox not found. Create it before testing."
} else {
    Write-Host "`n=== Sender Mailbox Verified ===" -ForegroundColor Green
    Write-Host "Mailbox: $($mailbox.PrimarySmtpAddress)"
    Write-Host "Type: $($mailbox.RecipientTypeDetails)"
}
#endregion

#region Configuration Output
$config = @"

================================================================================
OAUTH SMTP RELAY CONFIGURATION
================================================================================

SMTP Settings:
  Server: smtp.office365.com
  Port: 587
  Encryption: TLS (STARTTLS)

From Address: $SenderMailbox

OAuth 2.0 Credentials (Client Credentials Flow):
  Tenant ID: $TenantId
  Client ID: $ApplicationId
  Client Secret: [RETRIEVE FROM ENTRA ID → APP → CERTIFICATES & SECRETS]

Token Endpoint:
  https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token

Token Request Parameters:
  grant_type: client_credentials
  scope: https://outlook.office365.com/.default
  client_id: $ApplicationId
  client_secret: [SECRET_VALUE]

Authentication Method: XOAUTH2 (SASL)

Secret Expiration: [CHECK ENTRA ID - SET CALENDAR REMINDER]

================================================================================
Setup completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================

"@

Write-Host $config -ForegroundColor Green
#endregion

#region Cleanup
Disconnect-ExchangeOnline -Confirm:$false
Write-Host "`nDisconnected from Exchange Online." -ForegroundColor Yellow
#endregion
