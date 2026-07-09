<#
.SYNOPSIS
    Export-GalToCsv — Exports Contoso Global Address List data from Exchange Online

.DESCRIPTION
    Connects to Exchange Online and exports mailboxes, mail contacts, distribution groups,
    and the complete GAL for Contoso (contoso.com).
    Outputs CSV files to a timestamped folder. Interactive — requires admin login.

.NOTES
    Category: Environment-Specific
.KEYWORDS
    Contoso, Exchange, export, GAL, mailbox, report
#>

# Ensure Exchange Online Management module is installed
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "Installing Exchange Online Management module..." -ForegroundColor Yellow
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}

# Import the module
Import-Module ExchangeOnlineManagement

# Connect to Exchange Online
Write-Host "Connecting to Exchange Online for @contoso.com..." -ForegroundColor Cyan
try {
    Connect-ExchangeOnline
} catch {
    Write-Host "ERROR: Failed to connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# Set output path with timestamp
$date = Get-Date -Format "yyyy-MM-dd_HHmm"
$outputFolder = ".\Contoso_GAL_Export_$date"

# Create output folder
if (-not (Test-Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory | Out-Null
}

Write-Host "Exporting Global Address List data..." -ForegroundColor Cyan

# Export all mailboxes with contact information
try {
    Write-Host "  - Exporting mailboxes..." -ForegroundColor Yellow
    $mailboxPath = "$outputFolder\Contoso_Mailboxes.csv"
    Get-Mailbox -ResultSize Unlimited | Select-Object `
        DisplayName,
        PrimarySmtpAddress,
        UserPrincipalName,
        Alias,
        Title,
        Department,
        Office,
        Phone,
        MobilePhone,
        Company,
        City,
        StateOrProvince,
        PostalCode,
        StreetAddress,
        RecipientTypeDetails,
        WhenCreated,
        WhenChanged |
        Export-Csv -Path $mailboxPath -NoTypeInformation -Encoding UTF8
    Write-Host "  - Mailboxes exported: $mailboxPath" -ForegroundColor Green
} catch {
    Write-Host "  - ERROR exporting mailboxes: $($_.Exception.Message)" -ForegroundColor Red
}

# Export mail contacts
try {
    Write-Host "  - Exporting mail contacts..." -ForegroundColor Yellow
    $contactsPath = "$outputFolder\Contoso_MailContacts.csv"
    Get-MailContact -ResultSize Unlimited | Select-Object `
        DisplayName,
        ExternalEmailAddress,
        Phone,
        MobilePhone,
        Company,
        Title,
        Department,
        Office,
        City,
        StateOrProvince |
        Export-Csv -Path $contactsPath -NoTypeInformation -Encoding UTF8
    Write-Host "  - Mail contacts exported: $contactsPath" -ForegroundColor Green
} catch {
    Write-Host "  - ERROR exporting mail contacts: $($_.Exception.Message)" -ForegroundColor Red
}

# Export distribution groups
try {
    Write-Host "  - Exporting distribution groups..." -ForegroundColor Yellow
    $groupsPath = "$outputFolder\Contoso_DistributionGroups.csv"
    Get-DistributionGroup -ResultSize Unlimited | Select-Object `
        DisplayName,
        PrimarySmtpAddress,
        GroupType,
        ManagedBy,
        MemberCount,
        WhenCreated,
        WhenChanged |
        Export-Csv -Path $groupsPath -NoTypeInformation -Encoding UTF8
    Write-Host "  - Distribution groups exported: $groupsPath" -ForegroundColor Green
} catch {
    Write-Host "  - ERROR exporting distribution groups: $($_.Exception.Message)" -ForegroundColor Red
}

# Export complete GAL (all recipients)
try {
    Write-Host "  - Exporting complete GAL..." -ForegroundColor Yellow
    $galPath = "$outputFolder\Contoso_Complete_GAL.csv"
    Get-Recipient -ResultSize Unlimited | Select-Object `
        DisplayName,
        PrimarySmtpAddress,
        RecipientType,
        RecipientTypeDetails,
        Title,
        Department,
        Phone,
        MobilePhone,
        Company,
        Office,
        City,
        StateOrProvince,
        PostalCode,
        StreetAddress,
        EmailAddresses |
        Export-Csv -Path $galPath -NoTypeInformation -Encoding UTF8
    Write-Host "  - Complete GAL exported: $galPath" -ForegroundColor Green
} catch {
    Write-Host "  - ERROR exporting complete GAL: $($_.Exception.Message)" -ForegroundColor Red
}

# Disconnect from Exchange Online
Write-Host "`nDisconnecting from Exchange Online..." -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Export Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All files saved to: $outputFolder" -ForegroundColor White
Write-Host "`nFiles created:" -ForegroundColor White
Write-Host "  - Contoso_Mailboxes.csv" -ForegroundColor Gray
Write-Host "  - Contoso_MailContacts.csv" -ForegroundColor Gray
Write-Host "  - Contoso_DistributionGroups.csv" -ForegroundColor Gray
Write-Host "  - Contoso_Complete_GAL.csv" -ForegroundColor Gray
Write-Host "`nReady to send to requesting user" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan
