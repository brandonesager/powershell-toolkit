<#
.SYNOPSIS
    Diagnose IRM / OME activation state for an Exchange Online tenant.

.DESCRIPTION
    Checks all IRM and OME configuration flags, OWA mailbox policy IRMEnabled state,
    runs Test-IRMConfiguration for a target sender, and reports MSIPC client cache state.
    Identifies the most common causes of missing Encrypt buttons and template fetch failures:
    - LicensingLocation empty (Azure RMS URL not set).
    - AutomaticServiceUpdateEnabled=False (blocks auto-connection to Azure RMS).
    - InternalLicensingEnabled / AzureRMSLicensingEnabled False (OME never activated).
    - SimplifiedClientAccessEnabled=False (blocks Encrypt UI in Classic Outlook).
    - OWA policy IRMEnabled=False.

    Run from an already-connected Exchange Online PowerShell session.

.PARAMETER SenderUPN
    UPN of the mailbox to test with Test-IRMConfiguration.

.EXAMPLE
    .\Get-IrmActivationState.ps1 -SenderUPN 'jdoe@contoso.example.com'

.NOTES
    Created: 2026-05-29
    Category: M365-Exchange
    Context: Cloud

    Fix for LicensingLocation empty: see Fix-IRM-LicensingLocation.ps1.
    If AutomaticServiceUpdateEnabled=False: Set-IRMConfiguration -AutomaticServiceUpdateEnabled $true
    If InternalLicensingEnabled=False: Set-IRMConfiguration -InternalLicensingEnabled $true
    If SimplifiedClientAccessEnabled=False: Set-IRMConfiguration -SimplifiedClientAccessEnabled $true

.KEYWORDS
    IRM, OME, Purview, LicensingLocation, AzureRMS, Encrypt button, Test-IRMConfiguration, MSIPC
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$SenderUPN
)

$ErrorActionPreference = 'Continue'

Write-Host "`n=== IRM Configuration ===" -ForegroundColor Cyan
$irm = Get-IRMConfiguration
$irm | Format-List InternalLicensingEnabled,
    ExternalLicensingEnabled,
    AzureRMSLicensingEnabled,
    SimplifiedClientAccessEnabled,
    AutomaticServiceUpdateEnabled,
    RMSOnlineKeySharingLocation,
    LicensingLocation

# Flag common issues
if (-not $irm.InternalLicensingEnabled) {
    Write-Host "ISSUE: InternalLicensingEnabled=False. OME is off. Fix: Set-IRMConfiguration -InternalLicensingEnabled `$true" -ForegroundColor Red
}
if (-not $irm.AzureRMSLicensingEnabled) {
    Write-Host "ISSUE: AzureRMSLicensingEnabled=False. Fix: Set-IRMConfiguration -AzureRMSLicensingEnabled `$true" -ForegroundColor Red
}
if (-not $irm.SimplifiedClientAccessEnabled) {
    Write-Host "ISSUE: SimplifiedClientAccessEnabled=False. Encrypt button hidden in Classic Outlook." -ForegroundColor Yellow
    Write-Host "       Fix: Set-IRMConfiguration -SimplifiedClientAccessEnabled `$true" -ForegroundColor Yellow
}
if (-not $irm.AutomaticServiceUpdateEnabled) {
    Write-Host "ISSUE: AutomaticServiceUpdateEnabled=False. Exchange Online will not auto-sync Azure RMS templates." -ForegroundColor Yellow
    Write-Host "       Fix: Set-IRMConfiguration -AutomaticServiceUpdateEnabled `$true" -ForegroundColor Yellow
}
if ([string]::IsNullOrEmpty($irm.LicensingLocation)) {
    Write-Host "ISSUE: LicensingLocation is empty. Root cause of 'Failed to acquire RMS templates'." -ForegroundColor Red
    Write-Host "       Fix: run Fix-IRM-LicensingLocation.ps1 (requires AipService session)." -ForegroundColor Red
}

Write-Host "`n=== OWA Mailbox Policies ===" -ForegroundColor Cyan
Get-OwaMailboxPolicy | Format-List Identity, IRMEnabled

Write-Host "`n=== Test-IRMConfiguration ($SenderUPN) ===" -ForegroundColor Cyan
Test-IRMConfiguration -Sender $SenderUPN

Write-Host "`n=== Sender Mailbox Details ===" -ForegroundColor Cyan
Get-Mailbox $SenderUPN -ErrorAction SilentlyContinue |
    Format-List DisplayName, RecipientTypeDetails, OwaMailboxPolicy

Write-Host "`n=== MSIPC Cache State (client-side) ===" -ForegroundColor Cyan
Write-Host "MSIPC client cache is local to the endpoint -- cannot check from cloud session."
Write-Host "To inspect on the endpoint:"
Write-Host "  dir `"$env:LOCALAPPDATA\Microsoft\MSIPC`" (or %LOCALAPPDATA% in user session)"
Write-Host "  Look for *.drm template XML files. If none: Outlook has not fetched templates."
Write-Host "  To clear stale cache: Stop-Process -Name Outlook; Remove-Item `$env:LOCALAPPDATA\Microsoft\MSIPC -Recurse -Force"
