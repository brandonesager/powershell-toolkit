<#
.SYNOPSIS
    Set IRM LicensingLocation from AipService configuration URL and verify with Test-IRMConfiguration.

.DESCRIPTION
    Root cause: LicensingLocation is empty in Exchange Online IRMConfiguration, which prevents
    Exchange from fetching RMS templates. Azure RMS may be activated on the tenant but the
    licensing URL was never propagated to EXO.

    Fix:
    1. Retrieve LicensingIntranetDistributionPointUrl from AipService tenant configuration.
    2. Set it as LicensingLocation in Exchange Online.
    3. Enable InternalLicensingEnabled if not already enabled.
    4. Run Test-IRMConfiguration to confirm templates are now accessible.

    Requires two connected sessions:
    - Exchange Online PowerShell (assumed live, no Connect- preamble).
    - AipService: must run Connect-AipService before this script.
      AipService module is Windows-only; run from Windows endpoint or an admin workstation.

.PARAMETER SenderUPN
    UPN to use for Test-IRMConfiguration post-fix validation.

.EXAMPLE
    # From a Windows PS 5.1 session (AipService already connected):
    .\Fix-IRM-LicensingLocation.ps1 -SenderUPN 'jdoe@contoso.example.com'

.NOTES
    Created: 2026-05-29
    Category: M365-Exchange
    Context: Cloud (EXO) + local Windows PS (AipService)

    Reference: https://learn.microsoft.com/purview/set-up-new-message-encryption-capabilities

.KEYWORDS
    IRM, LicensingLocation, AipService, AzureRMS, OME, Encrypt button, template, fix
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$SenderUPN
)

$ErrorActionPreference = 'Stop'

# Step 1: Retrieve licensing URL from AipService
Write-Host "`n=== Step 1: AipService licensing URL ===" -ForegroundColor Cyan
try {
    $rmsConfig    = Get-AipServiceConfiguration -ErrorAction Stop
    $licenseUri   = $rmsConfig.LicensingIntranetDistributionPointUrl
    if ([string]::IsNullOrEmpty($licenseUri)) {
        Write-Error "LicensingIntranetDistributionPointUrl is empty in AipServiceConfiguration. Verify Azure RMS is activated on this tenant."
        return
    }
    Write-Host "Licensing URL: $licenseUri" -ForegroundColor Green
} catch {
    Write-Error "Get-AipServiceConfiguration failed: $($_.Exception.Message)"
    Write-Host "Ensure Connect-AipService is active and you have AIP Admin / Global Admin on this tenant."
    return
}

# Step 2: Before state
Write-Host "`n=== Step 2: Current IRMConfiguration ===" -ForegroundColor Cyan
Get-IRMConfiguration | Format-List LicensingLocation, InternalLicensingEnabled, AutomaticServiceUpdateEnabled

# Step 3: Apply LicensingLocation
Write-Host "`n=== Step 3: Setting LicensingLocation ===" -ForegroundColor Yellow
Set-IRMConfiguration -LicensingLocation $licenseUri
Write-Host "LicensingLocation set." -ForegroundColor Green

# Step 4: Ensure InternalLicensingEnabled
Write-Host "`n=== Step 4: Ensuring InternalLicensingEnabled ===" -ForegroundColor Yellow
Set-IRMConfiguration -InternalLicensingEnabled $true
Write-Host "InternalLicensingEnabled = True." -ForegroundColor Green

# Step 5: Enable AutomaticServiceUpdateEnabled (prevents future drift)
Write-Host "`n=== Step 5: AutomaticServiceUpdateEnabled ===" -ForegroundColor Yellow
Set-IRMConfiguration -AutomaticServiceUpdateEnabled $true
Write-Host "AutomaticServiceUpdateEnabled = True." -ForegroundColor Green

# Step 6: Verify
Write-Host "`n=== Step 6: Verification ===" -ForegroundColor Cyan
Get-IRMConfiguration | Format-List LicensingLocation, InternalLicensingEnabled, AutomaticServiceUpdateEnabled

# Step 7: Test
Write-Host "`n=== Step 7: Test-IRMConfiguration ($SenderUPN) ===" -ForegroundColor Cyan
Test-IRMConfiguration -Sender $SenderUPN

Write-Host "`nFix complete. If Test-IRMConfiguration shows templates (Encrypt, Do Not Forward), IRM is functional." -ForegroundColor Green
Write-Host "Client-side Outlook may take 24 hours to fetch templates on next sign-in." -ForegroundColor Yellow
