<#
.SYNOPSIS
    Determine whether a SharePoint file is protected by classic IRM or a sensitivity label,
    then print the correct remediation path.

.DESCRIPTION
    Fetches basic site and file information to distinguish between:
    - Classic IRM (Azure RMS template, library-level policy): requires AipService Super User.
    - Sensitivity label encryption (file-level, MIP): can use Unlock-SPOSensitivityLabelEncryptedFile.

    Detection logic:
    1. Check library-level IRM setting via Get-SPOSite -Detailed.
    2. If no library IRM, attempt Get-FileSensitivityLabelInfo on the file URL.
    3. Branch output tells the operator which script to run next.

    Run from an already-connected SPO session (Connect-SPOService must be active).
    SharePoint Admin role required for Unlock-SPO path. AIP Admin or Global Admin for
    the AipService Super User path.

.PARAMETER SiteUrl
    Full URL of the SharePoint site (e.g., https://contoso.sharepoint.com/sites/Sales).

.PARAMETER FileUrl
    Full URL of the affected file.

.EXAMPLE
    .\Test-SpoIrmProtectionType.ps1 `
        -SiteUrl 'https://contoso.sharepoint.com/sites/Sales' `
        -FileUrl  'https://contoso.sharepoint.com/sites/Sales/Shared Documents/file.xlsx'

.NOTES
    Created: 2026-05-29
    Category: M365-SharePoint
    Context: Cloud

    Key distinction: Classic IRM applies on download via library policy or file-level RMS template.
    Sensitivity labels embed AES-256 encryption directly in the file and travel with it.
    Only sensitivity label encryption supports server-side unlock via Unlock-SPOSensitivityLabelEncryptedFile.

.KEYWORDS
    SharePoint, IRM, sensitivity label, AIP, Unlock-SPO, AipService, protection type, GDAP
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$SiteUrl,

    [Parameter(Mandatory)]
    [string]$FileUrl
)

$ErrorActionPreference = 'Continue'

Write-Host "`n=== SPO IRM Protection Type Detector ===" -ForegroundColor Cyan
Write-Host "Site: $SiteUrl"
Write-Host "File: $FileUrl"

# Step 1: Site-level IRM check
Write-Host "`n--- Step 1: Site-level IRM setting ---" -ForegroundColor Yellow
try {
    $site = Get-SPOSite -Identity $SiteUrl -Detailed -ErrorAction Stop
    $irmEnabled = $site.IrmEnabled
    Write-Host "Site IrmEnabled: $irmEnabled"

    if ($irmEnabled) {
        Write-Host "`nResult: CLASSIC IRM (library-level policy detected on site)." -ForegroundColor Red
        Write-Host "Remediation path: AipService Super User (see Invoke-AipServiceSuperUser.ps1)." -ForegroundColor Yellow
        Write-Host "Requires: AIP Admin or Global Admin on the target tenant."
        return
    }
} catch {
    Write-Host "Could not query site (may lack SPO Admin or Connect-SPOService failed): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "If Connect-SPOService returns 400, check SPO module version and GDAP scope." -ForegroundColor Yellow
    Write-Host "Fallback: use SharePoint admin center browser UI to check Policies > Information Rights Management toggle." -ForegroundColor Yellow
}

# Step 2: File-level sensitivity label check
Write-Host "`n--- Step 2: File-level sensitivity label check ---" -ForegroundColor Yellow
try {
    $labelInfo = Get-FileSensitivityLabelInfo -FileUrl $FileUrl -ErrorAction Stop
    if ($labelInfo) {
        Write-Host "Sensitivity label found:" -ForegroundColor Green
        $labelInfo | Format-List
        Write-Host "`nResult: SENSITIVITY LABEL encryption." -ForegroundColor Green
        Write-Host "Remediation path: Unlock-SPOSensitivityLabelEncryptedFile" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Unlock-SPOSensitivityLabelEncryptedFile -FileUrl '<file-url>' -JustificationText 'Departed employee, account purged, file recovery'"
        Write-Host ""
        Write-Host "Requires: SharePoint Admin (available via GDAP)."
        Write-Host "Note: does NOT work on Double Key Encryption."
        return
    } else {
        Write-Host "No sensitivity label returned for this file." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Get-FileSensitivityLabelInfo failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "This cmdlet requires SharePoint Online Management Shell 16.0.22601+ and SPO Admin rights." -ForegroundColor Yellow
}

# Step 3: Inconclusive - print both paths
Write-Host "`n--- Result: INCONCLUSIVE ---" -ForegroundColor Yellow
Write-Host "Could not auto-detect protection type. Open the file in the browser and observe the error:"
Write-Host "  - 'protected by Information Rights Management (IRM)' = CLASSIC IRM -> AipService Super User path"
Write-Host "  - 'sensitivity label' or encryption badge  = SENSITIVITY LABEL -> Unlock-SPO path"
Write-Host ""
Write-Host "Classic IRM remediation: Invoke-AipServiceSuperUser.ps1"
Write-Host "Sensitivity label remediation: Unlock-SPOSensitivityLabelEncryptedFile (requires SharePoint Admin)"
