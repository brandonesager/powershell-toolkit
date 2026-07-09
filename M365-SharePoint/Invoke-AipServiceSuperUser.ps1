<#
.SYNOPSIS
    Enable AipService Super User, add an admin account, and guide manual file decryption.

.DESCRIPTION
    Classic IRM / Azure RMS protected files cannot be unlocked server-side. The Super User
    feature lets a designated account open any RMS-protected file in an Office desktop app,
    which auto-decrypts it. Operator then removes the protection and re-uploads.

    Steps:
    1. Enable Super User feature on the tenant.
    2. Add the specified admin email as a Super User.
    3. Print manual file remediation instructions.
    4. The disable step is left commented with a security note. Operator must run it
       explicitly after remediation is complete.

    Run from an already-connected AipService session (Connect-AipService before this script).
    Requires: AIP Admin or Global Admin on the target tenant.

    IMPORTANT: AipService module is Windows-only. Run from a Windows endpoint or an admin workstation.
    This is NOT a cloud shell script; it requires a local Windows PS session with the
    AIPService module installed.

.PARAMETER AdminEmail
    Email address to add as Super User (e.g., admin@clientdomain.com).

.EXAMPLE
    .\Invoke-AipServiceSuperUser.ps1 -AdminEmail 'admin@contoso.com'

.NOTES
    Created: 2026-05-29
    Category: M365-SharePoint
    Context: Local Windows PS (AipService module required, Windows-only)

    Security: Super User feature grants universal RMS decrypt access across the entire tenant.
    Enable only for the duration of the remediation session. Always disable immediately after.

.KEYWORDS
    AipService, Super User, IRM, RMS, SharePoint, classic IRM, file decryption, AIP Admin
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$AdminEmail
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== AipService Super User Enablement ===" -ForegroundColor Cyan
Write-Host "Admin: $AdminEmail"
Write-Host ""
Write-Host "WARNING: Super User grants universal RMS decrypt. Disable immediately after remediation." -ForegroundColor Red
Write-Host ""

# Step 1: Verify AipService module is loaded
if (-not (Get-Module -Name AIPService -ListAvailable -ErrorAction SilentlyContinue)) {
    Write-Error "AIPService module not found. Install via: Install-Module AIPService -Force"
    return
}

# Step 2: Enable Super User feature
Write-Host "Enabling Super User feature..." -ForegroundColor Yellow
Enable-AipServiceSuperUserFeature
Write-Host "Super User feature enabled." -ForegroundColor Green

# Step 3: Add admin as Super User
Write-Host "Adding Super User: $AdminEmail ..." -ForegroundColor Yellow
Add-AipServiceSuperUser -EmailAddress $AdminEmail
Write-Host "Super User added: $AdminEmail" -ForegroundColor Green

# Step 4: Verify
Write-Host "`nCurrent Super Users:" -ForegroundColor Cyan
Get-AipServiceSuperUser | ForEach-Object { Write-Host "  $_" }

# Step 5: Manual process instructions
Write-Host "`n=== MANUAL REMEDIATION STEPS ===" -ForegroundColor Yellow
Write-Host "For each IRM-protected file:"
Write-Host "  1. Download the file from SharePoint to a local folder."
Write-Host "  2. Open in Office desktop app signed in as $AdminEmail."
Write-Host "     (Super User auto-decrypts; no password prompt.)"
Write-Host "  3. In Office: File > Info > Protect Document (or Restrict Access) > No Restrictions."
Write-Host "  4. Save the file."
Write-Host "  5. Re-upload to the original SharePoint location."
Write-Host ""
Write-Host "For bulk files: script the download/upload loop using PnP.PowerShell or SharePoint REST API."
Write-Host ""

# Step 6: Disable step -- COMMENTED, must be run explicitly
Write-Host "=== DISABLE AFTER REMEDIATION ===" -ForegroundColor Red
Write-Host "Run these commands manually once all files are remediated:" -ForegroundColor Red
Write-Host ""
Write-Host '# SECURITY REQUIREMENT: Disable Super User feature after remediation.' -ForegroundColor DarkYellow
Write-Host '# Leaving it enabled grants universal decrypt access to all tenant files.' -ForegroundColor DarkYellow
Write-Host '# Remove-AipServiceSuperUser -EmailAddress ' + "'$AdminEmail'" -ForegroundColor DarkYellow
Write-Host '# Disable-AipServiceSuperUserFeature' -ForegroundColor DarkYellow
Write-Host '# Write-Host "Super User disabled." -ForegroundColor Green' -ForegroundColor DarkYellow
Write-Host ""

<#
DISABLE BLOCK -- copy and run after remediation:

Remove-AipServiceSuperUser -EmailAddress '<AdminEmail>'
Disable-AipServiceSuperUserFeature
Write-Host 'Super User disabled and feature turned off.' -ForegroundColor Green
#>

Write-Host "Invoke-AipServiceSuperUser complete. Proceed with manual file remediation." -ForegroundColor Cyan
