<#
.SYNOPSIS
    Detect orphaned Intune/MAM enrollment entries in local registry.

.DESCRIPTION
    Scans HKLM:\SOFTWARE\Microsoft\Enrollments for stale enrollment GUIDs.
    Identifies MAM (Mobile Application Management) and MDM enrollments that may
    block new device registration (error 8018000a, 0x80190190).

    MAM enrollments persist through TPM clear and dsregcmd /leave and do not
    appear in Intune admin center or Entra Devices portal.

.PARAMETER IncludeRelatedKeys
    Show Status and EnterpriseResourceManager keys alongside main enrollments.

.OUTPUTS
    List of enrollment GUIDs with UPN and ProviderID. Returns empty if no enrollments found.

.NOTES
    Context: Run via SYSTEM remote session (SYSTEM) or as local admin.
    Read-only diagnostic — does not delete enrollments.

.EXAMPLE
    .\Get-IntuneEnrollmentOrphans.ps1

    Lists all enrollment GUIDs with UPN field.

.EXAMPLE
    .\Get-IntuneEnrollmentOrphans.ps1 -IncludeRelatedKeys

    Shows Status and EnterpriseResourceManager keys alongside enrollments.

.NOTES
    Date: 2026-02-13
#>

[CmdletBinding()]
param(
    [switch]$IncludeRelatedKeys
)

$ErrorActionPreference = "Stop"

Write-Host "=== INTUNE ENROLLMENT ORPHAN DIAGNOSTIC ===" -ForegroundColor Cyan
Write-Host "Scanning HKLM:\SOFTWARE\Microsoft\Enrollments`n" -ForegroundColor Gray

# Main enrollment keys
$EnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
if (-not (Test-Path $EnrollmentPath)) {
    Write-Host "No Enrollments registry key found (clean state)." -ForegroundColor Green
    exit 0
}

$Enrollments = Get-ChildItem -Path $EnrollmentPath -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -ne "Context" -and $_.PSChildName -ne "Status" } |
    ForEach-Object {
        $Path = $_.PSPath
        $Props = Get-ItemProperty $Path -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            GUID        = Split-Path $Path -Leaf
            UPN         = $Props.UPN
            ProviderID  = $Props.ProviderID
            AADResourceID = $Props.AADResourceID
            EnrollmentType = if ($Props.ProviderID -eq "MS DM Server") { "MDM" } else { "MAM" }
        }
    }

if ($Enrollments) {
    Write-Host "FOUND enrollment entries:" -ForegroundColor Yellow
    $Enrollments | Format-Table -AutoSize
    Write-Host "`nOrphaned enrollments (UPN shows old user or unexpected account) can block new Entra joins." -ForegroundColor Yellow
    Write-Host "MAM enrollments do NOT appear in Intune or Entra portals — only discoverable via registry." -ForegroundColor Yellow
} else {
    Write-Host "No enrollment entries found (clean state)." -ForegroundColor Green
    exit 0
}

# Related keys (optional)
if ($IncludeRelatedKeys) {
    Write-Host "`n=== RELATED ENROLLMENT KEYS ===" -ForegroundColor Cyan

    # Status keys
    $StatusPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\Status"
    if (Test-Path $StatusPath) {
        $StatusKeys = Get-ChildItem $StatusPath -ErrorAction SilentlyContinue
        if ($StatusKeys) {
            Write-Host "Enrollment Status keys:" -ForegroundColor Gray
            $StatusKeys | ForEach-Object { Write-Host "  $($_.PSChildName)" }
        }
    }

    # EnterpriseResourceManager tracked keys
    $ERMPath = "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
    if (Test-Path $ERMPath) {
        $ERMKeys = Get-ChildItem $ERMPath -ErrorAction SilentlyContinue
        if ($ERMKeys) {
            Write-Host "`nEnterpriseResourceManager Tracked keys:" -ForegroundColor Gray
            $ERMKeys | ForEach-Object { Write-Host "  $($_.PSChildName)" }
        }
    }
}

Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host @"
If orphaned enrollments found:
1. Search Intune and Entra Devices portal for device by serial number and hostname
2. Delete any matching device objects from Intune and Entra ID
3. Wait 5-10 minutes for replication
4. Clean local registry enrollment keys
5. Reboot device
6. Retry Entra join via Settings > Accounts > Access work or school

Cleanup script: Remove-IntuneEnrollmentOrphans.ps1
Related error codes: 0x8018000a, 0x80190190
"@ -ForegroundColor White
