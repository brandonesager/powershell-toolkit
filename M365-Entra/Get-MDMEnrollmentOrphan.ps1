<#
.SYNOPSIS
    Lists stale MDM enrollment registry entries that can block Entra join (error 8018000a).
.DESCRIPTION
    Reads HKLM:\SOFTWARE\Microsoft\Enrollments and related keys to surface orphaned
    MAM/MDM enrollment GUIDs. Also reports EnterpriseResourceManager tracked keys
    and Enrollment Status keys. Diagnostic only -- makes no changes.

    Use the output GUID with Remove-MDMEnrollmentOrphan.ps1 to delete the stale entry.
    Run via SYSTEM remote session (SYSTEM context) or as local admin.
.EXAMPLE
    .\Get-MDMEnrollmentOrphan.ps1
.NOTES
    Context:    SYSTEM remote session (SYSTEM) or local admin
    Platform:   Windows 10/11, PS 5.1
    PS 5.1 compatible.
.KEYWORDS
    MDM, MAM, enrollment, Entra, 8018000a, orphan, registry, diagnostic
#>

[CmdletBinding()]
param()

#region Diagnostic: List Current Enrollments
Write-Host "=== CURRENT ENROLLMENT REGISTRY ENTRIES ===" -ForegroundColor Cyan
Write-Host "Looking for stale enrollments in HKLM:\SOFTWARE\Microsoft\Enrollments`n" -ForegroundColor Gray

$enrollments = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -ne "Context" -and $_.PSChildName -ne "Status" } |
    ForEach-Object {
        $path = $_.PSPath
        $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            GUID          = Split-Path $path -Leaf
            UPN           = $props.UPN
            ProviderID    = $props.ProviderID
            AADResourceID = $props.AADResourceID
        }
    }

if ($enrollments) {
    Write-Host "FOUND enrollment entries:" -ForegroundColor Yellow
    $enrollments | Format-Table -AutoSize
    Write-Host "If UPN shows an old user or the enrollment is unexpected, use Remove-MDMEnrollmentOrphan.ps1 to delete it.`n" -ForegroundColor Yellow
} else {
    Write-Host "No enrollment entries found (clean state).`n" -ForegroundColor Green
}
#endregion

#region Diagnostic: Check Related Keys
Write-Host "=== RELATED ENROLLMENT KEYS ===" -ForegroundColor Cyan

$statusKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments\Status" -ErrorAction SilentlyContinue
if ($statusKeys) {
    Write-Host "Enrollment Status keys:" -ForegroundColor Gray
    $statusKeys | ForEach-Object { Write-Host "  $($_.PSChildName)" }
} else {
    Write-Host "No Status keys found." -ForegroundColor Gray
}

$ermKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked" -ErrorAction SilentlyContinue
if ($ermKeys) {
    Write-Host "`nEnterpriseResourceManager Tracked keys:" -ForegroundColor Gray
    $ermKeys | ForEach-Object { Write-Host "  $($_.PSChildName)" }
} else {
    Write-Host "`nNo EnterpriseResourceManager Tracked keys found." -ForegroundColor Gray
}
#endregion

#region Next Steps
Write-Host @"

=== NEXT STEPS ===
1. Review the enrollment entries listed above
2. If an orphan is found, run Remove-MDMEnrollmentOrphan.ps1 with -EnrollmentGuid and -TargetUPN
3. Reboot the device
4. Retry Entra join:
   Settings > Accounts > Access work or school > Connect
   "Join this device to Azure Active Directory"

"@ -ForegroundColor White
#endregion
