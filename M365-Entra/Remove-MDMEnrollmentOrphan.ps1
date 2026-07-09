<#
.SYNOPSIS
    Removes a stale MAM/MDM enrollment registry entry blocking Entra join (error 8018000a).
.DESCRIPTION
    Deletes the three registry paths associated with an orphaned enrollment GUID:
    - HKLM:\SOFTWARE\Microsoft\Enrollments\{GUID}
    - HKLM:\SOFTWARE\Microsoft\Enrollments\Status\{GUID}
    - HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\{GUID}

    Verifies the UPN in the main enrollment key matches the expected target before
    deleting, to prevent accidental removal of a valid enrollment.
    After running, reboot the device and retry Entra join.

    Use Get-MDMEnrollmentOrphan.ps1 first to identify the correct GUID.
.PARAMETER EnrollmentGuid
    GUID of the orphaned enrollment entry to remove. Required.
.PARAMETER TargetUPN
    UPN expected in the enrollment key. The script aborts if the stored UPN
    does not match this value. Required.
.EXAMPLE
    .\Remove-MDMEnrollmentOrphan.ps1 -EnrollmentGuid "00000000-1111-2222-3333-444444444444" -TargetUPN "user@contoso.com"
.NOTES
    Context:    SYSTEM (RMM deployment) or local admin
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=Success, 1=Failure, 2=Not found (already gone)
    PS 5.1 compatible.
.KEYWORDS
    MDM, MAM, enrollment, Entra, 8018000a, orphan, registry, remove
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentGuid,

    [Parameter(Mandatory=$true)]
    [string]$TargetUPN
)

$ErrorActionPreference = "Stop"

$Paths = @(
    "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentGuid"
    "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollmentGuid"
    "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollmentGuid"
)

try {
    Write-Output "Removing stale MAM enrollment for $TargetUPN"
    Write-Output "GUID: $EnrollmentGuid"

    $MainPath = $Paths[0]
    if (-not (Test-Path $MainPath)) {
        Write-Output "WARNING: Enrollment not found - may already be deleted"
        exit 2
    }

    $Props = Get-ItemProperty -Path $MainPath -ErrorAction SilentlyContinue
    if ($Props.UPN -and $Props.UPN -ne $TargetUPN) {
        Write-Output "ERROR: UPN mismatch - found '$($Props.UPN)', expected '$TargetUPN'"
        Write-Output "Aborting to prevent accidental deletion"
        exit 1
    }

    $Deleted = 0
    foreach ($Path in $Paths) {
        if (Test-Path $Path) {
            Remove-Item -Path $Path -Recurse -Force
            Write-Output "Deleted: $Path"
            $Deleted++
        } else {
            Write-Output "Not found (skip): $Path"
        }
    }

    if (Test-Path $MainPath) {
        Write-Output "ERROR: Main enrollment key still exists after deletion"
        exit 1
    }

    Write-Output "SUCCESS: Deleted $Deleted registry keys"
    Write-Output "ACTION REQUIRED: Reboot device, then retry Entra join"
    exit 0

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
