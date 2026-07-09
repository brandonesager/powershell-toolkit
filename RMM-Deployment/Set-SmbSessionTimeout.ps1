<#
.SYNOPSIS
    Set SMB client SessionTimeout (seconds) on Windows 10/11 workstations to reduce
    mid-session mapped drive drops caused by idle SMB session expiry.

.DESCRIPTION
    Windows 11 closes idle SMB sessions more aggressively than Windows 10 (default
    60 seconds vs 600 seconds in some versions). When the session is dropped mid-work,
    re-establishment can fail silently, leaving mapped drives showing as disconnected.
    Increasing SessionTimeout to 600 seconds (10 minutes) gives users more idle time
    before the SMB client drops the session.

    Reports before and after values. Idempotent: exits 0 immediately if already set
    to the target value.

.PARAMETER TimeoutSeconds
    Target SessionTimeout in seconds. Default: 600.

.NOTES
    Created: 2026-05-29
    Category: RMM-Deployment
    Context: RMM | SYSTEM remote session (SYSTEM, PS 5.1)

.KEYWORDS
    SMB, SessionTimeout, drive drop, mapped drives, Windows 11, idle, reconnect
#>
#Requires -Version 5.1

param(
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'

Write-Output "Set-SmbSessionTimeout"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("Target    : {0} seconds" -f $TimeoutSeconds)
Write-Output ""

try {
    $before = (Get-SmbClientConfiguration).SessionTimeout
    Write-Output ("SessionTimeout before: {0} seconds" -f $before)

    if ($before -eq $TimeoutSeconds) {
        Write-Output ("Already set to {0}s. No change needed." -f $TimeoutSeconds)
        exit 0
    }

    Set-SmbClientConfiguration -SessionTimeout $TimeoutSeconds -Force

    $after = (Get-SmbClientConfiguration).SessionTimeout
    Write-Output ("SessionTimeout after : {0} seconds" -f $after)

    if ($after -eq $TimeoutSeconds) {
        Write-Output ("OK: SessionTimeout set to {0}s." -f $TimeoutSeconds)
        exit 0
    } else {
        Write-Output "ERROR: Value did not apply as expected."
        exit 1
    }
} catch {
    Write-Output ("ERROR: {0}" -f $_.Exception.Message)
    exit 1
}
