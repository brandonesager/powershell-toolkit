<#
.SYNOPSIS
    Read MountPoints2 mapped drives from a local user profile.

.DESCRIPTION
    Retrieves mapped drive UNC paths from HKEY_USERS MountPoints2 for a target user
    profile on the local machine. Works whether or not the user is currently logged in
    by loading NTUSER.DAT if the hive is not already mounted.

    Use case: identify drives mapped for a departing/source user to replicate for a
    new or replacement user on the same workstation.

    Context: SYSTEM or local admin
    Platform: Windows PowerShell 5.1

.PARAMETER ProfileName
    Local profile folder name (e.g. "fenny", "jsmith"). Matches C:\Users\{ProfileName}.

.EXAMPLE
    .\Get-MappedDrivesFromProfile.ps1 -ProfileName "jdoe"
    Lists all network mapped drives from the user's profile.

.NOTES
    MountPoints2 stores UNC paths with backslashes replaced by #:
      ##server#share  =  \\server\share
    Only entries starting with ## are network drives; single-# entries are local paths.

    RMM Deployment: Exit 0 = Success, Exit 1 = Failure
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ProfileName
)

$ErrorActionPreference = 'Stop'
$TempHiveName = 'MappedDriveTemp'

try {
    Write-Host "[START] Mapped drive lookup for profile: $ProfileName"

    # Resolve SID from ProfileList
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $sid = (Get-ChildItem $profileListPath |
        Get-ItemProperty |
        Where-Object { $_.ProfileImagePath -like "*\$ProfileName" } |
        Select-Object -First 1).PSChildName

    if (-not $sid) {
        Write-Output "ERROR: Profile '$ProfileName' not found in ProfileList registry."
        exit 1
    }
    Write-Host "[OK] SID resolved: $sid"

    $mountPoints2 = "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    $hivePath     = "Registry::HKEY_USERS\$sid\$mountPoints2"
    $hiveLoaded   = $false

    if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
        # User not logged in — load NTUSER.DAT
        $ntUserDat = "C:\Users\$ProfileName\NTUSER.DAT"
        if (-not (Test-Path $ntUserDat)) {
            Write-Output "ERROR: NTUSER.DAT not found at $ntUserDat"
            exit 1
        }
        Write-Host "[INFO] User not logged in — loading NTUSER.DAT"
        $null = reg load "HKU\$TempHiveName" $ntUserDat 2>&1
        $hivePath  = "Registry::HKEY_USERS\$TempHiveName\$mountPoints2"
        $hiveLoaded = $true
    }

    $drives = @()
    if (Test-Path $hivePath) {
        $drives = Get-ChildItem $hivePath |
            Where-Object { $_.PSChildName -match '^##' } |
            ForEach-Object {
                $_.PSChildName -replace '^##', '\\' -replace '#', '\'
            }
    }

    if ($hiveLoaded) {
        [gc]::Collect()
        Start-Sleep -Milliseconds 500
        $null = reg unload "HKU\$TempHiveName" 2>&1
        Write-Host "[INFO] Hive unloaded"
    }

    if ($drives.Count -eq 0) {
        Write-Host "[INFO] No network mapped drives found in MountPoints2 for $ProfileName"
    } else {
        Write-Host "[OK] Found $($drives.Count) mapped drive(s):"
        $drives | ForEach-Object { Write-Host "  $_" }
    }

    Write-Output ($drives | ConvertTo-Json -Compress)
    exit 0

} catch {
    # Attempt hive cleanup on error
    try { $null = reg unload "HKU\$TempHiveName" 2>&1 } catch {}
    Write-Host "[ERROR] $($_.Exception.Message)"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
