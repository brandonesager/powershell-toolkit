<#
.SYNOPSIS
    Change GPO drive-mapping action from Replace (R) to Update (U) in Drives.xml
    and increment the gpt.ini user version counter.

.DESCRIPTION
    The "Replace" action in a GPO Drives.xml deletes and recreates mapped drives on
    every Group Policy refresh. On Windows 11 hosts this causes mid-session drive drops
    when GP background refresh fires. Changing the action to "Update" modifies the
    drive assignment but does not drop and recreate existing connections.

    This script:
      1. Resolves the target GPO GUID from the display name.
      2. Modifies Drives.xml in SYSVOL: changes action="R" to action="U" on all
         matching drive entries (or a specific drive letter if provided).
      3. Increments the user-version counter in gpt.ini so clients detect the change
         on the next Group Policy refresh (~90 min) or gpupdate.

    Run on a DC with GroupPolicy and ActiveDirectory modules available.
    WRITE OPERATION. Modifies SYSVOL; requires domain admin or delegated GPO edit rights.

.PARAMETER GpoName
    Display name of the GPO that contains the Drives.xml.

.PARAMETER DriveLetter
    Optional. If provided, only change the action for this drive letter.
    Leave empty to change all Replace actions in the file.

.NOTES
    Created: 2026-05-29
    Category: RMM-Deployment
    Context: RMM shell (SYSTEM, PS 5.1) on Domain Controller

.KEYWORDS
    GPO, drive mapping, Drives.xml, Replace, Update, gpt.ini, SYSVOL, SMB drop,
    mapped drives, Group Policy
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$GpoName,

    [string]$DriveLetter = ''
)

$ErrorActionPreference = 'Stop'

Write-Output "Set-GpoDriveActionUpdate"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("GPO       : {0}" -f $GpoName)
Write-Output ("Drive     : {0}" -f $(if ($DriveLetter) { $DriveLetter } else { '(all)' }))
Write-Output ""

Import-Module GroupPolicy    -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$gpo     = Get-GPO -Name $GpoName -ErrorAction Stop
$gpoGuid = "{$($gpo.Id.ToString().ToUpper())}"
$domain  = (Get-ADDomain).DNSRoot

$xmlPath = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\User\Preferences\Drives\Drives.xml"
$gptPath = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\gpt.ini"

Write-Output ("SYSVOL Drives.xml : {0}" -f $xmlPath)
Write-Output ("SYSVOL gpt.ini    : {0}" -f $gptPath)
Write-Output ""

if (-not (Test-Path $xmlPath)) {
    Write-Output ("ERROR: Drives.xml not found at {0}" -f $xmlPath)
    exit 1
}

# --- Modify Drives.xml ---
Write-Output "=== Modifying Drives.xml ==="
[xml]$xml = Get-Content $xmlPath -Raw
$changed  = 0

foreach ($drive in $xml.Drives.Drive) {
    $letter = $drive.Properties.letter
    $before = $drive.Properties.action
    # Skip if filtering by drive letter and this isn't it
    if ($DriveLetter -and $letter -ne $DriveLetter) {
        Write-Output ("  Drive {0}: skipped (filter={1})" -f $letter, $DriveLetter)
        continue
    }
    if ($before -eq 'R') {
        $drive.Properties.action = 'U'
        $changed++
        Write-Output ("  Drive {0}: Replace (R) -> Update (U)" -f $letter)
    } else {
        Write-Output ("  Drive {0}: action={1} (no change needed)" -f $letter, $before)
    }
}

if ($changed -eq 0) {
    Write-Output "No Replace actions found to change. Drives.xml not written."
    exit 0
}

$xml.Save($xmlPath)
Write-Output ("{0} drive(s) updated in Drives.xml." -f $changed)

# --- Increment user version in gpt.ini ---
Write-Output ""
Write-Output "=== Incrementing gpt.ini user version ==="
$gptRaw = Get-Content $gptPath -Raw
$match  = [regex]::Match($gptRaw, 'Version=(\d+)')
if ($match.Success) {
    $curVer     = [int]$match.Groups[1].Value
    $compVer    = $curVer -shr 16
    $userVer    = $curVer -band 0xFFFF
    $newUserVer = $userVer + 1
    $newVer     = ($compVer -shl 16) -bor $newUserVer
    $newGptRaw  = $gptRaw -replace "Version=$curVer", "Version=$newVer"
    Set-Content $gptPath $newGptRaw -NoNewline
    Write-Output ("gpt.ini version {0} -> {1}  (user {2} -> {3})" -f $curVer, $newVer, $userVer, $newUserVer)
} else {
    Write-Output "WARNING: Could not parse Version= from gpt.ini. Version not incremented."
}

Write-Output ""
Write-Output "=== Done ==="
Write-Output "Clients will pick up the change on next Group Policy refresh (~90 min)."
Write-Output "To test immediately on a workstation: gpupdate /force"
