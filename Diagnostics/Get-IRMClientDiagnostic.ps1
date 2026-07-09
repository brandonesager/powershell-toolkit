#!ps
#maxlength=100000
#timeout=300000

<#
.SYNOPSIS
    Read-only device-side diagnostic for IRM/Rights Management client state.
.DESCRIPTION
    Checks the currently logged-on user's IRM/DRM registry keys, MSIPC template
    cache, DRM cache, GPO policy overrides, and Outlook IRM-related preferences.
    Runs as SYSTEM via RMM shell; bridges to the user hive via
    SID resolution. No server-side Test-IRMConfiguration is included here; run
    that separately from a cloud PS session with the target UPN.
.PARAMETER ProfileName
    Optional. If provided, limits Outlook Profiles registry output to the named
    profile. Default is all profiles.
.NOTES
    Category: Diagnostics
    PS 5.1 compatible.
    Context: RMM shell (SYSTEM), read-only.
.KEYWORDS
    IRM, RMS, DRM, MSIPC, rights management, Outlook encrypt, sensitivity label
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProfileName = ''
)

$loggedOn = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $loggedOn) {
    Write-Output "No interactive user logged on. Cannot check user-profile IRM state."
    exit 1
}

$userSID  = (New-Object System.Security.Principal.NTAccount($loggedOn)).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$userProf = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSID" `
    -ErrorAction SilentlyContinue).ProfileImagePath

if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
$hku = "HKU:\$userSID"

Write-Output "=== User Context ==="
Write-Output "User: $loggedOn  SID: $userSID  Profile: $userProf"

Write-Output "`n=== Outlook Version ==="
$olVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" `
    -ErrorAction SilentlyContinue).ClientVersionToReport
if ($olVer) { Write-Output "Click-to-Run: $olVer" } else { Write-Output "C2R version not found" }

Write-Output "`n=== DRM Registry (User Hive) ==="
$drmPath = "$hku\Software\Microsoft\Office\16.0\Common\DRM"
if (Test-Path $drmPath) {
    Get-ItemProperty $drmPath | Format-List
} else {
    Write-Output "Key does not exist"
}

Write-Output "`n=== DRM Subkeys ==="
if (Test-Path $drmPath) {
    Get-ChildItem $drmPath -Recurse | ForEach-Object {
        Write-Output "--- $($_.Name) ---"
        Get-ItemProperty $_.PSPath | Format-List
    }
} else {
    Write-Output "No subkeys"
}

Write-Output "`n=== IRM Template Cache (MSIPC) ==="
$msipc = "$userProf\AppData\Local\Microsoft\MSIPC"
if (Test-Path $msipc) {
    Get-ChildItem $msipc -Recurse -File |
        Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
} else {
    Write-Output "MSIPC folder does not exist"
}

Write-Output "`n=== DRM Cache ==="
$drm = "$userProf\AppData\Local\Microsoft\DRM"
if (Test-Path $drm) {
    Get-ChildItem $drm -Recurse -File |
        Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
} else {
    Write-Output "DRM folder does not exist"
}

Write-Output "`n=== GPO DRM Policy Keys ==="
$gpoPath = "$hku\Software\Policies\Microsoft\Office\16.0\Common\DRM"
if (Test-Path $gpoPath) {
    Get-ItemProperty $gpoPath | Format-List
} else {
    Write-Output "No GPO DRM policy keys"
}

Write-Output "`n=== Outlook Preferences (IRM-related) ==="
$tcPath = "$hku\Software\Microsoft\Office\16.0\Outlook\Preferences"
if (Test-Path $tcPath) {
    if ($ProfileName) {
        Write-Output "Filtering to profile: $ProfileName"
    }
    Get-ItemProperty $tcPath |
        Select-Object -Property *IRM*, *DRM*, *Encrypt*, *Rights* -ErrorAction SilentlyContinue |
        Format-List
} else {
    Write-Output "Outlook Preferences key not found"
}

Write-Output "`n=== Done ==="
