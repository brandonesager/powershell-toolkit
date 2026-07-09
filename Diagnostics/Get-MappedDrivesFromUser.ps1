# Get-MappedDrivesFromUser.ps1
# Purpose: Query mapped network drives from a user's registry hive (SYSTEM context via RMM SYSTEM remote session)
# Context: PS 5.1+ (RMM SYSTEM remote session), runs as SYSTEM
# Use case: Retrieve another user's drive mappings to replicate on a migrated profile

param(
    [Parameter(Mandatory)]
    [string]$Username
)

$user = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq $Username }

if (-not $user) {
    Write-Warning "User '$Username' not found on this machine."
    exit 1
}

$sid = $user.SID
Write-Host "Found SID for $Username : $sid" -ForegroundColor Green

$regPath = "Registry::HKEY_USERS\$sid\Network"

if (-not (Test-Path $regPath)) {
    Write-Warning "No mapped drives found for $Username (HKEY_USERS\$sid\Network does not exist)"
    exit 0
}

$drives = Get-ChildItem $regPath

if (-not $drives) {
    Write-Host "No mapped drives found for $Username" -ForegroundColor Yellow
    exit 0
}

Write-Host "`nMapped Drives for ${Username}:" -ForegroundColor Cyan

$results = foreach ($drive in $drives) {
    $letter     = $drive.PSChildName
    $remotePath = (Get-ItemProperty $drive.PSPath).RemotePath
    [PSCustomObject]@{
        DriveLetter = "${letter}:"
        RemotePath  = $remotePath
    }
}

$results | Format-Table -AutoSize

Write-Host "`nnet use commands to replicate:" -ForegroundColor Cyan
foreach ($r in $results) {
    Write-Host "  net use $($r.DriveLetter) $($r.RemotePath) /persistent:yes"
}
