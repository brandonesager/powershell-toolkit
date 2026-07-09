<#
.SYNOPSIS
    Launch a Windows 11 in-place upgrade via SYSTEM-level scheduled task.

.DESCRIPTION
    Mounts a staged Win11 24H2 ISO, writes an upgrade launcher script, and
    registers + starts a scheduled task running as SYSTEM. Returns immediately
    so the RMM session is not blocked. The upgrade runs independently (45-90 min)
    and the machine reboots automatically when setup completes.

    The ISO mount clears automatically after the upgrade reboot. Do not dismount
    manually while setup is running.

.PARAMETER IsoPath
    Path to the staged Win11 ISO. Default: C:\Temp\Win11_24H2.iso

.PARAMETER LogDir
    Directory for setup logs. Default: C:\Logs\Win11Upgrade

.NOTES
    - Run from RMM RMM shell or SYSTEM remote session
    - Requires ISO pre-staged (7 GB); 64 GB free disk space minimum after staging
    - Run Get-Win11UpgradeCompatScan.ps1 first to confirm no blockers (expect 0xC1900210)
    - Monitor task: Get-ScheduledTaskInfo -TaskName 'Win11InPlaceUpgrade'
    - Verify post-upgrade: (Get-CimInstance Win32_OperatingSystem).BuildNumber (expect 26100.x)
    - Delete ISO after upgrade: Remove-Item C:\Temp\Win11_24H2.iso -Force

#>

#!ps
#maxlength=100000
#timeout=300000

param(
    [string]$IsoPath = 'C:\Temp\Win11_24H2.iso',
    [string]$LogDir  = 'C:\Logs\Win11Upgrade'
)

if (-not (Test-Path $IsoPath)) {
    Write-Output "ERROR: ISO not found at $IsoPath"
    Write-Output "Stage the Win11 24H2 ISO before running."
    Write-Output "Download: https://www.microsoft.com/en-us/software-download/windows11"
    exit 1
}

# Mount ISO
Write-Output "Mounting ISO..."
$mount = Mount-DiskImage -ImagePath $IsoPath -PassThru
$drive = ($mount | Get-Volume).DriveLetter

if (-not $drive) {
    Write-Output "ERROR: ISO mounted but no drive letter assigned"
    Dismount-DiskImage -ImagePath $IsoPath | Out-Null
    exit 1
}

$setup = "${drive}:\setup.exe"
if (-not (Test-Path $setup)) {
    Write-Output "ERROR: setup.exe not found at $setup"
    Dismount-DiskImage -ImagePath $IsoPath | Out-Null
    exit 1
}

Write-Output "ISO mounted at ${drive}:\"

# Create log directory
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

# Write upgrade launcher script (scheduled task runs this as SYSTEM)
$upgradeScript = @"
`$logDir = '$LogDir'
if (-not (Test-Path `$logDir)) { New-Item -Path `$logDir -ItemType Directory -Force | Out-Null }
Start-Process -FilePath '${drive}:\setup.exe' ``
    -ArgumentList '/auto upgrade /quiet /eula accept /compat ignorewarning /migratedrivers all /dynamicupdate disable /copylogs $LogDir' ``
    -Wait
"@

$scriptPath = 'C:\Temp\Win11Upgrade.ps1'
Set-Content -Path $scriptPath -Value $upgradeScript -Encoding UTF8

# Register and start scheduled task as SYSTEM
$taskName = 'Win11InPlaceUpgrade'
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "WARNING: Task '$taskName' already exists — removing."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Output ""
Write-Output "=== Win11 Upgrade Launched ==="
Write-Output "Task:    $taskName"
Write-Output "Script:  $scriptPath"
Write-Output "Logs:    $LogDir"
Write-Output "Setup:   ${drive}:\setup.exe"
Write-Output ""
Write-Output "Upgrade runs independently (45-90 min). Machine reboots automatically."
Write-Output ""
Write-Output "Monitor:  Get-ScheduledTaskInfo -TaskName '$taskName'"
Write-Output "Verify:   (Get-CimInstance Win32_OperatingSystem).BuildNumber  # expect 26100.x"
Write-Output ""
Write-Output "DO NOT dismount the ISO while setup is running."
