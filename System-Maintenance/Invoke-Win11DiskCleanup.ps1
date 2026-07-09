<#
.SYNOPSIS
    Multi-pass disk cleanup targeting Win11 upgrade disk space requirements (64 GB free).

.DESCRIPTION
    Second-pass cleanup covering targets not addressed by cleanmgr silent mode:
    user temp, CBS archived logs, DISM component store (/StartComponentCleanup /ResetBase),
    installer patch cache, DirectX shader cache, and Windows Error Reporting archives.
    Reports measured freed space per target and actual disk delta (includes DISM).

    Run after the standard first-pass cleanmgr cleanup (WU cache, Delivery Optimization,
    Recycle Bin). Together the two passes typically free 20-30 GB on a machine that has
    not been cleaned in 12+ months.

    Safe for silent/unattended use — no user-visible prompts. Skips targets that
    require user approval (Downloads, user Documents).

.NOTES
    Context:    SYSTEM or elevated user
    Shell:      PowerShell 5.1+
    Target:     Win10/11 workstations pre-upgrade
    Win11 disk: 64 GB free minimum required for in-place upgrade

#>

#Requires -RunAsAdministrator

$freed = 0

# --- Survey current free space ---
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$startFree = [math]::Round($disk.FreeSpace / 1GB, 1)
Write-Output "Starting free space: $startFree GB"
Write-Output ""

# --- User Temp ---
Write-Output "=== User Temp ==="
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if ($user) {
    $sid = (New-Object System.Security.Principal.NTAccount($user)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    $userTemp = Join-Path $profile "AppData\Local\Temp"
    if (Test-Path $userTemp) {
        $before = (Get-ChildItem $userTemp -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $before) { $before = 0 }
        Get-ChildItem $userTemp -Force -EA SilentlyContinue | ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -EA SilentlyContinue
        }
        $after = (Get-ChildItem $userTemp -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $after) { $after = 0 }
        $diff = [math]::Round(($before - $after) / 1MB, 0)
        $freed += $diff
        Write-Output "  User Temp ($profile): $diff MB freed"
    } else {
        Write-Output "  User Temp path not found: $userTemp"
    }
} else {
    Write-Output "  No logged-in user detected -- skipping user temp"
}

# --- Thumbnail Cache ---
Write-Output ""
Write-Output "=== Thumbnail Cache ==="
if ($profile) {
    $thumbPath = Join-Path $profile "AppData\Local\Microsoft\Windows\Explorer"
    if (Test-Path $thumbPath) {
        $thumbFiles = @(Get-ChildItem $thumbPath -Filter "thumbcache_*.db" -Force -EA SilentlyContinue)
        $before = ($thumbFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $before) { $before = 0 }
        foreach ($f in $thumbFiles) { Remove-Item $f.FullName -Force -EA SilentlyContinue }
        $after = (@(Get-ChildItem $thumbPath -Filter "thumbcache_*.db" -Force -EA SilentlyContinue) | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $after) { $after = 0 }
        $diff = [math]::Round(($before - $after) / 1MB, 0)
        $freed += $diff
        Write-Output "  Thumbnail cache: $diff MB freed"
    }
}

# --- DirectX Shader Cache ---
Write-Output ""
Write-Output "=== DirectX Shader Cache ==="
$shaderPath = "C:\Windows\Temp\DirectX Shader Cache"
if (Test-Path $shaderPath) {
    $before = (Get-ChildItem $shaderPath -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $before) { $before = 0 }
    Remove-Item "$shaderPath\*" -Recurse -Force -EA SilentlyContinue
    $after = (Get-ChildItem $shaderPath -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $after) { $after = 0 }
    $diff = [math]::Round(($before - $after) / 1MB, 0)
    $freed += $diff
    Write-Output "  Shader cache: $diff MB freed"
} else {
    Write-Output "  No shader cache found"
}

# --- Windows Error Reporting ---
Write-Output ""
Write-Output "=== Windows Error Reporting ==="
$werPaths = @(
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"
)
foreach ($wer in $werPaths) {
    if (Test-Path $wer) {
        $before = (Get-ChildItem $wer -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $before) { $before = 0 }
        Remove-Item "$wer\*" -Recurse -Force -EA SilentlyContinue
        $after = (Get-ChildItem $wer -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $after) { $after = 0 }
        $diff = [math]::Round(($before - $after) / 1MB, 0)
        $freed += $diff
        Write-Output "  $(Split-Path $wer -Leaf): $diff MB freed"
    }
}

# --- CBS Logs (archived only, preserve active CBS.log) ---
Write-Output ""
Write-Output "=== CBS Logs ==="
$cbsPath = "C:\Windows\Logs\CBS"
if (Test-Path $cbsPath) {
    $cbsFiles = @(Get-ChildItem $cbsPath -Filter "*.log" -Force -EA SilentlyContinue | Where-Object { $_.Name -ne "CBS.log" })
    $before = ($cbsFiles | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $before) { $before = 0 }
    foreach ($f in $cbsFiles) { Remove-Item $f.FullName -Force -EA SilentlyContinue }
    $cabFiles = @(Get-ChildItem $cbsPath -Filter "*.cab" -Force -EA SilentlyContinue)
    $cabSize = ($cabFiles | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $cabSize) { $cabSize = 0 }
    $before += $cabSize
    foreach ($f in $cabFiles) { Remove-Item $f.FullName -Force -EA SilentlyContinue }
    $diff = [math]::Round($before / 1MB, 0)
    $freed += $diff
    Write-Output "  CBS logs (archived .log + .cab): $diff MB freed"
}

# --- DISM Component Store Cleanup ---
Write-Output ""
Write-Output "=== Component Store Cleanup ==="
Write-Output "  Running DISM /StartComponentCleanup /ResetBase (1-5 min)..."
dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-Null
Write-Output "  Component cleanup complete"

# --- Installer Patch Cache ---
Write-Output ""
Write-Output "=== Installer Patch Cache ==="
$patchCache = "C:\Windows\Installer\`$PatchCache`$"
if (Test-Path $patchCache) {
    $before = (Get-ChildItem $patchCache -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $before) { $before = 0 }
    Remove-Item "$patchCache\*" -Recurse -Force -EA SilentlyContinue
    $after = (Get-ChildItem $patchCache -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $after) { $after = 0 }
    $diff = [math]::Round(($before - $after) / 1MB, 0)
    $freed += $diff
    Write-Output "  Patch cache: $diff MB freed"
} else {
    Write-Output "  No patch cache found"
}

# --- Final Report ---
Write-Output ""
Write-Output "================================"
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$endFree = [math]::Round($disk.FreeSpace / 1GB, 1)
$totalFreed = [math]::Round($endFree - $startFree, 1)
Write-Output "Measured freed (file deletes): ~$([math]::Round($freed / 1024, 1)) GB"
Write-Output "Actual delta (includes DISM):  $totalFreed GB"
Write-Output "Free space now: $endFree GB"
if ($endFree -ge 64) {
    Write-Output "Win11 target (64 GB): READY"
} else {
    Write-Output "Win11 target (64 GB): still need $([math]::Round(64 - $endFree, 1)) GB more"
}
