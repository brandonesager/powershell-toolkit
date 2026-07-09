<#
.SYNOPSIS
    Get-SharePointSyncDiagnostic — Diagnostic script for SharePoint/OneDrive sync issues

.DESCRIPTION
    Gathers OneDrive sync status, process info, temp/lock files, storage,
    and network connectivity to SharePoint Online. Run in user context
    (not SYSTEM) to access OneDrive settings.

.NOTES
    Category: Diagnostics
    Run as: Current user (SYSTEM remote session or interactive)

.KEYWORDS
    onedrive, sharepoint, sync, diagnostic, cloud-storage
#>

$ErrorActionPreference = 'SilentlyContinue'
$divider = '=' * 60

Write-Host "`n$divider"
Write-Host "OneDrive / SharePoint Sync Diagnostic — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "$divider`n"

# 1. OneDrive process status
Write-Host "--- OneDrive Process ---"
$odProcess = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
if ($odProcess) {
    Write-Host "OneDrive running: PID $($odProcess.Id), CPU: $([math]::Round($odProcess.CPU, 1))s, Memory: $([math]::Round($odProcess.WorkingSet64 / 1MB, 1)) MB"
} else {
    Write-Host "WARNING: OneDrive process NOT running"
}

# 2. OneDrive version
Write-Host "`n--- OneDrive Version ---"
$odExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $odExe) {
    $ver = (Get-Item $odExe).VersionInfo.ProductVersion
    Write-Host "Version: $ver"
} else {
    Write-Host "OneDrive executable not found at expected path"
}

# 3. OneDrive account / sync folders from registry
Write-Host "`n--- Sync Accounts & Libraries ---"
$accountKeys = Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue
foreach ($key in $accountKeys) {
    $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
    Write-Host "`nAccount: $($key.PSChildName)"
    Write-Host "  UserEmail : $($props.UserEmail)"
    Write-Host "  UserFolder: $($props.UserFolder)"
    Write-Host "  Business  : $($props.Business)"

    # List synced SharePoint libraries under this account
    $scopeKeys = Get-ChildItem "$($key.PSPath)\ScopeIdToMountPointPathCache" -ErrorAction SilentlyContinue
    if (-not $scopeKeys) {
        $mountCache = Get-ItemProperty "$($key.PSPath)\ScopeIdToMountPointPathCache" -ErrorAction SilentlyContinue
        if ($mountCache) {
            $mountCache.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Host "  Library   : $($_.Value)"
            }
        }
    }
}

# 4. Check for temp/lock files in synced SharePoint folders
Write-Host "`n--- Temp/Lock Files in Synced Folders ---"
$syncFolders = @()
$accountKeys | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.UserFolder -and (Test-Path $props.UserFolder)) {
        $syncFolders += $props.UserFolder
    }
    $mountCache = Get-ItemProperty "$($_.PSPath)\ScopeIdToMountPointPathCache" -ErrorAction SilentlyContinue
    if ($mountCache) {
        $mountCache.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and (Test-Path $_.Value) } | ForEach-Object {
            $syncFolders += $_.Value
        }
    }
}

$tempFiles = @()
foreach ($folder in $syncFolders) {
    $tempFiles += Get-ChildItem -Path $folder -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^~\$|^\.~lock|\.tmp$|\.conflict$' }
}

if ($tempFiles) {
    Write-Host "Found $($tempFiles.Count) temp/lock/conflict file(s):"
    $tempFiles | ForEach-Object { Write-Host "  $($_.FullName) ($($_.Length) bytes, modified $($_.LastWriteTime))" }
} else {
    Write-Host "No temp/lock/conflict files found"
}

# 5. Files with sync-pending status (cloud-only or pending upload)
Write-Host "`n--- Files with Pending Sync Status ---"
foreach ($folder in $syncFolders) {
    $pendingFiles = Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint -or
                       $_.Attributes -band [System.IO.FileAttributes]::Offline } |
        Select-Object -First 20
    if ($pendingFiles) {
        Write-Host "Folder: $folder"
        $pendingFiles | ForEach-Object { Write-Host "  $($_.Name) — Attr: $($_.Attributes)" }
    }
}

# 6. Disk space
Write-Host "`n--- Disk Space ---"
$sysDrive = Get-PSDrive C
Write-Host "C: Free: $([math]::Round($sysDrive.Free / 1GB, 1)) GB / Used: $([math]::Round($sysDrive.Used / 1GB, 1)) GB"

# 7. Network connectivity to SharePoint
Write-Host "`n--- Network Connectivity ---"
$spDomains = @(
    'login.microsoftonline.com'
)
foreach ($domain in $spDomains) {
    $tcp = Test-NetConnection -ComputerName $domain -Port 443 -WarningAction SilentlyContinue
    $status = if ($tcp.TcpTestSucceeded) { 'OK' } else { 'FAILED' }
    Write-Host "  $domain`:443 — $status (Latency: $($tcp.PingReplyDetails.RoundtripTime)ms)"
}

# 8. Recent OneDrive errors in Event Log
Write-Host "`n--- Recent OneDrive Event Log Errors (last 24h) ---"
$cutoff = (Get-Date).AddHours(-24)
$odEvents = Get-WinEvent -FilterHashtable @{
    LogName     = 'Application'
    ProviderName = 'Microsoft OneDrive'
    Level       = @(1,2,3)  # Critical, Error, Warning
    StartTime   = $cutoff
} -MaxEvents 10 -ErrorAction SilentlyContinue

if ($odEvents) {
    $odEvents | ForEach-Object {
        Write-Host "  [$($_.TimeCreated.ToString('MM/dd HH:mm'))] Level $($_.Level): $($_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)))"
    }
} else {
    Write-Host "  No OneDrive errors/warnings in last 24h"
}

# 9. OneDrive sync settings (Files On-Demand, Office integration)
Write-Host "`n--- OneDrive Settings ---"
$odSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive' -ErrorAction SilentlyContinue
if ($odSettings) {
    Write-Host "  FilesOnDemandEnabled: $($odSettings.FilesOnDemandEnabled)"
    Write-Host "  EnableADAL         : $($odSettings.EnableADAL)"
    Write-Host "  SilentAccountConfig: $($odSettings.SilentAccountConfig)"
}
$gpoSettings = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -ErrorAction SilentlyContinue
if ($gpoSettings) {
    Write-Host "  GPO SilentAccountConfig: $($gpoSettings.SilentAccountConfig)"
    Write-Host "  GPO FilesOnDemand      : $($gpoSettings.FilesOnDemandEnabled)"
    Write-Host "  GPO KFMSilentOptIn     : $($gpoSettings.KFMSilentOptIn)"
}

Write-Host "`n$divider"
Write-Host "Diagnostic complete"
Write-Host $divider
