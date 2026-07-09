<#
.SYNOPSIS
    Removes orphaned RMM (ITSPlatform/SAAZ) MSI product registration.
.DESCRIPTION
    Clears stale Windows Installer entries that block fresh agent MSI install
    with "Another version of this product is already installed" (error 1638).
    Registry-based approach — avoids Win32_Product enumeration (repair trigger).
    Requires elevated PowerShell (Run as Administrator).
#>
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Elevation check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator. Right-click PowerShell > Run as Administrator." -ForegroundColor Red
    return
}

Write-Host "`n=== RMM Stale MSI Cleanup ===" -ForegroundColor Cyan
Write-Host "Machine: $env:COMPUTERNAME | User: $env:USERNAME`n"

# --- Phase 1: Discovery (registry scan) ---
Write-Host "[Phase 1] Scanning for orphaned ITSPlatform/SAAZ/the PSA entries...`n" -ForegroundColor Yellow

$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

$found = @()
foreach ($path in $uninstallPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.DisplayName -like '*ITSPlatform*' -or
            $props.DisplayName -like '*SAAZ*' -or
            $props.DisplayName -like '*the PSA*') {
            $found += [PSCustomObject]@{
                Name    = $props.DisplayName
                Version = $props.DisplayVersion
                GUID    = $_.PSChildName
                Path    = $_.PSPath
            }
        }
    }
}

# Check Classes\Installer\Products (packed GUID format)
$installerProductsPath = 'HKLM:\SOFTWARE\Classes\Installer\Products'
$installerFound = @()
if (Test-Path $installerProductsPath) {
    Get-ChildItem $installerProductsPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.ProductName -like '*ITSPlatform*' -or
            $props.ProductName -like '*SAAZ*' -or
            $props.ProductName -like '*the PSA*') {
            $installerFound += [PSCustomObject]@{
                ProductName = $props.ProductName
                PackedGUID  = $_.PSChildName
                Path        = $_.PSPath
            }
        }
    }
}

# Check CW RMM registry quirk (leading space in key name)
$cw6432Paths = @(
    'HKLM:\SOFTWARE\WOW6432Node\ITSPlatform',
    'HKLM:\SOFTWARE\WOW6432Node\ \ITSPlatform'
)
$extraKeys = @()
foreach ($p in $cw6432Paths) {
    if (Test-Path $p) {
        $extraKeys += $p
    }
}

# Check scheduled task
$selfHealTask = $null
try {
    $selfHealTask = Get-ScheduledTask -TaskName 'ITSPlatformSelfHealUtility' -ErrorAction SilentlyContinue
} catch { }

# Check ProgramData remnant
$progDataPath = 'C:\ProgramData\SAAZOD'
$progDataExists = Test-Path $progDataPath

# --- Discovery report ---
Write-Host "--- Discovery Results ---" -ForegroundColor Cyan

if ($found.Count -gt 0) {
    Write-Host "Uninstall registry entries:" -ForegroundColor White
    $found | ForEach-Object {
        Write-Host "  Name: $($_.Name) | GUID: $($_.GUID) | Version: $($_.Version)"
    }
} else {
    Write-Host "  No Uninstall registry entries found" -ForegroundColor DarkGray
}

if ($installerFound.Count -gt 0) {
    Write-Host "Windows Installer product entries:" -ForegroundColor White
    $installerFound | ForEach-Object {
        Write-Host "  Product: $($_.ProductName) | Packed: $($_.PackedGUID)"
    }
} else {
    Write-Host "  No Installer\Products entries found" -ForegroundColor DarkGray
}

if ($extraKeys.Count -gt 0) {
    Write-Host "Extra CW RMM registry keys:" -ForegroundColor White
    $extraKeys | ForEach-Object { Write-Host "  $_" }
}

if ($selfHealTask) {
    Write-Host "Scheduled task: ITSPlatformSelfHealUtility (present)" -ForegroundColor White
}

if ($progDataExists) {
    Write-Host "ProgramData remnant: $progDataPath (present)" -ForegroundColor White
}

$totalItems = $found.Count + $installerFound.Count + $extraKeys.Count
if ($totalItems -eq 0 -and -not $selfHealTask -and -not $progDataExists) {
    Write-Host "`nNo orphaned entries found. Fresh MSI install should succeed." -ForegroundColor Green
    return
}

Write-Host "`n[Phase 2] Removing stale entries...`n" -ForegroundColor Yellow

# --- Phase 2a: Try msiexec /x for each discovered GUID ---
foreach ($entry in $found) {
    $guid = $entry.GUID
    if ($guid -match '^\{') {
        Write-Host "Attempting msiexec /x $guid /quiet /norestart..." -ForegroundColor White
        $proc = Start-Process msiexec -ArgumentList "/x $guid /quiet /norestart" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  msiexec succeeded (exit 0)" -ForegroundColor Green
        } else {
            Write-Host "  msiexec returned $($proc.ExitCode) — proceeding to registry cleanup" -ForegroundColor DarkYellow
        }
    }
}

# --- Phase 2b: Registry cleanup ---
# Remove Uninstall keys
foreach ($entry in $found) {
    $regPath = $entry.Path
    if (Test-Path $regPath) {
        Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed: $regPath" -ForegroundColor Green
    }
}

# Remove Classes\Installer entries
foreach ($entry in $installerFound) {
    $prodPath = $entry.Path
    Remove-Item $prodPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed: $prodPath" -ForegroundColor Green

    # Remove matching Features key
    $featPath = $prodPath -replace 'Products', 'Features'
    if (Test-Path $featPath) {
        Remove-Item $featPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed: $featPath" -ForegroundColor Green
    }

    # Remove UserData entry
    $udPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$($entry.PackedGUID)"
    if (Test-Path $udPath) {
        Remove-Item $udPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed: $udPath" -ForegroundColor Green
    }
}

# Remove extra CW RMM keys
foreach ($key in $extraKeys) {
    Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed: $key" -ForegroundColor Green
}

# Remove scheduled task
if ($selfHealTask) {
    Unregister-ScheduledTask -TaskName 'ITSPlatformSelfHealUtility' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Removed scheduled task: ITSPlatformSelfHealUtility" -ForegroundColor Green
}

# Remove ProgramData remnant
if ($progDataExists) {
    Remove-Item $progDataPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed: $progDataPath" -ForegroundColor Green
}

# --- Phase 3: Verification ---
Write-Host "`n[Phase 3] Verifying cleanup...`n" -ForegroundColor Yellow

$remainUninstall = 0
foreach ($path in $uninstallPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.DisplayName -like '*ITSPlatform*' -or
            $props.DisplayName -like '*SAAZ*' -or
            $props.DisplayName -like '*the PSA*') {
            $remainUninstall++
            Write-Host "  STILL PRESENT: $($props.DisplayName) at $($_.PSPath)" -ForegroundColor Red
        }
    }
}

$remainInstaller = 0
if (Test-Path $installerProductsPath) {
    Get-ChildItem $installerProductsPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.ProductName -like '*ITSPlatform*' -or
            $props.ProductName -like '*SAAZ*' -or
            $props.ProductName -like '*the PSA*') {
            $remainInstaller++
            Write-Host "  STILL PRESENT: $($props.ProductName) at $($_.PSPath)" -ForegroundColor Red
        }
    }
}

if ($remainUninstall -eq 0 -and $remainInstaller -eq 0) {
    Write-Host "ALL CLEAR — no orphaned MSI entries remain." -ForegroundColor Green
    Write-Host "`nReady for fresh agent install:" -ForegroundColor Cyan
    Write-Host "  1. Download agent from RMM portal > Sites > (select site) > Download Agent"
    Write-Host "  2. Run the MSI installer"
    Write-Host "  3. Verify: Get-Service ITSPlatform,ITSPlatformManager | Select Name,Status"
} else {
    Write-Host "`nWARNING: $($remainUninstall + $remainInstaller) entries remain. Manual review needed." -ForegroundColor Red
}
