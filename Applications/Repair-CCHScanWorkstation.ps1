<#
.SYNOPSIS
    Full CCH ProSystem fx Scan Workstation removal and reinstall preparation.
.DESCRIPTION
    Aggressively removes an existing CCH Scan Workstation installation to prepare
    for a clean reinstall. Steps:
    1. Kills all processes that could lock CCH files
    2. Stops and disables all CCH-related services
    3. Takes ownership of the CCH installation folder
    4. Clears the tessdata OCR folder
    5. Removes CCH-related temp files
    6. Silently uninstalls the existing CCH Scan Workstation via MSI or EXE
    7. Force-deletes any remaining installation folder
    8. Launches the installer if found at -InstallerPath

    Requires elevation (Run as Administrator).
.PARAMETER InstallerPath
    Full path to the CCH Scan Workstation installer EXE. The script launches it
    elevated after cleanup. If the path does not exist, a prompt to run manually
    is shown instead.
    Default: empty (skips auto-launch).
.EXAMPLE
    .\Repair-CCHScanWorkstation.ps1 -InstallerPath "C:\Install\ProSystem fx Scan Workstation.exe"
.EXAMPLE
    .\Repair-CCHScanWorkstation.ps1
    # Runs cleanup only; installer must be launched manually.
.NOTES
    Context:    Elevated (Run as Administrator)
    Platform:   Windows 10/11, PS 5.1
    Client:     Contoso
.KEYWORDS
    CCH, ProSystem, scan, workstation, repair, reinstall, uninstall, Contoso
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$InstallerPath = ""
)

Write-Host "============================================" -ForegroundColor Red
Write-Host " CCH SCAN WORKSTATION REPAIR" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

# Step 1: Kill all potentially locking processes
Write-Host "[1/7] Killing all potentially locking processes..." -ForegroundColor Yellow

$processesToKill = @(
    "*CCH*", "*Scan*", "*PrintScan*", "*Broker*",
    "*tesseract*", "*ocr*", "*PDFlyer*", "*Axcess*",
    "msiexec", "TrustedInstaller"
)

foreach ($pattern in $processesToKill) {
    Get-Process | Where-Object { $_.Name -like $pattern } | ForEach-Object {
        Write-Host "  Killing: $($_.Name) [$($_.Id)]" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  Done." -ForegroundColor Green

# Step 2: Stop all CCH services
Write-Host "[2/7] Stopping all CCH services..." -ForegroundColor Yellow

$servicesToStop = @(
    "PrintScanBrokerService",
    "CCH*"
)

foreach ($svc in $servicesToStop) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Stopping: $($_.DisplayName)" -ForegroundColor Gray
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }
}
Write-Host "  Done." -ForegroundColor Green

# Step 3: Take ownership of CCH installation folder
Write-Host "[3/7] Taking ownership of CCH installation folder..." -ForegroundColor Yellow

$cchPath = "C:\Program Files (x86)\CCH ProSystem fx Scan Workstation"

if (Test-Path $cchPath) {
    takeown /F $cchPath /R /A /D Y 2>$null
    icacls $cchPath /reset /T /Q 2>$null
    icacls $cchPath /grant "BUILTIN\Administrators:(OI)(CI)F" /T /Q 2>$null
    icacls $cchPath /grant "BUILTIN\Users:(OI)(CI)M" /T /Q 2>$null
    icacls $cchPath /grant "SYSTEM:(OI)(CI)F" /T /Q 2>$null
    Write-Host "  Ownership and permissions reset." -ForegroundColor Green
} else {
    Write-Host "  CCH folder not found (fresh install)." -ForegroundColor Gray
}

# Step 4: Clear tessdata folder
Write-Host "[4/7] Clearing tessdata folder..." -ForegroundColor Yellow

$tessdata = "$cchPath\tessdata"

if (Test-Path $tessdata) {
    Remove-Item -Path $tessdata -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $tessdata) {
        Get-ChildItem $tessdata -File | ForEach-Object {
            $newName = "$($_.FullName).old"
            Rename-Item $_.FullName $newName -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  Tessdata files renamed to .old" -ForegroundColor Yellow
    } else {
        Write-Host "  Tessdata folder deleted." -ForegroundColor Green
    }
} else {
    Write-Host "  Tessdata folder not found." -ForegroundColor Gray
}

# Step 5: Clear temp installer files
Write-Host "[5/7] Clearing temp files..." -ForegroundColor Yellow

Remove-Item "$env:TEMP\*CCH*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\*Scan*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\*CCH*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "  Done." -ForegroundColor Green

# Step 6: Uninstall existing CCH Scan Workstation
Write-Host "[6/7] Uninstalling existing CCH Scan Workstation..." -ForegroundColor Yellow

$uninstallKeys = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$cchUninstall = $null
foreach ($key in $uninstallKeys) {
    $cchUninstall = Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*CCH*Scan*Workstation*" }
    if ($cchUninstall) { break }
}

if ($cchUninstall) {
    Write-Host "  Found: $($cchUninstall.DisplayName)" -ForegroundColor Gray
    $uninstallString = $cchUninstall.UninstallString

    if ($uninstallString -like "*msiexec*") {
        $productCode = $uninstallString -replace '.*(\{[A-Z0-9-]+\}).*','$1'
        Write-Host "  Running MSI uninstall..." -ForegroundColor Gray
        Start-Process msiexec -ArgumentList "/x $productCode /qn /norestart" -Wait -ErrorAction SilentlyContinue
    } else {
        Write-Host "  Running uninstaller..." -ForegroundColor Gray
        Start-Process cmd -ArgumentList "/c `"$uninstallString`" /S" -Wait -ErrorAction SilentlyContinue
    }
    Write-Host "  Uninstall complete." -ForegroundColor Green
} else {
    Write-Host "  No existing installation found." -ForegroundColor Gray
}

# Step 7: Delete remaining CCH folder
Write-Host "[7/7] Final cleanup..." -ForegroundColor Yellow

if (Test-Path $cchPath) {
    $emptyDir = "$env:TEMP\EmptyDir"
    New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
    robocopy $emptyDir $cchPath /MIR /R:1 /W:1 2>$null
    Remove-Item $cchPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $emptyDir -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $cchPath)) {
    Write-Host "  CCH folder completely removed." -ForegroundColor Green
} else {
    Write-Host "  WARNING: Some files remain (will be overwritten by reinstall)." -ForegroundColor Yellow
}

# Done - Launch installer
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " CLEANUP COMPLETE - READY FOR INSTALL" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

if (-not [string]::IsNullOrEmpty($InstallerPath) -and (Test-Path $InstallerPath)) {
    Write-Host "Launching installer as Administrator..." -ForegroundColor Cyan
    Start-Process $InstallerPath -Verb RunAs
} else {
    Write-Host "Please run the CCH Scan Workstation installer manually as Administrator." -ForegroundColor Yellow
    if (-not [string]::IsNullOrEmpty($InstallerPath)) {
        Write-Host "Installer not found at: $InstallerPath" -ForegroundColor Yellow
    }
}
