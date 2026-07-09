#Requires -Version 5.1

<#
.SYNOPSIS
    Install-KB5078127 — Checks for KB5074109 (cloud sync breaker) and installs KB5078127 fix

.DESCRIPTION
    Preemptive check for the Jan 2026 security update KB5074109 that breaks
    OneDrive/SharePoint/Dropbox cloud-backed storage sync. If KB5074109 is
    present and KB5078127 (OOB fix, Jan 24 2026) is absent, searches Windows
    Update for KB5078127 and installs it.

    Run as the logged-in user with elevated (Run as Administrator) PowerShell.
    Uses the Windows Update COM API — no third-party modules required.

.EXAMPLE
    .\Install-KB5078127.ps1
    Checks both KBs, installs fix if needed.

.NOTES
    Category: System-Maintenance

.KEYWORDS
    update, KB5074109, KB5078127, OneDrive, SharePoint, sync, remediate

.ERRORCODES
    KB5074109
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Elevation check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires elevation. Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# --- Check installed hotfixes ---
Write-Host "Checking installed updates..." -ForegroundColor Cyan

$badKB = Get-HotFix -Id 'KB5074109' -ErrorAction SilentlyContinue
$fixKB = Get-HotFix -Id 'KB5078127' -ErrorAction SilentlyContinue

if ($null -eq $badKB) {
    Write-Host "KB5074109 not installed — no cloud sync risk from this update." -ForegroundColor Green
    Write-Host "No action needed."
    exit 0
}

Write-Host "KB5074109 FOUND (installed $($badKB.InstalledOn.ToString('yyyy-MM-dd')))" -ForegroundColor Yellow
Write-Host "  This update breaks OneDrive/SharePoint cloud-backed storage sync."

if ($null -ne $fixKB) {
    Write-Host "KB5078127 already installed (installed $($fixKB.InstalledOn.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    Write-Host "  Fix is in place. No action needed."
    exit 0
}

Write-Host "KB5078127 NOT installed — searching Windows Update for the fix..." -ForegroundColor Yellow

# --- Search Windows Update for KB5078127 ---
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $searcher = $updateSession.CreateUpdateSearcher()

    Write-Host "Querying Windows Update catalog (this may take a minute)..."
    $searchResult = $searcher.Search("IsInstalled=0")

    $targetUpdate = $null
    foreach ($update in $searchResult.Updates) {
        foreach ($kb in $update.KBArticleIDs) {
            if ($kb -eq '5078127') {
                $targetUpdate = $update
                break
            }
        }
        if ($null -ne $targetUpdate) { break }
    }

    if ($null -eq $targetUpdate) {
        Write-Host "KB5078127 not available via Windows Update on this machine." -ForegroundColor Red
        Write-Host "Possible reasons:"
        Write-Host "  - Already superseded by a newer cumulative update"
        Write-Host "  - Not applicable to this OS build"
        Write-Host "  - WSUS/SCCM policy restricting available updates"
        Write-Host ""
        Write-Host "Try: Settings > Windows Update > Check for updates manually,"
        Write-Host "or download KB5078127 from Microsoft Update Catalog." -ForegroundColor Cyan
        exit 1
    }

    Write-Host "Found: $($targetUpdate.Title)" -ForegroundColor Green

    # --- Download ---
    Write-Host "Downloading KB5078127..."
    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    $updatesToDownload.Add($targetUpdate) | Out-Null

    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $updatesToDownload
    $downloadResult = $downloader.Download()

    if ($downloadResult.ResultCode -ne 2) {
        Write-Host "Download failed (result code: $($downloadResult.ResultCode))" -ForegroundColor Red
        exit 1
    }
    Write-Host "Download complete." -ForegroundColor Green

    # --- Install ---
    Write-Host "Installing KB5078127..."
    $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    $updatesToInstall.Add($targetUpdate) | Out-Null

    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $updatesToInstall
    $installResult = $installer.Install()

    if ($installResult.ResultCode -eq 2) {
        Write-Host "KB5078127 installed successfully." -ForegroundColor Green
    } else {
        Write-Host "Installation returned result code: $($installResult.ResultCode)" -ForegroundColor Yellow
        Write-Host "  2=Succeeded, 3=SucceededWithErrors, 4=Failed, 5=Aborted"
    }

    if ($installResult.RebootRequired) {
        Write-Host ""
        Write-Host "REBOOT REQUIRED to complete installation." -ForegroundColor Yellow
        Write-Host "Schedule a reboot at the user's convenience."
    }

} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Fallback: download KB5078127 from Microsoft Update Catalog and install with wusa.exe" -ForegroundColor Cyan
    exit 1
}
