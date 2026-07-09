<#
.SYNOPSIS
    Zoom Direct MSI Deployment (Idempotent)
.DESCRIPTION
    Removes per-user Zoom installations and deploys machine-wide Zoom via MSI
    downloaded directly from Zoom. Idempotent - safe to re-run.

    Downloads from https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64
    Auto-update configured via ZConfig/ZRecommend MSI parameters.

    Designed for RMM deployment in SYSTEM context (PowerShell 5.1).
.PARAMETER MinVersion
    Minimum acceptable Zoom version. Skips install if installed >= this. Default: 0.0.0.0
.PARAMETER Force
    Force reinstall even if current version meets requirements.
.NOTES
    Created:    2026-01-29
    Context:    SYSTEM (RMM)
    PS Version: 5.1

    Exit codes:
    0   = Success (installed or already up-to-date)
    1   = Failure
    112 = Partial success (reboot required or warnings)

    Based on patterns from:
    - Deploy-SND-MSI-Idempotent.ps1 (idempotent structure)

    References:
    - MSI arguments: https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0064484
    - Auto-update policies: https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0058493
#>

param(
    [version]$MinVersion = "0.0.0.0",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Configuration ---
$ProductName = "Zoom"
$ZoomMsiUrl = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$InstalledExePath = "C:\Program Files\Zoom\bin\Zoom.exe"
$TempDir = "C:\temp"
$MsiFilename = "ZoomInstallerFull.msi"
$TempMsiPath = Join-Path $TempDir $MsiFilename
$LogPath = Join-Path $TempDir "ZoomDeploy_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$MinMsiSizeMB = 1  # Minimum valid MSI size in MB (catches HTML error pages)

# --- Enterprise MSI Options ---
# ZConfig: Locked settings users cannot change
#   nogoogle=1          - Disable Google calendar integration
#   kCmdParam_InstallOption=8 - Default to SSO login
# ZRecommend: Defaults users can modify
#   AudioAutoAdjust=1   - Enable automatic audio adjustment
$ZConfig = "nogoogle=1;kCmdParam_InstallOption=8"
$ZRecommend = "AudioAutoAdjust=1"

# --- Ensure temp directory exists BEFORE any logging ---
if (-not (Test-Path -PathType Container $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

# --- Functions ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogPath -Value $logLine -ErrorAction SilentlyContinue
    if ($Level -eq "ERROR") {
        Write-Output "ERROR: $Message"
    } else {
        Write-Output $Message
    }
}

function Get-InstalledVersion {
    param([string]$ExePath)
    if ([string]::IsNullOrEmpty($ExePath)) { return $null }
    if (Test-Path $ExePath) {
        $versionStr = (Get-Item $ExePath).VersionInfo.ProductVersion
        if ([string]::IsNullOrEmpty($versionStr)) { return $null }
        # Clean version string (handle formats like "1.2.3.4" or "1.2.3 (build 4)")
        $cleanVersion = $versionStr -replace '\s*\(.*\)', '' -replace '[^0-9.]', ''
        try {
            return [version]$cleanVersion
        } catch {
            return $null
        }
    }
    return $null
}

function Remove-PerUserZoom {
    param([string]$ProfilePath, [string]$Username)

    $removed = $false

    # Path to per-user Zoom uninstaller
    $uninstallerPath = Join-Path $ProfilePath "AppData\Roaming\Zoom\uninstall\Installer.exe"

    if (Test-Path $uninstallerPath) {
        Write-Log "Found Zoom uninstaller for $Username, running silent uninstall..."
        try {
            $proc = Start-Process -FilePath $uninstallerPath -ArgumentList "/uninstall","/silent" -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -eq 0) {
                Write-Log "Uninstall completed for $Username"
                $removed = $true
            } else {
                Write-Log "Uninstall returned exit code $($proc.ExitCode) for $Username" -Level "WARN"
            }
        } catch {
            Write-Log "Uninstall failed for $Username : $($_.Exception.Message)" -Level "WARN"
        }
    }

    # Clean up leftover Zoom folders
    $zoomPaths = @(
        (Join-Path $ProfilePath "AppData\Roaming\Zoom"),
        (Join-Path $ProfilePath "AppData\Local\Programs\Zoom"),
        (Join-Path $ProfilePath "AppData\Local\Zoom")
    )

    foreach ($path in $zoomPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Log "Removed: $path"
                $removed = $true
            } catch {
                Write-Log "Could not remove $path : $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    return $removed
}

# --- Main Script ---
try {
    Write-Log "=== $ProductName Direct MSI Deployment (Idempotent) ==="
    Write-Log "Source: $ZoomMsiUrl"
    Write-Log "MinVersion: $MinVersion | Force: $Force"

    # --- Phase 0: Version Check (Idempotent) ---
    $skipInstall = $false
    $installedVersion = $null

    Write-Log "--- Phase 0: Checking installed version ---"
    $installedVersion = Get-InstalledVersion -ExePath $InstalledExePath

    if ($null -ne $installedVersion) {
        Write-Log "Found installed version: $installedVersion"
        if ($installedVersion -ge $MinVersion -and -not $Force) {
            Write-Log "Installed version ($installedVersion) meets minimum ($MinVersion). Skipping install."
            $skipInstall = $true
        } elseif ($Force) {
            Write-Log "Force flag set - will reinstall regardless of version"
        } else {
            Write-Log "Installed version ($installedVersion) below minimum ($MinVersion). Will upgrade."
        }
    } else {
        Write-Log "No installation found at $InstalledExePath. Will install."
    }

    # Exit early if skip (but still log summary)
    if ($skipInstall) {
        Write-Log "=== Deployment Summary ==="
        Write-Log "Product: $ProductName"
        Write-Log "Action: Skipped (version adequate)"
        Write-Log "Installed version: $installedVersion"
        Write-Output "SUCCESS: $ProductName already installed ($installedVersion >= $MinVersion)"
        exit 0
    }

    # --- Phase 1: Remove Per-User Zoom Installations ---
    Write-Log "--- Phase 1: Removing per-user Zoom installations ---"

    $excludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
    $profiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $excludedProfiles -notcontains $_.Name }

    $cleanedCount = 0
    foreach ($profile in $profiles) {
        Write-Log "Checking profile: $($profile.Name)"
        if (Remove-PerUserZoom -ProfilePath $profile.FullName -Username $profile.Name) {
            $cleanedCount++
        }
    }
    Write-Log "Cleaned Zoom from $cleanedCount user profile(s)"

    # --- Phase 2: Download Zoom MSI (Direct from Zoom) ---
    Write-Log "--- Phase 2: Downloading Zoom MSI from Zoom ---"

    # Remove existing temp file if present
    if (Test-Path $TempMsiPath) {
        Remove-Item -Path $TempMsiPath -Force
    }

    try {
        # Use TLS 1.2 for download
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Write-Log "Downloading from: $ZoomMsiUrl"

        # Brief pause to ensure network stability
        Start-Sleep -Seconds 3

        Invoke-WebRequest -Uri $ZoomMsiUrl -OutFile $TempMsiPath -UseBasicParsing

        # Validate download: file must exist
        if (-not (Test-Path $TempMsiPath)) {
            throw "MSI download failed - file not found at $TempMsiPath"
        }

        # Validate download: file must be larger than MinMsiSizeMB (catches HTML error pages)
        $fileSizeBytes = (Get-Item $TempMsiPath).Length
        $fileSizeMB = $fileSizeBytes / 1MB

        if ($fileSizeMB -lt $MinMsiSizeMB) {
            # Check if it's HTML (common redirect/error response)
            $firstBytes = Get-Content -Path $TempMsiPath -TotalCount 1 -ErrorAction SilentlyContinue
            if ($firstBytes -match '<!DOCTYPE|<html|<HTML') {
                throw "Download returned HTML instead of MSI (likely redirect or error page)"
            }
            throw "Downloaded file too small ($([math]::Round($fileSizeMB, 2)) MB). Expected >${MinMsiSizeMB} MB."
        }

        Write-Log "Downloaded MSI: $([math]::Round($fileSizeMB, 2)) MB"
    } catch {
        throw "Failed to download Zoom MSI: $($_.Exception.Message)"
    }

    # --- Phase 3: Install Zoom MSI Machine-Wide ---
    Write-Log "--- Phase 3: Installing Zoom MSI machine-wide ---"

    $msiLogPath = Join-Path $TempDir "ZoomMsiInstall.log"

    # Build MSI arguments with enterprise config
    $msiArgs = "/i `"$TempMsiPath`" /qn /norestart /L*v `"$msiLogPath`" ZConfig=`"$ZConfig`" ZRecommend=`"$ZRecommend`""

    Write-Log "Running: msiexec $msiArgs"
    Write-Log "ZConfig: $ZConfig"
    Write-Log "ZRecommend: $ZRecommend"

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    $msiExitCode = $proc.ExitCode

    # Handle MSI exit codes: 0=success, 3010/1641=success+reboot needed, others=failure
    $rebootRequired = $false
    if ($msiExitCode -eq 0) {
        Write-Log "MSI installation completed successfully (exit code 0)"
    } elseif ($msiExitCode -eq 3010) {
        Write-Log "MSI installation succeeded - reboot required (exit code 3010)" -Level "WARN"
        $rebootRequired = $true
    } elseif ($msiExitCode -eq 1641) {
        Write-Log "MSI installation succeeded - reboot initiated (exit code 1641)" -Level "WARN"
        $rebootRequired = $true
    } else {
        throw "MSI installation failed with exit code: $msiExitCode. Check log: $msiLogPath"
    }

    # --- Phase 4: Validation ---
    Write-Log "--- Phase 4: Validation ---"

    $validationPassed = $true
    $newVersion = $null

    # Check Zoom.exe exists in Program Files
    if (Test-Path $InstalledExePath) {
        $newVersion = Get-InstalledVersion -ExePath $InstalledExePath
        Write-Log "PASS: Zoom.exe found at $InstalledExePath (Version: $newVersion)"
    } else {
        Write-Log "FAIL: Zoom.exe not found at $InstalledExePath" -Level "ERROR"
        $validationPassed = $false
    }

    # Check for remaining per-user Zoom directories
    $remainingZoom = @()
    foreach ($profile in $profiles) {
        $checkPaths = @(
            (Join-Path $profile.FullName "AppData\Roaming\Zoom"),
            (Join-Path $profile.FullName "AppData\Local\Programs\Zoom")
        )
        foreach ($checkPath in $checkPaths) {
            if (Test-Path $checkPath) {
                $remainingZoom += $checkPath
            }
        }
    }

    if ($remainingZoom.Count -eq 0) {
        Write-Log "PASS: No per-user Zoom directories remain"
    } else {
        Write-Log "WARN: Some per-user Zoom directories remain: $($remainingZoom -join ', ')" -Level "WARN"
    }

    Write-Log "INFO: Auto-update configured via ZConfig=$ZConfig"

    # --- Cleanup ---
    if (Test-Path $TempMsiPath) {
        Remove-Item -Path $TempMsiPath -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temp MSI file"
    }

    # --- Summary ---
    Write-Log "=== Deployment Summary ==="
    Write-Log "Product: $ProductName"
    Write-Log "Action: Installed"
    Write-Log "Profiles cleaned: $cleanedCount"
    if ($null -ne $newVersion) {
        Write-Log "Version: $newVersion"
    }
    Write-Log "ZConfig applied: $ZConfig"
    Write-Log "ZRecommend applied: $ZRecommend"
    Write-Log "Reboot required: $rebootRequired"
    Write-Log "Validation passed: $validationPassed"
    Write-Log "Log file: $LogPath"

    # Determine exit code
    if ($validationPassed -and -not $rebootRequired) {
        Write-Output "SUCCESS: $ProductName deployment completed"
        exit 0
    } elseif ($validationPassed -and $rebootRequired) {
        Write-Output "PARTIAL: $ProductName deployed successfully but reboot required"
        exit 112
    } else {
        Write-Output "PARTIAL: Deployment completed with warnings - review log at $LogPath"
        exit 112
    }

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level "ERROR"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
