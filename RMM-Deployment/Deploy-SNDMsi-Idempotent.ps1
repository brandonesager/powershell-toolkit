<#
.SYNOPSIS
    Idempotent MSI deployment via SafeNetDeploy (SND).
.DESCRIPTION
    Generic, vendor-agnostic MSI deployment template. Downloads an MSI from a
    SafeNetDeploy public URL, validates the download, and installs silently.
    Safe to re-run: skips install if the installed version already meets the
    minimum requirement. Logs all phases to C:\temp.

    Designed for RMM deployment in SYSTEM context (PS 5.1).
.PARAMETER SNDUrl
    SafeNetDeploy public download URL for the MSI. Required.
.PARAMETER MsiFilename
    Local filename for the downloaded MSI. Default: Installer.msi
.PARAMETER ProductName
    Display name used in log output. Default: Application
.PARAMETER InstalledExePath
    Path to the installed executable for version checking. Skipped when omitted.
.PARAMETER TempDir
    Working directory for downloads and logs. Default: C:\temp
.PARAMETER MinVersion
    Minimum acceptable version. Skips install if installed version is >= this.
    Default: 0.0.0.0
.PARAMETER OptionalMsiArgs
    Additional MSI arguments (e.g., 'PROPERTY=value ANOTHER=value').
    Default: empty
.PARAMETER Force
    Force reinstall even if the current version meets the minimum requirement.
.EXAMPLE
    .\Deploy-SNDMsi-Idempotent.ps1 -SNDUrl "https://snd.rmm.example.com/public/download/TOKEN" -ProductName "Acme App"
.EXAMPLE
    .\Deploy-SNDMsi-Idempotent.ps1 -SNDUrl "https://snd.rmm.example.com/public/download/TOKEN" `
        -MsiFilename "AcmeInstaller.msi" -ProductName "Acme App" `
        -InstalledExePath "C:\Program Files\Acme\acme.exe" -MinVersion "2.0.0.0"
.NOTES
    Context:    SYSTEM (RMM)
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=Success (installed or already up-to-date), 1=Failure,
                112=Partial (reboot required or warnings)
    PS 5.1 compatible.
.KEYWORDS
    MSI, deployment, SND, SafeNetDeploy, RMM, idempotent, install
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SNDUrl,

    [string]$MsiFilename = "Installer.msi",
    [string]$ProductName = "Application",
    [string]$InstalledExePath = "",
    [string]$TempDir = "C:\temp",
    [version]$MinVersion = "0.0.0.0",
    [string]$OptionalMsiArgs = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Configuration ---
$MinMsiSizeMB = 1
$TempMsiPath = Join-Path $TempDir $MsiFilename
$LogPath = Join-Path $TempDir "$($ProductName -replace '\s+','')_Deploy_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
        $cleanVersion = $versionStr -replace '\s*\(.*\)', '' -replace '[^0-9.]', ''
        try {
            return [version]$cleanVersion
        } catch {
            return $null
        }
    }
    return $null
}

# --- Main Script ---
try {
    Write-Log "=== $ProductName MSI Deployment (SND) ==="
    Write-Log "Source: $SNDUrl"
    Write-Log "MSI: $MsiFilename"
    if (-not [string]::IsNullOrEmpty($InstalledExePath)) {
        Write-Log "Version check path: $InstalledExePath"
    }
    Write-Log "MinVersion: $MinVersion | Force: $Force"

    # --- Phase 0: Version Check (Idempotent) ---
    $skipInstall = $false
    $installedVersion = $null

    if (-not [string]::IsNullOrEmpty($InstalledExePath)) {
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
    } else {
        Write-Log "--- Phase 0: Skipped (no InstalledExePath provided) ---"
    }

    if ($skipInstall) {
        Write-Log "=== Deployment Summary ==="
        Write-Log "Product: $ProductName"
        Write-Log "Action: Skipped (version adequate)"
        Write-Log "Installed version: $installedVersion"
        Write-Output "SUCCESS: $ProductName already installed ($installedVersion >= $MinVersion)"
        exit 0
    }

    # --- Phase 1: Download MSI from SND ---
    Write-Log "--- Phase 1: Downloading MSI from SafeNetDeploy ---"

    if (Test-Path $TempMsiPath) {
        Remove-Item -Path $TempMsiPath -Force
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log "Downloading: $SNDUrl"
        Start-Sleep -Seconds 3

        Invoke-WebRequest -Uri $SNDUrl -OutFile $TempMsiPath -UseBasicParsing

        if (-not (Test-Path $TempMsiPath)) {
            throw "Download failed - file not found at $TempMsiPath"
        }

        $fileSizeBytes = (Get-Item $TempMsiPath).Length
        $fileSizeMB = $fileSizeBytes / 1MB

        if ($fileSizeMB -lt $MinMsiSizeMB) {
            $firstBytes = Get-Content -Path $TempMsiPath -TotalCount 1 -ErrorAction SilentlyContinue
            if ($firstBytes -match '<!DOCTYPE|<html|<HTML') {
                throw "Download returned HTML instead of MSI (redirect or error page)"
            }
            throw "Downloaded file too small ($([math]::Round($fileSizeMB, 2)) MB). Expected >${MinMsiSizeMB} MB."
        }

        Write-Log "Downloaded: $([math]::Round($fileSizeMB, 2)) MB"
    } catch {
        throw "Failed to download from SND: $($_.Exception.Message)"
    }

    # --- Phase 2: Install MSI ---
    Write-Log "--- Phase 2: Installing MSI ---"

    $msiLogPath = Join-Path $TempDir "$($ProductName -replace '\s+','')_MsiInstall.log"

    $msiArgs = "/i `"$TempMsiPath`" /qn /norestart /L*v `"$msiLogPath`""
    if (-not [string]::IsNullOrEmpty($OptionalMsiArgs)) {
        $msiArgs = "$msiArgs $OptionalMsiArgs"
    }

    Write-Log "Running: msiexec $msiArgs"

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    $msiExitCode = $proc.ExitCode

    $rebootRequired = $false
    if ($msiExitCode -eq 0) {
        Write-Log "MSI installation completed (exit code 0)"
    } elseif ($msiExitCode -eq 3010) {
        Write-Log "MSI installation succeeded - reboot required (exit code 3010)" -Level "WARN"
        $rebootRequired = $true
    } elseif ($msiExitCode -eq 1641) {
        Write-Log "MSI installation succeeded - reboot initiated (exit code 1641)" -Level "WARN"
        $rebootRequired = $true
    } else {
        throw "MSI installation failed (exit code: $msiExitCode). Check log: $msiLogPath"
    }

    # --- Phase 3: Validation ---
    Write-Log "--- Phase 3: Validation ---"

    $validationPassed = $true
    $newVersion = $null

    if (-not [string]::IsNullOrEmpty($InstalledExePath)) {
        if (Test-Path $InstalledExePath) {
            $newVersion = Get-InstalledVersion -ExePath $InstalledExePath
            Write-Log "PASS: Installed at $InstalledExePath (Version: $newVersion)"
        } else {
            Write-Log "WARN: Expected exe not found at $InstalledExePath" -Level "WARN"
            $validationPassed = $false
        }
    } else {
        Write-Log "INFO: No InstalledExePath - skipping exe validation"
    }

    # --- Cleanup ---
    if (Test-Path $TempMsiPath) {
        Remove-Item -Path $TempMsiPath -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temp MSI"
    }

    # --- Summary ---
    Write-Log "=== Deployment Summary ==="
    Write-Log "Product: $ProductName"
    Write-Log "Action: Installed"
    if ($null -ne $newVersion) {
        Write-Log "Version: $newVersion"
    }
    Write-Log "Reboot required: $rebootRequired"
    Write-Log "Validation: $validationPassed"
    Write-Log "Log: $LogPath"

    if ($validationPassed -and -not $rebootRequired) {
        Write-Output "SUCCESS: $ProductName deployment completed"
        exit 0
    } elseif ($validationPassed -and $rebootRequired) {
        Write-Output "PARTIAL: $ProductName deployed - reboot required"
        exit 112
    } else {
        Write-Output "PARTIAL: $ProductName deployment completed with warnings"
        exit 112
    }

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level "ERROR"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
