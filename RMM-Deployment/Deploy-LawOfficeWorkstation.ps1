<#
.SYNOPSIS
    Deploys site-specific workstation configuration for a law office.

.DESCRIPTION
    Automated deployment for law-office workstations:
    - Creates RDS Web shortcut (required for Needles/WordPerfect)
    - Creates Litify Login shortcut
    - Installs Chrome, Firefox, VLC, Adobe Reader DC via winget (SYSTEM context)
    - Dialpad excluded (requires manual install or separate deployment)

    Run as SYSTEM via RMM.

.PARAMETER SkipInstalls
    Skip software installation, only create shortcuts.

.EXAMPLE
    .\Deploy-LawOfficeWorkstation.ps1

.EXAMPLE
    .\Deploy-LawOfficeWorkstation.ps1 -SkipInstalls

.NOTES
    Winget SYSTEM context: resolved via WindowsApps path resolution
    Winget exit code -1978335189 = already installed (treated as success)
    Winget exit code -1978335215 = no machine-scope installer available
    Add --disable-interactivity to suppress progress bar noise in RMM logs
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipInstalls
)

$ErrorActionPreference = "Stop"

$Shortcuts = @{
    "Remote Apps (RDS)" = "https://remote.contoso.com/RDWeb"
    "Litify Login"               = "https://contoso.litify.com"
}

$TempDir      = "C:\Temp\ClientSetup"
$PublicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")

function Find-WingetPath {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue
    if ($paths) { return ($paths | Select-Object -Last 1).Path }
    $paths = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\AppInstallerCLI.exe" -ErrorAction SilentlyContinue
    if ($paths) { return ($paths | Select-Object -Last 1).Path }
    return $null
}

function Test-AppInstalled {
    param([string]$ExePath)
    return Test-Path $ExePath
}

function Install-WingetApp {
    param(
        [string]$WingetPath,
        [string]$PackageId,
        [string]$ExePath
    )
    if (Test-AppInstalled $ExePath) { return "Skipped" }
    $result = & $WingetPath install --id $PackageId --silent --accept-package-agreements --accept-source-agreements --scope machine --disable-interactivity 2>&1
    switch ($LASTEXITCODE) {
        0               { return "Installed" }
        -1978335189     { return "Skipped" }  # Already installed
        -1978335212     { return "Skipped" }  # No upgrade available
        -1978335215     { return "Failed" }   # No machine-scope installer
        default         { return "Failed" }
    }
}

try {
    Write-Host "=== Law Office Workstation Deployment ==="
    Write-Host "Machine: $env:COMPUTERNAME"
    Write-Host "Context: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    if (!(Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }

    # --- Shortcuts ---
    Write-Host "`n[SHORTCUTS] Creating desktop shortcuts..."
    $WScript = New-Object -ComObject WScript.Shell
    foreach ($Name in $Shortcuts.Keys) {
        $Path     = Join-Path $PublicDesktop "$Name.url"
        $Shortcut = $WScript.CreateShortcut($Path)
        $Shortcut.TargetPath = $Shortcuts[$Name]
        $Shortcut.Save()
        Write-Host "  [OK] $Name"
    }

    if ($SkipInstalls) {
        Write-Host "SkipInstalls specified — skipping software."
        Write-Output "SUCCESS: Shortcuts created, installs skipped"
        exit 0
    }

    # --- Winget ---
    Write-Host "`n[WINGET] Locating winget executable..."
    $Winget = Find-WingetPath
    if (!$Winget) {
        Write-Host "[ERROR] winget not found — install manually or deploy AppInstaller"
        exit 1
    }
    Write-Host "[WINGET] Found winget at: $Winget"
    $ver = & $Winget --version 2>&1
    Write-Host "[WINGET] Version: $ver"

    # --- Software ---
    $Apps = @(
        @{ Id = "Google.Chrome";              Name = "Google Chrome";     Exe = "C:\Program Files\Google\Chrome\Application\chrome.exe" },
        @{ Id = "Mozilla.Firefox";            Name = "Mozilla Firefox";   Exe = "C:\Program Files\Mozilla Firefox\firefox.exe" },
        @{ Id = "VideoLAN.VLC";               Name = "VLC Media Player";  Exe = "C:\Program Files\VideoLAN\VLC\vlc.exe" },
        @{ Id = "Adobe.Acrobat.Reader.64-bit"; Name = "Adobe Reader DC"; Exe = "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" }
    )

    $Installed = @(); $Skipped = @(); $Failed = @()

    Write-Host "`n[INSTALL] Beginning software installation..."
    foreach ($App in $Apps) {
        Write-Host "  Installing $($App.Name) ($($App.Id))..."
        $status = Install-WingetApp -WingetPath $Winget -PackageId $App.Id -ExePath $App.Exe
        switch ($status) {
            "Installed" { $Installed += $App.Name; Write-Host "  [OK] $($App.Name) installed" }
            "Skipped"   { $Skipped   += $App.Name; Write-Host "  [SKIP] $($App.Name) already installed" }
            "Failed"    { $Failed    += $App.Name; Write-Host "  [FAIL] $($App.Name) failed (exit $LASTEXITCODE)" }
        }
    }

    # --- Summary ---
    Write-Host "`n=== Deployment Summary ==="
    Write-Host "Installed: $($Installed.Count) ($($Installed -join ', '))"
    Write-Host "Skipped:   $($Skipped.Count) ($($Skipped -join ', '))"
    Write-Host "Failed:    $($Failed.Count) ($($Failed -join ', '))"

    if ($Failed.Count -gt 0) {
        Write-Output "PARTIAL: Installed=$($Installed.Count) Skipped=$($Skipped.Count) Failed=$($Failed.Count): $($Failed -join ', ')"
        exit 1
    }

    Write-Output "SUCCESS: Installed=$($Installed.Count) Skipped=$($Skipped.Count)"
    exit 0

} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
