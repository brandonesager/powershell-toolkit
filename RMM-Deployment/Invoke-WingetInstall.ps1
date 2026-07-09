<#
.SYNOPSIS
    Install applications via winget in SYSTEM context (RMM/RMM shell).

.DESCRIPTION
    Resolves winget.exe directly from WindowsApps (PATH unavailable in SYSTEM context),
    then installs a configurable list of applications machine-wide. Handles already-installed
    apps gracefully. Run each install sequentially — loop scripts can hang on some apps
    when winget holds a source lock.

    SYSTEM context limitation: winget is not on PATH and cannot be invoked as a bare command.
    Direct path resolution via Get-ChildItem on WindowsApps is required.

    UWP/Store apps may fail with --scope machine. MSI/EXE installers work reliably.

.PARAMETER Apps
    Array of hashtables with keys: Id (winget package ID), Name (display name).
    Defaults to an empty array — populate before running.

.NOTES
    Context:    SYSTEM (RMM RMM shell or SYSTEM remote session)
    PS version: 5.1+
    Exit codes: 0 = all installed, 1 = winget not found, partial failures logged as WARN (exit 0)

#>

#!ps
#maxlength=100000
#timeout=600000

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] [$Level] $Msg"
}

Write-Log "=== WINGET APP INSTALLATION ==="
Write-Log "Machine: $env:COMPUTERNAME"

# --- Resolve winget path ---
# winget is not on PATH in SYSTEM context. Locate winget.exe directly under WindowsApps.
$wingetPath = $null
$appInstaller = Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" `
    -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1

if ($appInstaller) {
    $exe = Join-Path $appInstaller.FullName "winget.exe"
    if (Test-Path $exe) { $wingetPath = $exe }

    # Fallback: AppInstallerCLI.exe (older builds)
    if (-not $wingetPath) {
        $cli = Join-Path $appInstaller.FullName "AppInstallerCLI.exe"
        if (Test-Path $cli) { $wingetPath = $cli }
    }
}

if (-not $wingetPath) {
    Write-Log "winget not found under WindowsApps. Install App Installer from Store or deploy apps manually." -Level ERROR
    exit 1
}

Write-Log "Using winget: $wingetPath"

# --- App list ---
# Populate with hashtables: @{ Id = 'Publisher.AppName'; Name = 'Display Name' }
# Common IDs: Dropbox.Dropbox, Adobe.Acrobat.Reader.64-bit, Zoom.Zoom,
#             SlackTechnologies.Slack, Notepad++.Notepad++, 7zip.7zip,
#             PuTTY.PuTTY, ShareX.ShareX, Inkscape.Inkscape, Foxit.FoxitReader
$apps = @(
    # Add entries here, e.g.:
    # @{ Id = 'Dropbox.Dropbox'; Name = 'Dropbox' }
)

if ($apps.Count -eq 0) {
    Write-Log "No apps defined. Populate the `$apps array before running." -Level WARN
    exit 0
}

$installed = @()
$failed    = @()

# --- Install loop ---
# NOTE: Run sequentially. Parallel or rapid-fire calls can cause winget source lock contention.
# If running interactively in SYSTEM remote session, paste each line individually if the loop hangs.
foreach ($app in $apps) {
    Write-Log "Installing $($app.Name) ($($app.Id))..."
    try {
        $result   = & $wingetPath install --id $app.Id --silent --accept-package-agreements --accept-source-agreements --scope machine 2>&1
        $exitCode = $LASTEXITCODE
        $resultText = ($result | Out-String).Trim()

        if ($exitCode -eq 0) {
            Write-Log "SUCCESS: $($app.Name)" -Level SUCCESS
            $installed += $app.Name
        } elseif ($resultText -match 'already installed') {
            Write-Log "SKIP: $($app.Name) already installed" -Level SUCCESS
            $installed += $app.Name
        } else {
            Write-Log "WARN: $($app.Name) exit $exitCode" -Level WARN
            Write-Log $resultText -Level WARN
            $failed += "$($app.Name) (exit $exitCode)"
        }
    } catch {
        Write-Log "ERROR: $($app.Name) — $($_.Exception.Message)" -Level ERROR
        $failed += "$($app.Name) (exception)"
    }
}

# --- Summary ---
Write-Log "=== SUMMARY ==="
Write-Log "Installed ($($installed.Count)): $($installed -join ', ')"
if ($failed.Count -gt 0) {
    Write-Log "Failed ($($failed.Count)): $($failed -join ', ')" -Level WARN
    Write-Log "Install failed apps manually in a user session or via direct MSI." -Level WARN
}
