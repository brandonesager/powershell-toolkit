<#
.SYNOPSIS
    Removes consumer AppX bloatware and HP Win32 software from a Windows endpoint.

.DESCRIPTION
    Two-phase removal:

    Phase 1 — AppX packages: removes consumer/non-business AppX packages defined in
    $AppxBloat. Preserves Edge, Office, Store, Calculator, Notepad, Paint, Photos,
    Snipping Tool, Terminal, frameworks/runtimes, managed security agents (e.g.,
    SentinelOne), RMM, M365, Intune, and any business application.

    Phase 2 — HP Win32 programs: removes HP bloatware (Wolf Security suite, HP agents,
    HP documentation, HP notifications, and related components) using the registered
    UninstallString. Uses msiexec /x for MSI-based entries and silent switches for
    EXE-based entries. Logs items with no uninstall string for manual follow-up.

    Modify $AppxBloat and $HpWin32Targets at the top of the script to adjust scope
    before deployment.

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1) or SYSTEM remote session
    Platform: Windows 10/11 — HP OEM hardware
    PS 5.1 compatible.

.KEYWORDS
    bloatware, appx, cleanup, hp, wolf security, workstation setup, OEM, PC refresh
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# -----------------------------------------------------------------------
# CONFIGURABLE: AppX packages to remove
# Add or remove package names as needed before deployment.
# -----------------------------------------------------------------------
$AppxBloat = @(
    'AppUp.IntelArcSoftware'
    'AppUp.IntelManagementandSecurityStatus'
    'Clipchamp.Clipchamp'
    'Microsoft.BingNews'
    'Microsoft.BingSearch'
    'Microsoft.BingWeather'
    'Microsoft.GamingApp'
    'Microsoft.GetHelp'
    'Microsoft.MicrosoftSolitaireCollection'
    'Microsoft.MicrosoftStickyNotes'
    'Microsoft.PowerAutomateDesktop'
    'Microsoft.Todos'
    'Microsoft.Windows.DevHome'
    'Microsoft.WindowsFeedbackHub'
    'Microsoft.WindowsSoundRecorder'
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxGamingOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
    'Microsoft.YourPhone'
    'Microsoft.ZuneMusic'
    'MicrosoftCorporationII.MicrosoftFamily'
    'MicrosoftWindows.CrossDevice'
    'MSTeams'
)

# -----------------------------------------------------------------------
# CONFIGURABLE: HP Win32 display names to uninstall
# Exact match. Wolf Security Chrome support uses a wildcard match below.
# -----------------------------------------------------------------------
$HpWin32Targets = @(
    'HP Connection Optimizer'
    'HP Documentation'
    'HP Insights'
    'HP Notifications'
    'HP One Agent'
    'HP Security Update Service'
    'HP Sure Recover'
    'HP Sure Run Module'
    'HP System Default Settings'
    'HP Wolf Security'
    'HP Wolf Security - Console'
    'HP Wolf Security Application Support for Sure Sense'
)

# Wolf Security Chrome support — version suffix varies; use wildcard match
$HpWolfChromePattern = 'HP Wolf Security Application Support for Chrome*'

# -----------------------------------------------------------------------
# Phase 1: AppX packages
# -----------------------------------------------------------------------
Write-Host "=== Phase 1: AppX Bloatware ===" -ForegroundColor Cyan

$appxRemoved = 0
$appxFailed  = 0

foreach ($app in $AppxBloat) {
    $pkg = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
    if ($pkg) {
        try {
            $pkg | Remove-AppxPackage -ErrorAction Stop
            Write-Host "Removed: $app" -ForegroundColor Green
            $appxRemoved++
        } catch {
            Write-Host "Failed: $app - $($_.Exception.Message)" -ForegroundColor Red
            $appxFailed++
        }
    } else {
        Write-Host "Not found: $app" -ForegroundColor Yellow
    }
}

Write-Host "AppX done. Removed: $appxRemoved | Failed: $appxFailed"

# -----------------------------------------------------------------------
# Phase 2: HP Win32 programs
# -----------------------------------------------------------------------
Write-Host "`n=== Phase 2: HP Win32 Programs ===" -ForegroundColor Cyan

$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$allInstalled = $regPaths | ForEach-Object {
    Get-ItemProperty $_ -ErrorAction SilentlyContinue
} | Where-Object { $_.DisplayName }

$hpRemoved = 0
$hpFailed  = 0
$hpManual  = @()

function Invoke-HpUninstall {
    param($Entry)
    $uninstall = $Entry.UninstallString
    if (-not $uninstall) {
        Write-Host "No uninstall string: $($Entry.DisplayName)" -ForegroundColor Yellow
        return $false
    }
    Write-Host "Uninstalling: $($Entry.DisplayName)..." -ForegroundColor White
    try {
        if ($uninstall -match 'msiexec') {
            $guid = [regex]::Match($uninstall, '\{[0-9A-Fa-f\-]+\}').Value
            if ($guid) {
                Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -ErrorAction Stop
            } else {
                Start-Process cmd.exe -ArgumentList "/c `"$uninstall /qn /norestart`"" -Wait -ErrorAction Stop
            }
        } else {
            $cleanCmd = $uninstall -replace '"', ''
            Start-Process cmd.exe -ArgumentList "/c `"$cleanCmd`" /s /S /silent /SILENT /quiet /QUIET" -Wait -ErrorAction Stop
        }
        Write-Host "Removed: $($Entry.DisplayName)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed: $($Entry.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

foreach ($target in $HpWin32Targets) {
    $entries = $allInstalled | Where-Object { $_.DisplayName -eq $target }
    foreach ($entry in $entries) {
        $result = Invoke-HpUninstall -Entry $entry
        if ($result -eq $true) { $hpRemoved++ }
        elseif ($result -eq $false -and -not $entry.UninstallString) { $hpManual += $entry.DisplayName }
        elseif ($result -eq $false) { $hpFailed++ }
    }
}

# HP Wolf Chrome support (version-specific name)
$chromeEntries = $allInstalled | Where-Object { $_.DisplayName -like $HpWolfChromePattern }
foreach ($entry in $chromeEntries) {
    $result = Invoke-HpUninstall -Entry $entry
    if ($result -eq $true) { $hpRemoved++ }
    elseif ($result -eq $false -and -not $entry.UninstallString) { $hpManual += $entry.DisplayName }
    elseif ($result -eq $false) { $hpFailed++ }
}

Write-Host "`nHP done. Removed: $hpRemoved | Failed: $hpFailed"

if ($hpManual.Count -gt 0) {
    Write-Host "`nManual removal needed (no uninstall string):" -ForegroundColor Yellow
    $hpManual | ForEach-Object { Write-Host "  - $_" }
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "AppX: $appxRemoved removed, $appxFailed failed (of $($AppxBloat.Count) targets)"
Write-Host "HP Win32: $hpRemoved removed, $hpFailed failed"
