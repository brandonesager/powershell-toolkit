<#
.SYNOPSIS
    Initialize-KioskDesktop — Prepopulate a shared kiosk PC desktop with shortcuts

.DESCRIPTION
    Creates desktop shortcuts for the "lab" account on a shared common-area kiosk PC. Adds app shortcuts for pre-installed Win 11 Home apps and URL shortcuts
    for commonly needed free web resources.

    Runs as the logged-in user (lab or manager) without admin rights.
    Safe to re-run — overwrites existing shortcuts with same name.

.EXAMPLE
    .\Initialize-KioskDesktop.ps1
    Creates all shortcuts on the current user's desktop

.EXAMPLE
    .\Initialize-KioskDesktop.ps1 -WhatIf
    Preview what shortcuts would be created without creating them

.NOTES
    Context: User (no admin required)

.KEYWORDS
    desktop, shortcuts, lab, kiosk
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Configuration (edit these to customize) ---

# App shortcuts: Name, Target exe, Icon (optional — blank uses target's default icon)
# Confirmed installed on the target PC
$AppShortcuts = @(
    @{ Name = 'Microsoft Edge';   Target = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; Icon = '' }
    @{ Name = 'Adobe Acrobat';    Target = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'; Icon = '' }
    @{ Name = 'Calculator';       Target = 'calc.exe'; Icon = '' }
    @{ Name = 'Notepad';          Target = 'notepad.exe'; Icon = '' }
    @{ Name = 'Paint';            Target = 'mspaint.exe'; Icon = '' }
)

# UWP app shortcuts: Name, AppUserModelId (shell:AppsFolder launch)
# These use explorer.exe shell:AppsFolder to launch Store apps without admin
$UwpShortcuts = @(
    @{ Name = 'Photos';           AppId = 'Microsoft.Windows.Photos_8wekyb3d8bbwe!App' }
    @{ Name = 'Snipping Tool';    AppId = 'Microsoft.ScreenSketch_8wekyb3d8bbwe!App' }
    @{ Name = 'Printers';         AppId = 'Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy!App' }
)

# Web shortcuts: Name, URL
$WebShortcuts = @(
    # Search & Email (web-based — safe for shared lab PC, no account persistence)
    @{ Name = 'Google';           URL = 'https://www.google.com' }
    @{ Name = 'Gmail';            URL = 'https://mail.google.com' }
    @{ Name = 'Yahoo Mail';       URL = 'https://mail.yahoo.com' }
    @{ Name = 'Outlook Mail';     URL = 'https://outlook.live.com' }

    # Office (free web versions — no license needed)
    @{ Name = 'Word Online';      URL = 'https://www.office.com/launch/word' }
    @{ Name = 'Excel Online';     URL = 'https://www.office.com/launch/excel' }

)

# --- End Configuration ---

$desktop = [Environment]::GetFolderPath('Desktop')
$shell = New-Object -ComObject WScript.Shell
$created = 0
$failed = 0

Write-Host "Desktop path: $desktop" -ForegroundColor Cyan
Write-Host ""

# Create app shortcuts (.lnk) — Win32 apps
Write-Host "=== App Shortcuts ===" -ForegroundColor Yellow
foreach ($app in $AppShortcuts) {
    $lnkPath = Join-Path $desktop "$($app.Name).lnk"

    # Resolve system apps (calc.exe, notepad.exe) to full path
    $target = $app.Target
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $resolved = Get-Command $target -ErrorAction SilentlyContinue
        if ($resolved) { $target = $resolved.Source }
    }

    if (-not (Test-Path $target)) {
        Write-Host "  SKIP: $($app.Name) — target not found: $target" -ForegroundColor DarkYellow
        continue
    }

    if ($PSCmdlet.ShouldProcess($lnkPath, "Create app shortcut")) {
        try {
            $shortcut = $shell.CreateShortcut($lnkPath)
            $shortcut.TargetPath = $target
            if ($app.Icon) { $shortcut.IconLocation = $app.Icon }
            $shortcut.Save()
            Write-Host "  OK: $($app.Name)" -ForegroundColor Green
            $created++
        }
        catch {
            Write-Host "  FAIL: $($app.Name) — $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}

Write-Host ""

# Create UWP app shortcuts (.lnk via shell:AppsFolder)
Write-Host "=== UWP App Shortcuts ===" -ForegroundColor Yellow
foreach ($uwp in $UwpShortcuts) {
    $lnkPath = Join-Path $desktop "$($uwp.Name).lnk"

    if ($PSCmdlet.ShouldProcess($lnkPath, "Create UWP shortcut")) {
        try {
            $shortcut = $shell.CreateShortcut($lnkPath)
            $shortcut.TargetPath = "explorer.exe"
            $shortcut.Arguments = "shell:AppsFolder\$($uwp.AppId)"
            $shortcut.Save()
            Write-Host "  OK: $($uwp.Name)" -ForegroundColor Green
            $created++
        }
        catch {
            Write-Host "  FAIL: $($uwp.Name) — $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}

Write-Host ""

# Create web shortcuts (.url)
Write-Host "=== Web Shortcuts ===" -ForegroundColor Yellow
foreach ($web in $WebShortcuts) {
    $urlPath = Join-Path $desktop "$($web.Name).url"

    if ($PSCmdlet.ShouldProcess($urlPath, "Create web shortcut")) {
        try {
            # .url files are INI format — no COM needed
            $content = @"
[InternetShortcut]
URL=$($web.URL)
"@
            Set-Content -Path $urlPath -Value $content -Encoding ASCII
            Write-Host "  OK: $($web.Name)" -ForegroundColor Green
            $created++
        }
        catch {
            Write-Host "  FAIL: $($web.Name) — $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}

Write-Host ""
Write-Host "Done: $created created, $failed failed" -ForegroundColor Cyan
