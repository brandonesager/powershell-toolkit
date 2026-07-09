<#
.SYNOPSIS
    Diagnoses Adobe Acrobat font rendering issues: installation, version, cache, and Protected Mode.
.DESCRIPTION
    Read-only diagnostic for Adobe font rendering problems. Checks:
    - Adobe Acrobat installation state and version
    - Known buggy versions listed in -KnownBadVersions
    - Protected Mode registry setting
    - Adobe font cache .lst files (AdobeFnt, AdobeCMapFnt, AdobeSysFnt)
    - Adobe preferences folder size
    - Windows FontCache service status
    - FNTCACHE.DAT age and size
    - FontCache service folder file count

    No elevation required. Makes no changes.
    Run in the affected user's session (interactive remote session).
.PARAMETER AcrobatVersion
    Acrobat registry subkey to check for Protected Mode setting.
    Default: DC (covers Acrobat DC and later).
.PARAMETER KnownBadVersions
    Array of version strings known to cause font rendering bugs.
    Default: @('2025.001.20744')
.EXAMPLE
    .\Get-AdobeFontDiag.ps1
.EXAMPLE
    .\Get-AdobeFontDiag.ps1 -AcrobatVersion "2020" -KnownBadVersions @('2020.013.20074','2025.001.20744')
.NOTES
    Context:    User session (interactive remote session)
    Platform:   Windows 10/11, PS 5.1
.KEYWORDS
    Adobe, Acrobat, font, cache, rendering, Protected Mode, diagnostic, FNTCACHE
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$AcrobatVersion = "DC",

    [string[]]$KnownBadVersions = @('2025.001.20744')
)

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "`n=== Adobe Font Diagnostic ===" -ForegroundColor Cyan
Write-Host "Machine: $env:COMPUTERNAME | User: $env:USERNAME`n"

# --- Adobe Installation Check ---
Write-Host "--- Adobe Acrobat Installation ---" -ForegroundColor Yellow

$adobeKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$acrobat = foreach ($keyPath in $adobeKeys) {
    Get-ItemProperty $keyPath -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Adobe Acrobat' }
}

if ($acrobat) {
    foreach ($app in $acrobat) {
        Write-Host "  Found: $($app.DisplayName)"
        Write-Host "  Version: $($app.DisplayVersion)"
        Write-Host "  Install Location: $($app.InstallLocation)"

        foreach ($badVer in $KnownBadVersions) {
            if ($app.DisplayVersion -match [regex]::Escape($badVer)) {
                Write-Host "  ** WARNING: Known rendering bug version ($badVer) **" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "  Adobe Acrobat NOT FOUND in registry" -ForegroundColor Red
}

# --- Protected Mode ---
Write-Host "`n--- Protected Mode ---" -ForegroundColor Yellow

$protectedMode = Get-ItemProperty "HKCU:\Software\Adobe\Adobe Acrobat\$AcrobatVersion\Privileged" -Name bProtectedMode -ErrorAction SilentlyContinue
if ($null -ne $protectedMode) {
    $pmValue = $protectedMode.bProtectedMode
    $pmStatus = if ($pmValue -eq 0) { "Disabled" } else { "Enabled" }
    Write-Host "  Protected Mode: $pmStatus (value=$pmValue)"
} else {
    Write-Host "  Protected Mode: Registry key not found (default = Enabled)"
}

# --- Adobe Font Cache Files ---
Write-Host "`n--- Adobe Font Cache Files ---" -ForegroundColor Yellow

$adobeCachePaths = @(
    "$env:ProgramFiles\Common Files\Adobe\TypeSpt",
    "${env:LOCALAPPDATA}\Adobe\Acrobat\$AcrobatVersion"
)

$lstPatterns = @('AdobeFnt*.lst', 'AdobeCMapFnt*.lst', 'AdobeSysFnt*.lst')
$foundCache = $false

foreach ($cachePath in $adobeCachePaths) {
    if (Test-Path $cachePath) {
        foreach ($pattern in $lstPatterns) {
            $files = Get-ChildItem -Path $cachePath -Filter $pattern -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $foundCache = $true
                Write-Host "  $($f.FullName) -- $([math]::Round($f.Length/1KB,1)) KB, modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
            }
        }
    }
}

if (-not $foundCache) {
    Write-Host "  No Adobe font cache .lst files found"
}

# --- Adobe Preferences Folder ---
Write-Host "`n--- Adobe Preferences ---" -ForegroundColor Yellow

$adobePrefsPath = "$env:APPDATA\Adobe\Acrobat\$AcrobatVersion"
if (Test-Path $adobePrefsPath) {
    $prefsSize = (Get-ChildItem $adobePrefsPath -Recurse -Force -ErrorAction SilentlyContinue |
        Measure-Object Length -Sum).Sum
    Write-Host "  Prefs folder exists: $adobePrefsPath"
    Write-Host "  Size: $([math]::Round($prefsSize/1MB,1)) MB"
} else {
    Write-Host "  Prefs folder NOT FOUND -- Adobe may be uninstalled or never configured" -ForegroundColor Red
}

# --- Windows Font Cache ---
Write-Host "`n--- Windows Font Cache ---" -ForegroundColor Yellow

$fontCacheService = Get-Service FontCache -ErrorAction SilentlyContinue
if ($fontCacheService) {
    Write-Host "  FontCache service: $($fontCacheService.Status)"
} else {
    Write-Host "  FontCache service: NOT FOUND" -ForegroundColor Red
}

$fntcacheDat = "$env:SystemRoot\System32\FNTCACHE.DAT"
if (Test-Path $fntcacheDat) {
    $fntInfo = Get-Item $fntcacheDat -ErrorAction SilentlyContinue
    Write-Host "  FNTCACHE.DAT: $([math]::Round($fntInfo.Length/1MB,1)) MB, modified $($fntInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
} else {
    Write-Host "  FNTCACHE.DAT: NOT FOUND"
}

$fontCacheFolder = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"
if (Test-Path $fontCacheFolder) {
    $fcFiles = Get-ChildItem $fontCacheFolder -ErrorAction SilentlyContinue
    $fcSize = ($fcFiles | Measure-Object Length -Sum).Sum
    Write-Host "  FontCache folder: $($fcFiles.Count) files, $([math]::Round($fcSize/1MB,1)) MB"
} else {
    Write-Host "  FontCache folder: NOT FOUND"
}

# --- Summary ---
Write-Host "`n--- Summary ---" -ForegroundColor Green
$issues = @()
if (-not $acrobat) { $issues += "Adobe Acrobat not installed" }
foreach ($badVer in $KnownBadVersions) {
    if ($acrobat -and ($acrobat | Where-Object { $_.DisplayVersion -match [regex]::Escape($badVer) })) {
        $issues += "Buggy version $badVer detected"
    }
}
if ($foundCache) { $issues += "Stale Adobe font cache files present" }
if (-not (Test-Path $adobePrefsPath)) { $issues += "Adobe preferences folder missing" }

if ($issues.Count -gt 0) {
    Write-Host "  Issues found:"
    foreach ($issue in $issues) { Write-Host "  - $issue" -ForegroundColor Red }
} else {
    Write-Host "  No obvious issues detected -- font problem may be PDF-specific or preference-based"
}

Write-Host "`nNext: Run Clear-AdobeFontCache.ps1 (elevated) to clear caches`n"
