<#
.SYNOPSIS
    Stop Adobe processes, clear Adobe AdobeFnt*.lst font cache files, stop the Windows
    FontCache service, delete FNTCACHE.DAT and FontCache folder contents, then restart
    the service. Reboot recommended.

.DESCRIPTION
    Two-layer font cache reset:
      Layer 1 (Adobe): AdobeFnt*.lst, AdobeCMapFnt*.lst, AdobeSysFnt*.lst files in
        - C:\Program Files\Common Files\Adobe\TypeSpt
        - %LOCALAPPDATA%\Adobe\Acrobat\DC
      Layer 2 (Windows): FontCache service + FNTCACHE.DAT + FontCache folder

    Both layers must be cleared together. Clearing only the Adobe layer leaves stale
    Windows font bitmaps that Acrobat still picks up. Clearing only the Windows layer
    leaves stale Adobe cache entries.

    Requires elevation (Run as Administrator or SYSTEM). A reboot is recommended
    after running so caches rebuild cleanly on next launch.

.NOTES
    Category: Diagnostics
    Context: User (interactive remote session, elevated) or RMM shell (SYSTEM)

.KEYWORDS
    Adobe, Acrobat, font, cache, clear, FNTCACHE, FontCache, AdobeFnt.lst,
    rendering, garbled
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'SilentlyContinue'
$changes = [System.Collections.Generic.List[string]]::new()

Write-Host "`n=== Clear-AdobeFontCache ===" -ForegroundColor Cyan
Write-Host ("Machine: {0}  User: {1}" -f $env:COMPUTERNAME, $env:USERNAME)
Write-Host ""

# --- 1. Kill Adobe processes ---
Write-Host "--- Stopping Adobe Processes ---" -ForegroundColor Yellow
foreach ($name in @('Acrobat', 'AcroCEF', 'AdobeCollabSync', 'AcroBroker', 'AdobeARM', 'AcroRd32')) {
    $procs = Get-Process -Name $name
    if ($procs) {
        $procs | Stop-Process -Force
        Write-Host ("  Stopped: {0} ({1} instance(s))" -f $name, $procs.Count)
        $changes.Add("Stopped $name")
    }
}
if ($changes.Count -eq 0) { Write-Host "  No Adobe processes running." }
Start-Sleep -Seconds 2

# --- 2. Clear Adobe font cache (.lst files) ---
Write-Host ""
Write-Host "--- Clearing Adobe Font Cache (.lst files) ---" -ForegroundColor Yellow
$cachePaths   = @("$env:ProgramFiles\Common Files\Adobe\TypeSpt", "${env:LOCALAPPDATA}\Adobe\Acrobat\DC")
$lstPatterns  = @('AdobeFnt*.lst', 'AdobeCMapFnt*.lst', 'AdobeSysFnt*.lst')
$deletedCount = 0

foreach ($path in $cachePaths) {
    if (Test-Path $path) {
        foreach ($pattern in $lstPatterns) {
            Get-ChildItem $path -Filter $pattern | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force
                    Write-Host ("  Deleted: {0}" -f $_.FullName)
                    $deletedCount++
                } catch {
                    Write-Host ("  FAILED to delete: {0} -- {1}" -f $_.FullName, $_.Exception.Message) -ForegroundColor Red
                }
            }
        }
    }
}
if ($deletedCount -gt 0) {
    $changes.Add("Deleted $deletedCount Adobe font cache .lst file(s)")
} else {
    Write-Host "  No Adobe font cache .lst files found (already clean)."
}

# --- 3. Stop FontCache service ---
Write-Host ""
Write-Host "--- Stopping Windows FontCache Service ---" -ForegroundColor Yellow
$fc = Get-Service FontCache
if ($fc -and $fc.Status -eq 'Running') {
    try {
        Stop-Service FontCache -Force
        Write-Host "  Stopped FontCache service."
        $changes.Add("Stopped FontCache service")
    } catch {
        Write-Host ("  FAILED to stop FontCache: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
} else {
    Write-Host ("  FontCache service is {0} (no stop needed)." -f $fc.Status)
}
Start-Sleep -Seconds 2

# --- 4. Delete FontCache folder contents ---
Write-Host ""
Write-Host "--- Clearing FontCache Folder ---" -ForegroundColor Yellow
$fcFolder = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"
if (Test-Path $fcFolder) {
    $files = Get-ChildItem $fcFolder
    $del   = 0
    foreach ($f in $files) {
        try { Remove-Item $f.FullName -Force -Recurse; $del++ }
        catch { Write-Host ("  FAILED: {0} -- {1}" -f $f.Name, $_.Exception.Message) -ForegroundColor Red }
    }
    Write-Host ("  Deleted {0} item(s) from FontCache folder." -f $del)
    if ($del -gt 0) { $changes.Add("Deleted $del FontCache folder item(s)") }
} else {
    Write-Host "  FontCache folder not found."
}

# --- 5. Delete FNTCACHE.DAT ---
Write-Host ""
Write-Host "--- Deleting FNTCACHE.DAT ---" -ForegroundColor Yellow
$fnt = "$env:SystemRoot\System32\FNTCACHE.DAT"
if (Test-Path $fnt) {
    try {
        Remove-Item $fnt -Force
        Write-Host "  Deleted FNTCACHE.DAT."
        $changes.Add("Deleted FNTCACHE.DAT")
    } catch {
        Write-Host ("  FAILED to delete FNTCACHE.DAT: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
} else {
    Write-Host "  FNTCACHE.DAT not present."
}

# --- 6. Restart FontCache ---
Write-Host ""
Write-Host "--- Restarting FontCache Service ---" -ForegroundColor Yellow
try {
    Start-Service FontCache
    Write-Host "  Restarted FontCache service."
    $changes.Add("Restarted FontCache service")
} catch {
    Write-Host ("  FAILED to restart FontCache: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# --- Summary ---
Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Green
if ($changes.Count -gt 0) {
    Write-Host "  Changes made:"
    $changes | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "  No changes made (caches already clean)."
}
Write-Host ""
Write-Host "  REBOOT RECOMMENDED -- font caches rebuild on next startup." -ForegroundColor Yellow
Write-Host "  After reboot, open an affected PDF in Acrobat to verify rendering.`n"
