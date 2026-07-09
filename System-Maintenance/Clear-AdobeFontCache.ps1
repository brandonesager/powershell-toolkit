<#
.SYNOPSIS
    Clears Adobe Acrobat and Windows font caches to resolve font rendering issues.
.DESCRIPTION
    Stops Adobe processes, removes Adobe font cache .lst files, stops the Windows
    FontCache service, deletes FNTCACHE.DAT and FontCache folder contents, then
    restarts the service. Requires elevation (Run as Administrator).
    Reboot recommended after running.
.EXAMPLE
    .\Clear-AdobeFontCache.ps1
.NOTES
    Context:    User session (interactive remote session, elevated)
    Platform:   Windows 10/11, PS 5.1
    PS 5.1 compatible.
.KEYWORDS
    Adobe, font, cache, clear, FNTCACHE, FontCache, Acrobat, remediate
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "`n=== Font Cache Cleanup ===" -ForegroundColor Cyan
Write-Host "Machine: $env:COMPUTERNAME | User: $env:USERNAME`n"

$changes = [System.Collections.Generic.List[string]]::new()

# --- Step 1: Kill Adobe Processes ---
Write-Host "--- Stopping Adobe Processes ---" -ForegroundColor Yellow

$adobeProcesses = @('Acrobat', 'AcroCEF', 'AdobeCollabSync', 'AcroBroker', 'AdobeARM')
foreach ($procName in $adobeProcesses) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  Stopped: $procName ($($procs.Count) instance(s))"
        $changes.Add("Stopped $procName")
    }
}

if ($changes.Count -eq 0) {
    Write-Host "  No Adobe processes running"
}

Start-Sleep -Seconds 2

# --- Step 2: Clear Adobe Font Cache ---
Write-Host "`n--- Clearing Adobe Font Cache ---" -ForegroundColor Yellow

$adobeCachePaths = @(
    "$env:ProgramFiles\Common Files\Adobe\TypeSpt",
    "${env:LOCALAPPDATA}\Adobe\Acrobat\DC"
)

$lstPatterns = @('AdobeFnt*.lst', 'AdobeCMapFnt*.lst', 'AdobeSysFnt*.lst')
$deletedCount = 0

foreach ($cachePath in $adobeCachePaths) {
    if (Test-Path $cachePath) {
        foreach ($pattern in $lstPatterns) {
            $files = Get-ChildItem -Path $cachePath -Filter $pattern -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                try {
                    Remove-Item $f.FullName -Force -ErrorAction Stop
                    Write-Host "  Deleted: $($f.FullName)"
                    $deletedCount++
                } catch {
                    Write-Host "  FAILED to delete: $($f.FullName) -- $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

if ($deletedCount -gt 0) {
    $changes.Add("Deleted $deletedCount Adobe font cache file(s)")
} else {
    Write-Host "  No Adobe font cache files found"
}

# --- Step 3: Clear Windows Font Cache ---
Write-Host "`n--- Clearing Windows Font Cache ---" -ForegroundColor Yellow

$fontCacheService = Get-Service FontCache -ErrorAction SilentlyContinue
if ($fontCacheService -and $fontCacheService.Status -eq 'Running') {
    try {
        Stop-Service FontCache -Force -ErrorAction Stop
        Write-Host "  Stopped FontCache service"
        $changes.Add("Stopped FontCache service")
    } catch {
        Write-Host "  FAILED to stop FontCache service -- $($_.Exception.Message)" -ForegroundColor Red
    }
}

Start-Sleep -Seconds 2

$fontCacheFolder = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"
if (Test-Path $fontCacheFolder) {
    $fcFiles = Get-ChildItem $fontCacheFolder -ErrorAction SilentlyContinue
    if ($fcFiles.Count -gt 0) {
        $fcDeleted = 0
        foreach ($f in $fcFiles) {
            try {
                Remove-Item $f.FullName -Force -Recurse -ErrorAction Stop
                $fcDeleted++
            } catch {
                Write-Host "  FAILED to delete: $($f.Name) -- $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host "  Deleted $fcDeleted file(s) from FontCache folder"
        $changes.Add("Deleted $fcDeleted Windows FontCache file(s)")
    } else {
        Write-Host "  FontCache folder already empty"
    }
}

$fntcacheDat = "$env:SystemRoot\System32\FNTCACHE.DAT"
if (Test-Path $fntcacheDat) {
    try {
        Remove-Item $fntcacheDat -Force -ErrorAction Stop
        Write-Host "  Deleted FNTCACHE.DAT"
        $changes.Add("Deleted FNTCACHE.DAT")
    } catch {
        Write-Host "  FAILED to delete FNTCACHE.DAT -- $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  FNTCACHE.DAT not present"
}

try {
    Start-Service FontCache -ErrorAction Stop
    Write-Host "  Restarted FontCache service"
    $changes.Add("Restarted FontCache service")
} catch {
    Write-Host "  FAILED to restart FontCache service -- $($_.Exception.Message)" -ForegroundColor Red
}

# --- Summary ---
Write-Host "`n--- Summary ---" -ForegroundColor Green
if ($changes.Count -gt 0) {
    Write-Host "  Changes made:"
    foreach ($change in $changes) { Write-Host "  - $change" }
} else {
    Write-Host "  No changes made -- caches were already clean"
}

Write-Host "`n  ** REBOOT RECOMMENDED ** -- Font caches rebuild on next startup" -ForegroundColor Yellow
Write-Host "  After reboot, open an affected PDF in Acrobat to test rendering`n"
