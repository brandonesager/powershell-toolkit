<#
.SYNOPSIS
    Diagnose OneDrive file presence across all user profiles.

.DESCRIPTION
    Scans all user profiles (including renamed variants like .OLD, .HQ, .DOMAIN) for OneDrive
    folders. Reports file counts by year, date ranges, placeholder vs. hydrated file states,
    and checks for Windows Update issues that affect OneDrive sync (KB5074109/KB5078127).

    Designed for RMM (PowerShell 5.1, SYSTEM context).

    Use case: User reports missing OneDrive files after profile re-creation. This script
    identifies where files actually reside and whether sync root points to old profile.

.PARAMETER TargetYear
    Highlight files from this year forward in output (default: current year - 2).

.PARAMETER Verbose
    Enable verbose logging for troubleshooting.

.EXAMPLE
    .\Get-OneDriveLocalRecovery.ps1

    Scans all profiles, highlights files from 2 years ago to present.

.EXAMPLE
    .\Get-OneDriveLocalRecovery.ps1 -TargetYear 2024 -Verbose

    Highlights files from 2024 onward with detailed logging.

.NOTES
    Context: RMM (SYSTEM), PS 5.1

.LINK
#>

[CmdletBinding()]
param(
    [int]$TargetYear = ((Get-Date).Year - 2)
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message"
}

try {
    Write-Log "=== OneDrive Local Recovery Diagnostic ==="
    Write-Log "Computer: $env:COMPUTERNAME"
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Log "OS: $($os.Caption) Build $($os.BuildNumber)"
    Write-Log "Target year range: $TargetYear+"

    # --- Section 1: Discover all user profile folders ---
    Write-Log "--- Section 1: User Profile Discovery ---"

    $profileDirs = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('All Users', 'Default', 'Default User', 'Public') }

    foreach ($dir in $profileDirs) {
        $hasNtuser = Test-Path (Join-Path $dir.FullName "NTUSER.DAT") -ErrorAction SilentlyContinue
        $isOldProfile = $dir.Name -match '\.(OLD|HQ|DOMAIN|bak|BACKUP)\b' -or ($dir.Name -match '\.\w+$' -and $dir.Name -notmatch '^\.')
        $label = if ($isOldProfile) { "OLD/RENAMED" } elseif ($hasNtuser) { "ACTIVE" } else { "PARTIAL" }
        Write-Host ("  [{0,-12}] {1}" -f $label, $dir.FullName)
    }

    # --- Section 2: Find OneDrive folders in all profiles ---
    Write-Log "--- Section 2: OneDrive Folder Discovery ---"

    $oneDrivePatterns = @('OneDrive*', 'OneDrive - *')
    $discoveredFolders = @()

    foreach ($dir in $profileDirs) {
        foreach ($pattern in $oneDrivePatterns) {
            $odFolders = Get-ChildItem -Path $dir.FullName -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like $pattern }

            foreach ($odFolder in $odFolders) {
                $discoveredFolders += $odFolder
            }
        }
    }

    if ($discoveredFolders.Count -eq 0) {
        Write-Log "No OneDrive folders found in any profile." -Level "WARN"
    }
    else {
        Write-Host ""
        Write-Log "Found $($discoveredFolders.Count) OneDrive folder(s):"

        foreach ($odFolder in $discoveredFolders) {
            Write-Host ""
            Write-Host ("  FOLDER: {0}" -f $odFolder.FullName) -ForegroundColor Cyan

            # Count files and get date ranges
            $allFiles = @()
            try {
                $allFiles = @(Get-ChildItem -Path $odFolder.FullName -File -Recurse -Force -ErrorAction SilentlyContinue)
            }
            catch {
                Write-Log "  Error scanning: $($_.Exception.Message)" -Level "WARN"
                continue
            }

            $totalFiles = $allFiles.Count
            $totalFolders = @(Get-ChildItem -Path $odFolder.FullName -Directory -Recurse -Force -ErrorAction SilentlyContinue).Count

            if ($totalFiles -eq 0) {
                Write-Host "    Files: 0 (empty)" -ForegroundColor Yellow
                continue
            }

            # Date range
            $dates = $allFiles | ForEach-Object { $_.LastWriteTime }
            $oldest = ($dates | Measure-Object -Minimum).Minimum
            $newest = ($dates | Measure-Object -Maximum).Maximum

            Write-Host ("    Files: {0:N0}  |  Folders: {1:N0}" -f $totalFiles, $totalFolders)
            Write-Host ("    Date range: {0:yyyy-MM-dd} to {1:yyyy-MM-dd}" -f $oldest, $newest)

            # Files by year
            $byYear = $allFiles | Group-Object { $_.LastWriteTime.Year } | Sort-Object Name
            Write-Host "    Files by year:"
            foreach ($yearGroup in $byYear) {
                $yearDates = $yearGroup.Group | ForEach-Object { $_.LastWriteTime }
                $yearOldest = ($yearDates | Measure-Object -Minimum).Minimum
                $yearNewest = ($yearDates | Measure-Object -Maximum).Maximum
                $marker = if ([int]$yearGroup.Name -ge $TargetYear) { " <-- TARGET RANGE" } else { "" }
                Write-Host ("      {0}: {1,6:N0} files  ({2:yyyy-MM-dd} to {3:yyyy-MM-dd}){4}" -f $yearGroup.Name, $yearGroup.Count, $yearOldest, $yearNewest, $marker)
            }

            # Check for placeholder (cloud-only) files
            $placeholderCount = 0
            $hydratedCount = 0
            foreach ($f in $allFiles) {
                $hasOffline = ($f.Attributes -band [System.IO.FileAttributes]::Offline) -ne 0
                $hasReparse = ($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                if ($hasOffline -and $hasReparse) { $placeholderCount++ }
                else { $hydratedCount++ }
            }
            Write-Host ("    Hydrated (local): {0:N0}  |  Placeholder (cloud-only): {1:N0}" -f $hydratedCount, $placeholderCount)

            # Total size of hydrated files
            $hydratedSize = ($allFiles | Where-Object {
                $off = ($_.Attributes -band [System.IO.FileAttributes]::Offline) -ne 0
                $rp = ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                -not ($off -and $rp)
            } | Measure-Object -Property Length -Sum).Sum
            if ($null -eq $hydratedSize) { $hydratedSize = 0 }
            $hydratedGB = [math]::Round($hydratedSize / 1GB, 2)
            Write-Host ("    Hydrated size: {0:N2} GB" -f $hydratedGB)
        }
    }

    # --- Section 3: Check for KFM-redirected folders outside OneDrive ---
    Write-Log "--- Section 3: Known Folder Move Check ---"

    foreach ($dir in $profileDirs) {
        $kfmFolders = @('Desktop', 'Documents', 'Pictures')
        $hasKfmFiles = $false
        foreach ($kf in $kfmFolders) {
            $kfPath = Join-Path $dir.FullName $kf
            if (Test-Path $kfPath) {
                $kfFiles = @(Get-ChildItem -Path $kfPath -File -Recurse -Force -ErrorAction SilentlyContinue)
                if ($kfFiles.Count -gt 0) {
                    if (-not $hasKfmFiles) {
                        Write-Host "  Profile: $($dir.Name)" -ForegroundColor Cyan
                        $hasKfmFiles = $true
                    }
                    $kfSize = ($kfFiles | Measure-Object -Property Length -Sum).Sum
                    if ($null -eq $kfSize) { $kfSize = 0 }
                    Write-Host ("    {0}: {1:N0} files, {2:N2} GB" -f $kf, $kfFiles.Count, ($kfSize / 1GB))
                }
            }
        }
    }

    # --- Section 4: OneDrive sync client status ---
    Write-Log "--- Section 4: OneDrive Sync Client ---"

    $odProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($odProcesses) {
        foreach ($proc in $odProcesses) {
            $owner = "unknown"
            try {
                $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).GetOwner().User
            }
            catch { }
            Write-Host ("  OneDrive.exe running — PID: {0}, User: {1}" -f $proc.Id, $owner)
        }
    }
    else {
        Write-Host "  OneDrive.exe is NOT running" -ForegroundColor Yellow
    }

    # Check OneDrive version from registry
    $odVersionKeys = @(
        "HKLM:\SOFTWARE\Microsoft\OneDrive",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive"
    )
    foreach ($key in $odVersionKeys) {
        if (Test-Path $key) {
            $ver = (Get-ItemProperty -Path $key -Name "Version" -ErrorAction SilentlyContinue).Version
            if ($ver) { Write-Host "  OneDrive version: $ver" }
        }
    }

    # --- Section 5: Windows Update check for KB5074109/KB5078127 ---
    Write-Log "--- Section 5: Windows Update History (KB5074109 / KB5078127) ---"

    $targetKBs = @('KB5074109', 'KB5078127')
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -in $targetKBs }

    if ($hotfixes) {
        foreach ($hf in $hotfixes) {
            $status = if ($hf.HotFixID -eq 'KB5074109') { "PROBLEM UPDATE (cloud I/O bug)" } else { "FIX UPDATE" }
            Write-Host ("  {0} — Installed: {1:yyyy-MM-dd} — {2}" -f $hf.HotFixID, $hf.InstalledOn, $status)
        }
    }
    else {
        Write-Host "  Neither KB5074109 nor KB5078127 found in hotfix list"
        # Fallback: check via WU session history
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $count = $searcher.GetTotalHistoryCount()
            if ($count -gt 0) {
                $history = $searcher.QueryHistory(0, [math]::Min($count, 100))
                foreach ($kb in $targetKBs) {
                    $match = $history | Where-Object { $_.Title -like "*$kb*" } | Select-Object -First 1
                    if ($match) {
                        Write-Host ("  {0} — Found in WU history: {1:yyyy-MM-dd} — {2}" -f $kb, $match.Date, $match.Title)
                    }
                    else {
                        Write-Host "  $kb — Not found in WU history"
                    }
                }
            }
        }
        catch {
            Write-Host "  Could not query WU history: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # --- Section 6: Summary ---
    Write-Host ""
    Write-Log "=== Diagnostic Complete ==="

    $hasTargetFiles = $false
    foreach ($odFolder in $discoveredFolders) {
        $targetFiles = @(Get-ChildItem -Path $odFolder.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime.Year -ge $TargetYear })
        if ($targetFiles.Count -gt 0) {
            $hasTargetFiles = $true
            Write-Host ("  FOUND: {0:N0} files from {1}+ in {2}" -f $targetFiles.Count, $TargetYear, $odFolder.FullName) -ForegroundColor Green
        }
    }

    if (-not $hasTargetFiles) {
        Write-Host "  NO files from target year range found in any local OneDrive folder" -ForegroundColor Red
        Write-Host "  Recovery must come from OneDrive cloud (recycle bin, Restore Your OneDrive, or admin SPO restore)" -ForegroundColor Yellow
    }

    exit 0
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level "ERROR"
    Write-Host "Script failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
