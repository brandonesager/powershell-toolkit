<#
.SYNOPSIS
    Search for Outlook data files (PST, OST) on file server shares

.DESCRIPTION
    Scans specified paths for .pst and .ost files, returning file details
    including size, last modified date, and full path.
    Designed for RMM (PowerShell 5.1, SYSTEM context).

.PARAMETER SearchPath
    Root path to search. Default: All fixed drives.

.PARAMETER MaxDepth
    Maximum folder depth to search. Default: 10 (prevents infinite recursion)

.PARAMETER MinSizeMB
    Minimum file size in MB to report. Default: 1 (filters tiny/empty files)

.EXAMPLE
    .\Find-OutlookDataFiles.ps1
    Searches all fixed drives for PST/OST files

.EXAMPLE
    .\Find-OutlookDataFiles.ps1 -SearchPath "D:\UserShares"
    Searches only D:\UserShares

.NOTES
#>
param(
    [string]$SearchPath = "",
    [int]$MaxDepth = 10,
    [int]$MinSizeMB = 1
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

function Get-OutlookFiles {
    param(
        [string]$Path,
        [int]$Depth
    )

    $files = @()

    try {
        # Get PST and OST files in current directory
        $found = Get-ChildItem -Path $Path -Filter "*.pst" -File -ErrorAction SilentlyContinue
        $found += Get-ChildItem -Path $Path -Filter "*.ost" -File -ErrorAction SilentlyContinue

        foreach ($file in $found) {
            $sizeMB = [math]::Round($file.Length / 1MB, 2)
            if ($sizeMB -ge $MinSizeMB) {
                $files += [PSCustomObject]@{
                    Name         = $file.Name
                    Extension    = $file.Extension.ToUpper()
                    SizeMB       = $sizeMB
                    LastModified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                    FullPath     = $file.FullName
                    ParentFolder = $file.DirectoryName
                }
            }
        }

        # Recurse into subdirectories if depth allows
        if ($Depth -gt 0) {
            $subdirs = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
            foreach ($subdir in $subdirs) {
                # Skip system directories
                $skipDirs = @('$Recycle.Bin', 'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', 'System Volume Information')
                if ($skipDirs -contains $subdir.Name) { continue }

                $subFiles = Get-OutlookFiles -Path $subdir.FullName -Depth ($Depth - 1)
                $files += $subFiles
            }
        }
    }
    catch {
        # Access denied or other error - log and continue
        Write-Log "Cannot access: $Path - $($_.Exception.Message)" -Level "WARN"
    }

    return $files
}

try {
    Write-Log "Starting Outlook data file search"
    Write-Log "Minimum file size: $MinSizeMB MB"

    $searchPaths = @()

    if ([string]::IsNullOrEmpty($SearchPath)) {
        # Search all fixed drives
        $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($drive in $drives) {
            $searchPaths += $drive.DeviceID + "\"
        }
        Write-Log "Searching all fixed drives: $($searchPaths -join ', ')"
    }
    else {
        if (Test-Path $SearchPath) {
            $searchPaths += $SearchPath
            Write-Log "Searching specified path: $SearchPath"
        }
        else {
            Write-Output "ERROR: Path not found: $SearchPath"
            exit 1
        }
    }

    $allFiles = @()

    foreach ($path in $searchPaths) {
        Write-Log "Scanning: $path"
        $found = Get-OutlookFiles -Path $path -Depth $MaxDepth
        $allFiles += $found
    }

    if ($allFiles.Count -eq 0) {
        Write-Output "NO_FILES_FOUND: No PST or OST files found matching criteria"
        Write-Log "Search complete - no files found"
        exit 0
    }

    # Sort by size descending
    $allFiles = $allFiles | Sort-Object SizeMB -Descending

    Write-Log "Found $($allFiles.Count) Outlook data file(s)"
    Write-Host ""
    Write-Host "========== OUTLOOK DATA FILES FOUND =========="
    Write-Host ""

    # Group by extension type
    $pstFiles = $allFiles | Where-Object { $_.Extension -eq '.PST' }
    $ostFiles = $allFiles | Where-Object { $_.Extension -eq '.OST' }

    if ($pstFiles.Count -gt 0) {
        Write-Host "--- PST FILES (Portable/Archive) ---"
        foreach ($file in $pstFiles) {
            Write-Host "  $($file.SizeMB) MB | $($file.LastModified) | $($file.FullPath)"
        }
        Write-Host ""
    }

    if ($ostFiles.Count -gt 0) {
        Write-Host "--- OST FILES (Offline Cache - Cannot Import) ---"
        foreach ($file in $ostFiles) {
            Write-Host "  $($file.SizeMB) MB | $($file.LastModified) | $($file.FullPath)"
        }
        Write-Host ""
    }

    # Summary statistics
    $totalPST = ($pstFiles | Measure-Object -Property SizeMB -Sum).Sum
    $totalOST = ($ostFiles | Measure-Object -Property SizeMB -Sum).Sum

    if ($null -eq $totalPST) { $totalPST = 0 }
    if ($null -eq $totalOST) { $totalOST = 0 }

    Write-Host "========== SUMMARY =========="
    Write-Host "PST files: $($pstFiles.Count) ($([math]::Round($totalPST, 2)) MB total)"
    Write-Host "OST files: $($ostFiles.Count) ($([math]::Round($totalOST, 2)) MB total)"
    Write-Host ""

    # Output JSON for EDF capture
    $summary = @{
        PSTCount    = $pstFiles.Count
        OSTCount    = $ostFiles.Count
        TotalPSTMB  = [math]::Round($totalPST, 2)
        TotalOSTMB  = [math]::Round($totalOST, 2)
        Files       = $allFiles | Select-Object Name, Extension, SizeMB, FullPath
    }

    Write-Output "SUCCESS: Found $($allFiles.Count) Outlook data files"
    Write-Output ($summary | ConvertTo-Json -Compress -Depth 3)

    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Log "Fatal error: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
