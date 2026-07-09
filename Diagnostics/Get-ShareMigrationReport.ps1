# Get-ShareMigrationReport.ps1
# Purpose: Pre-migration file share assessment for SharePoint/OneDrive migrations
# Collects folder sizes, last accessed/modified dates, ownership, and files over 1 GB
# Run directly on the file server via SYSTEM remote session for best performance
#
# Usage:
#   Set $localPaths below to the share names and their local paths (use Get-SmbShare to discover)
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

param(
    [string]$OutputDir = 'C:\Temp',
    [long]$LargeFileSizeBytes = 1GB
)

# --- Configure share paths here ---
$localPaths = @{
    'ShareName1' = 'D:\ShareName1'
    'ShareName2' = 'D:\ShareName2'
}
# ----------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportPath     = Join-Path $OutputDir "ShareAnalysis_$timestamp.csv"
$largeFilesPath = Join-Path $OutputDir "LargeFiles_$timestamp.csv"
$summaryPath    = Join-Path $OutputDir "SUMMARY_$timestamp.txt"

New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction SilentlyContinue | Out-Null

$folderResults    = @()
$largeFileResults = @()

foreach ($shareName in $localPaths.Keys) {
    $rootPath = $localPaths[$shareName]

    Write-Host "=== Analyzing: $shareName ($rootPath) ===" -ForegroundColor Cyan

    # Use Get-Item to get a DirectoryInfo object for the root (avoids type-mismatch when mixing with Get-ChildItem output)
    $rootItem = Get-Item -LiteralPath $rootPath -ErrorAction SilentlyContinue
    if (-not $rootItem) {
        Write-Warning "Cannot access $rootPath — skipping"
        continue
    }

    $subDirs = Get-ChildItem -LiteralPath $rootPath -Recurse -Directory -ErrorAction SilentlyContinue
    $folders = @($rootItem) + $subDirs

    $counter = 0
    foreach ($folder in $folders) {
        $counter++
        if ($counter % 100 -eq 0) { Write-Host "  Processed $counter folders..." -ForegroundColor Gray }

        $folderPath = $folder.FullName

        try {
            $filesInFolder = Get-ChildItem -LiteralPath $folderPath -File -ErrorAction SilentlyContinue
            $folderSizeBytes = ($filesInFolder | Measure-Object -Property Length -Sum).Sum

            $acl   = Get-Acl -LiteralPath $folderPath -ErrorAction SilentlyContinue
            $owner = if ($acl) { $acl.Owner } else { 'N/A' }

            $largeFiles = $filesInFolder | Where-Object { $_.Length -gt $LargeFileSizeBytes }
            foreach ($lf in $largeFiles) {
                $largeFileResults += [PSCustomObject]@{
                    Share        = $shareName
                    FilePath     = $lf.FullName.Replace($rootPath, '')
                    FileName     = $lf.Name
                    SizeGB       = [math]::Round($lf.Length / 1GB, 2)
                    LastModified = $lf.LastWriteTime
                    LastAccessed = $lf.LastAccessTime
                }
            }

            $totalSizeBytes = (Get-ChildItem -LiteralPath $folderPath -Recurse -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum

            $folderResults += [PSCustomObject]@{
                Share             = $shareName
                FolderPath        = $folderPath.Replace($rootPath, '')
                FolderSizeMB      = [math]::Round($folderSizeBytes / 1MB, 2)
                TotalWithSubsGB   = [math]::Round($totalSizeBytes / 1GB, 2)
                FileCount         = $filesInFolder.Count
                LastModified      = $folder.LastWriteTime
                LastAccessed      = $folder.LastAccessTime
                Owner             = $owner
                LargeFilesInFolder = $largeFiles.Count
            }
        }
        catch {
            Write-Warning "Error processing $($folderPath): $($_)"
        }
    }

    Write-Host "  Completed $shareName — $counter folders processed" -ForegroundColor Green
}

$folderResults    | Export-Csv -Path $reportPath     -NoTypeInformation
$largeFileResults | Export-Csv -Path $largeFilesPath -NoTypeInformation

$summaryStats = $folderResults | Where-Object { $_.FolderPath -eq '' } |
    Select-Object Share, TotalWithSubsGB, FileCount, LargeFilesInFolder

$summaryText = @"
SharePoint Migration Assessment
Generated: $(Get-Date)
Server: $($env:COMPUTERNAME)

=== SHARE SUMMARY ===
$($summaryStats | Format-Table -AutoSize | Out-String)
=== REPORTS GENERATED ===
Folder Analysis : $reportPath
Large Files     : $largeFilesPath
"@

$summaryText | Out-File -FilePath $summaryPath -Encoding ascii

Write-Host ''
Write-Host 'Reports saved to:' -ForegroundColor Green
Write-Host "  Summary      : $summaryPath"
Write-Host "  Folder detail: $reportPath"
Write-Host "  Large files  : $largeFilesPath"

$summaryStats | Format-Table -AutoSize
