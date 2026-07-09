#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads files from Axcient x360Recover FTPS restore points with hybrid concurrency.
.DESCRIPTION
    Downloads specified files from multiple Axcient FTPS restore points. Starts with
    2 concurrent downloads, scales to 3 if successful, falls back to sequential on failure.
    Logs progress to a log file for monitoring from RMM shell.

    Does NOT modify any existing files on the target system.
.PARAMETER FtpHost
    FTPS server hostname
.PARAMETER FtpPort
    FTPS server port
.PARAMETER FtpUser
    FTPS username from Axcient Recovery Wizard
.PARAMETER FtpPass
    FTPS password from Axcient Recovery Wizard
.PARAMETER RestorePoints
    Array of hashtables with Suffix and FtpPath keys. Example:
    @(@{Suffix='0317';FtpPath='2026_03_17_21_00_00/E/Data'})
.PARAMETER FileNames
    Array of filenames to download from each restore point
.PARAMETER DestDir
    Local directory to save downloaded files
.PARAMETER BaseName
    Base filename for renaming (suffix inserted before extension)
.NOTES
    Category: Backup-Recovery
    Execution: Background process (write to disk, launch with Start-Process)
    See commands-tab.md Long-Running Scripts section for execution pattern.
.KEYWORDS
    Axcient, FTPS, backup, download, restore
#>
param(
    [Parameter(Mandatory)][string]$FtpHost,
    [Parameter(Mandatory)][int]$FtpPort,
    [Parameter(Mandatory)][string]$FtpUser,
    [Parameter(Mandatory)][string]$FtpPass,
    [Parameter(Mandatory)][hashtable[]]$RestorePoints,
    [Parameter(Mandatory)][string[]]$FileNames,
    [Parameter(Mandatory)][string]$DestDir,
    [string]$BaseName = ''
)

$baseUri = "ftp://${FtpHost}:${FtpPort}"
$logFile = Join-Path $DestDir 'download-log.txt'

if (-not (Test-Path $DestDir)) {
    New-Item -Path $DestDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Add-Content -Path $logFile -Value $entry -Encoding UTF8
    Write-Output $entry
}

$downloadBlock = {
    param(
        [string]$BaseUri, [string]$FtpUser, [string]$FtpPass,
        [string]$FtpPath, [string[]]$FileNames, [string]$BaseName,
        [string]$Suffix, [string]$DestDir, [string]$LogFile
    )

    function Write-JobLog {
        param([string]$Message)
        $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Suffix] $Message"
        $mutex = New-Object System.Threading.Mutex($false, 'AxcientDownloadLog')
        $mutex.WaitOne() | Out-Null
        try { Add-Content -Path $LogFile -Value $entry -Encoding UTF8 }
        finally { $mutex.ReleaseMutex() }
    }

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $results = @()

    foreach ($fileName in $FileNames) {
        $fileUri = "$BaseUri/$FtpPath/$fileName"
        if ($BaseName) {
            $ext = [System.IO.Path]::GetExtension($fileName)
            $nameNoExt = $fileName.Substring(0, $fileName.Length - $ext.Length)
            $localName = "${nameNoExt}_${Suffix}${ext}"
        } else {
            $localName = "${Suffix}_${fileName}"
        }
        $localPath = Join-Path $DestDir $localName

        Write-JobLog "Downloading $fileName ..."
        try {
            $request = [System.Net.FtpWebRequest]::Create($fileUri)
            $request.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
            $request.Credentials = New-Object System.Net.NetworkCredential($FtpUser, $FtpPass)
            $request.EnableSsl = $true
            $request.UseBinary = $true
            $request.UsePassive = $true
            $request.KeepAlive = $false
            $request.Timeout = 600000

            $response = $request.GetResponse()
            $responseStream = $response.GetResponseStream()
            $fileStream = [System.IO.File]::Create($localPath)
            $buffer = New-Object byte[] 65536
            $totalBytes = 0
            $lastLog = [DateTime]::MinValue

            while (($read = $responseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $read)
                $totalBytes += $read
                if (([DateTime]::Now - $lastLog).TotalSeconds -ge 30) {
                    $mb = [math]::Round($totalBytes / 1MB, 1)
                    Write-JobLog "$fileName : ${mb} MB downloaded"
                    $lastLog = [DateTime]::Now
                }
            }

            $fileStream.Close()
            $responseStream.Close()
            $response.Close()

            $finalMB = [math]::Round($totalBytes / 1MB, 1)
            Write-JobLog "$fileName : COMPLETE (${finalMB} MB)"
            $results += @{ File = $localName; Status = 'OK'; SizeMB = $finalMB }
        }
        catch {
            Write-JobLog "$fileName : FAILED - $($_.Exception.Message)"
            $results += @{ File = $localName; Status = 'FAILED'; Error = $_.Exception.Message }
            if (Test-Path $localPath) { Remove-Item $localPath -Force }
        }
    }
    return $results
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Write-Log "=== Axcient FTPS Backup Download ==="
Write-Log "Restore points: $($RestorePoints.Count)"
Write-Log "Destination: $DestDir"
Write-Log "Concurrency: hybrid (start 2, scale to 3 if successful)"

$allResults = @()
$queue = [System.Collections.ArrayList]@($RestorePoints)
$concurrency = 2
$failedAny = $false

while ($queue.Count -gt 0) {
    $batch = @()
    $take = [math]::Min($concurrency, $queue.Count)
    for ($i = 0; $i -lt $take; $i++) {
        $batch += $queue[0]
        $queue.RemoveAt(0)
    }

    Write-Log "Starting batch of $($batch.Count) downloads (concurrency: $concurrency)"

    if ($batch.Count -eq 1) {
        $rp = $batch[0]
        Write-Log "[$($rp.Suffix)] Starting sequential download"
        $result = & $downloadBlock -BaseUri $baseUri -FtpUser $FtpUser -FtpPass $FtpPass `
            -FtpPath $rp.FtpPath -FileNames $FileNames -BaseName $BaseName `
            -Suffix $rp.Suffix -DestDir $DestDir -LogFile $logFile
        $allResults += $result
        $batchFailed = ($result | Where-Object { $_.Status -eq 'FAILED' }).Count -gt 0
    }
    else {
        $jobs = @()
        foreach ($rp in $batch) {
            Write-Log "[$($rp.Suffix)] Starting job"
            $job = Start-Job -ScriptBlock $downloadBlock -ArgumentList @(
                $baseUri, $FtpUser, $FtpPass, $rp.FtpPath,
                $FileNames, $BaseName, $rp.Suffix, $DestDir, $logFile
            )
            $jobs += $job
        }

        $jobs | Wait-Job -Timeout 1200 | Out-Null

        $batchFailed = $false
        foreach ($job in $jobs) {
            if ($job.State -eq 'Completed') {
                $result = Receive-Job -Job $job
                $allResults += $result
                if (($result | Where-Object { $_.Status -eq 'FAILED' }).Count -gt 0) {
                    $batchFailed = $true
                }
            }
            else {
                Write-Log "Job $($job.Id) did not complete (state: $($job.State)). Stopping."
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                $batchFailed = $true
            }
            Remove-Job -Job $job -Force
        }
    }

    if ($batchFailed) {
        $failedAny = $true
        if ($concurrency -gt 1) {
            Write-Log "Batch had failures. Falling back to sequential (concurrency: 1)"
            $concurrency = 1
        }
    }
    elseif (-not $failedAny -and $concurrency -lt 3) {
        $concurrency = 3
        Write-Log "Batch succeeded. Scaling to concurrency: $concurrency"
    }
}

Write-Log ""
Write-Log "=== Download Summary ==="
$okCount = ($allResults | Where-Object { $_.Status -eq 'OK' }).Count
$failCount = ($allResults | Where-Object { $_.Status -eq 'FAILED' }).Count
Write-Log "Completed: $okCount | Failed: $failCount"

foreach ($r in $allResults) {
    if ($r.Status -eq 'OK') {
        Write-Log "  OK   : $($r.File) ($($r.SizeMB) MB)"
    }
    else {
        Write-Log "  FAIL : $($r.File) - $($r.Error)"
    }
}

Write-Log ""
Write-Log "Files in ${DestDir}:"
Get-ChildItem $DestDir -File | ForEach-Object {
    $mb = [math]::Round($_.Length / 1MB, 1)
    Write-Log "  $($_.Name) ($mb MB)"
}

Write-Log ""
Write-Log "=== Download complete ==="

return
