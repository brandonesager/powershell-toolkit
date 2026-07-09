#Requires -Version 5.1
<#
.SYNOPSIS
    Lists Axcient x360Recover FTPS directory structure for backup restore points.
.DESCRIPTION
    Connects to an Axcient FTPS server and lists:
    1. Root-level restore point folders
    2. Drive letter structure of the first restore point
    3. Contents of a target path across all restore points

    Read-only; does not download or modify any files.
.PARAMETER FtpHost
    FTPS server hostname (e.g., backup-appliance.example.com)
.PARAMETER FtpPort
    FTPS server port (e.g., 11000)
.PARAMETER FtpUser
    FTPS username from Axcient Recovery Wizard
.PARAMETER FtpPass
    FTPS password from Axcient Recovery Wizard
.PARAMETER TargetPath
    Path within each restore point to inspect (e.g., "E/Quickbooks/2018").
    Uses forward slashes. Omit the leading slash.
.PARAMETER FileFilter
    Wildcard filter for files in the target path (e.g., "*.qbw"). Default: "*"
.NOTES
    Category: Backup-Recovery
    Execution: RMM shell (#!ps #timeout=60000 #maxlength=100000)
.KEYWORDS
    Axcient, FTPS, backup, discovery, restore
#>
param(
    [Parameter(Mandatory)][string]$FtpHost,
    [Parameter(Mandatory)][int]$FtpPort,
    [Parameter(Mandatory)][string]$FtpUser,
    [Parameter(Mandatory)][string]$FtpPass,
    [string]$TargetPath = '',
    [string]$FileFilter = '*'
)

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$baseUri = "ftp://${FtpHost}:${FtpPort}"
$cred = New-Object System.Net.NetworkCredential($FtpUser, $FtpPass)

function Get-FtpList([string]$Uri) {
    $req = [System.Net.FtpWebRequest]::Create($Uri)
    $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
    $req.Credentials = $cred
    $req.EnableSsl = $true
    $req.UseBinary = $true
    $req.UsePassive = $true
    $req.KeepAlive = $false
    $req.Timeout = 15000
    $resp = $req.GetResponse()
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $list = $reader.ReadToEnd()
    $reader.Close()
    $resp.Close()
    $lines = $list.Split([char[]]@(13,10), [System.StringSplitOptions]::RemoveEmptyEntries)
    return ($lines | Where-Object { $_ -ne '.' -and $_ -ne '..' })
}

Write-Output "=== ROOT ==="
$roots = Get-FtpList $baseUri
$roots | ForEach-Object { Write-Output "  $_" }

Write-Output ""
Write-Output "=== FIRST RESTORE POINT DRIVE LETTERS ==="
$first = $roots | Select-Object -First 1
$drives = Get-FtpList "$baseUri/$first"
$drives | ForEach-Object { Write-Output "  $first/$_" }

if ($TargetPath) {
    Write-Output ""
    Write-Output "=== TARGET PATH ($TargetPath) ==="
    foreach ($rp in $roots) {
        try {
            $files = Get-FtpList "$baseUri/$rp/$TargetPath"
            $matched = $files | Where-Object { $_ -like $FileFilter }
            Write-Output "  $rp : $($matched.Count) matches"
            $matched | ForEach-Object { Write-Output "    $_" }
        } catch {
            Write-Output "  $rp : ERROR - $($_.Exception.Message)"
        }
    }
}

Write-Output ""
Write-Output "=== Discovery complete ==="
