<#
.SYNOPSIS
    Verify Office Click-to-Run version, SHA256, and Authenticode signature on a specific
    binary, and check SentinelOne agent state and recent process-create events (4688).

.DESCRIPTION
    Used for SentinelOne false-positive triage when S1 quarantines an Office C2R update
    binary. Checks:
      - Office C2R version from registry
      - File metadata, SHA256, and Authenticode signature at the quarantined path
      - SHA256 and Authenticode on the live ClickToRun service binary
      - ClickToRun service state
      - SentinelOne agent service + SentinelCtl status/version
      - Security log 4688 events (process-create) for OfficeClickToRun in last N hours
      - Application log Office/ClickToRun events in last 24 hours

.PARAMETER QuarantinedPath
    Full path to the specific binary S1 flagged. Defaults to an empty string (skip file check).

.PARAMETER ExpectedSha256
    Expected SHA256 hash of the quarantined binary. If provided, the script compares
    and reports match/mismatch. Leave empty to skip hash comparison.

.PARAMETER EventHours
    How many hours back to search Security 4688 events. Default 6.

.NOTES
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1)

.KEYWORDS
    Office, ClickToRun, C2R, SentinelOne, S1, false positive, SHA256, Authenticode,
    quarantine, 4688, process-create
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$QuarantinedPath = '',
    [string]$ExpectedSha256  = '',
    [int]   $EventHours      = 6
)

$ErrorActionPreference = 'Continue'
$Since6h  = (Get-Date).AddHours(-$EventHours)
$Since24h = (Get-Date).AddHours(-24)

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Confirm-OfficeClickToRun"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# --- Host ---
Sec "HOST"
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
W ("Computer   : {0}" -f $env:COMPUTERNAME)
W ("Last logon : {0}" -f $cs.UserName)

# --- Office C2R version ---
Sec "OFFICE CLICK-TO-RUN VERSION"
$c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
if (Test-Path $c2rKey) {
    Get-ItemProperty $c2rKey |
        Select-Object VersionToReport, ClientVersionToReport, UpdateChannel, CDNBaseUrl, ProductReleaseIds |
        Format-List | Out-String | W
} else { W "No Click-to-Run Configuration key found." }

# --- Quarantined binary ---
if ($QuarantinedPath) {
    Sec "FILE AT QUARANTINED PATH: $QuarantinedPath"
    if (Test-Path -LiteralPath $QuarantinedPath) {
        $f   = Get-Item -LiteralPath $QuarantinedPath
        $h   = Get-FileHash -LiteralPath $QuarantinedPath -Algorithm SHA256
        $sig = Get-AuthenticodeSignature -LiteralPath $QuarantinedPath
        W ("Path        : {0}" -f $f.FullName)
        W ("Size        : {0} bytes" -f $f.Length)
        W ("Modified    : {0}" -f $f.LastWriteTime)
        W ("Version     : {0}" -f $f.VersionInfo.FileVersion)
        W ("ProductName : {0}" -f $f.VersionInfo.ProductName)
        W ("CompanyName : {0}" -f $f.VersionInfo.CompanyName)
        W ("SHA256      : {0}" -f $h.Hash)
        if ($ExpectedSha256) { W ("Match exp?  : {0}" -f ($h.Hash -ieq $ExpectedSha256)) }
        W ("SigStatus   : {0}" -f $sig.Status)
        W ("Signer      : {0}" -f $sig.SignerCertificate.Subject)
    } else {
        W "Path missing (expected if S1 quarantined and removed from disk): $QuarantinedPath"
    }
}

# --- Live ClickToRun binary ---
Sec "LIVE CLICK-TO-RUN SERVICE BINARY"
$liveCore = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe'
if (Test-Path -LiteralPath $liveCore) {
    $f   = Get-Item -LiteralPath $liveCore
    $sig = Get-AuthenticodeSignature -LiteralPath $liveCore
    W ("Path      : {0}" -f $f.FullName)
    W ("Version   : {0}" -f $f.VersionInfo.FileVersion)
    W ("Company   : {0}" -f $f.VersionInfo.CompanyName)
    W ("SigStatus : {0}" -f $sig.Status)
    W ("Signer    : {0}" -f $sig.SignerCertificate.Subject)
} else { W "Live binary missing: $liveCore" }

# --- ClickToRun service ---
Sec "CLICK-TO-RUN SERVICE"
Get-Service ClickToRunSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-List | Out-String | W

# --- SentinelOne ---
Sec "SENTINELONE AGENT"
$s1svc = Get-Service SentinelAgent -ErrorAction SilentlyContinue
if ($s1svc) {
    W ("Service : {0} | {1} | StartType {2}" -f $s1svc.Name, $s1svc.Status, $s1svc.StartType)
} else { W "SentinelAgent service not found." }

$s1Dir = Get-ChildItem 'C:\Program Files\SentinelOne\Sentinel Agent*' -Directory |
         Sort-Object Name -Descending | Select-Object -First 1
if ($s1Dir) {
    W ("Install : {0}" -f $s1Dir.FullName)
    $ctl = Join-Path $s1Dir.FullName 'SentinelCtl.exe'
    if (Test-Path $ctl) {
        W "--- SentinelCtl status ---"
        & $ctl status  2>&1 | ForEach-Object { W $_ }
        W "--- SentinelCtl version ---"
        & $ctl version 2>&1 | ForEach-Object { W $_ }
    }
}

# --- 4688 process-create events ---
Sec ("SECURITY 4688 PROCESS-CREATE EVENTS - last {0}h" -f $EventHours)
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$Since6h } -ErrorAction Stop |
            Where-Object { $_.Message -match 'OfficeClickToRun|services\.exe' } |
            Select-Object -First 20 TimeCreated, @{n='Msg';e={ ($_.Message -split "`n")[0..6] -join ' | ' }}
    if ($evts) { $evts | Format-List | Out-String | W }
    else { W "No matching 4688 events (may need audit process-creation policy enabled)." }
} catch {
    W ("4688 query failed: {0}" -f $_.Exception.Message)
}

# --- Application log Office events ---
Sec "APPLICATION LOG - OFFICE/CLICKTORUN EVENTS (last 24h)"
Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since24h } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Office|ClickToRun' } |
    Select-Object -First 15 TimeCreated, Id, ProviderName, LevelDisplayName |
    Format-Table -AutoSize | Out-String | W

W ""
W "===== END Confirm-OfficeClickToRun ====="
