<#
.SYNOPSIS
    Local workstation diagnostic for Outlook send failures.
.DESCRIPTION
    Checks Outlook profile, OST size, cached credentials, network
    connectivity to Exchange Online, Office activation, and DNS.
    Run on the client machine via remote session.
.EXAMPLE
    .\Get-OutlookLocalDiagnostic.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n=== Local Outlook Diagnostic ===" -ForegroundColor Cyan
Write-Host "Machine: $env:COMPUTERNAME | User: $env:USERNAME`n"

# --- 1. Outlook process ---
Write-Host "--- 1. Outlook Process ---" -ForegroundColor Green
$outlook = Get-Process OUTLOOK -ErrorAction SilentlyContinue
if ($outlook) {
    Write-Host "Outlook PID      : $($outlook.Id)"
    Write-Host "Memory (MB)      : $([math]::Round($outlook.WorkingSet64 / 1MB, 1))"
    Write-Host "Start Time       : $($outlook.StartTime)"
    $newOutlook = Get-Process 'olk' -ErrorAction SilentlyContinue
    if ($newOutlook) { Write-Host "New Outlook (olk) : ALSO RUNNING — may conflict" -ForegroundColor Yellow }
} else {
    Write-Host "Outlook is NOT running" -ForegroundColor Yellow
    $newOutlook = Get-Process 'olk' -ErrorAction SilentlyContinue
    if ($newOutlook) { Write-Host "New Outlook (olk) : Running (PID $($newOutlook.Id))" }
}

# --- 2. Outlook profiles ---
Write-Host "`n--- 2. Outlook Profiles ---" -ForegroundColor Green
$profileRoot = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles"
if (Test-Path $profileRoot) {
    $profiles = Get-ChildItem $profileRoot | Select-Object -ExpandProperty PSChildName
    Write-Host "Profiles found   : $($profiles -join ', ')"
    $default = (Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Outlook" -Name DefaultProfile -ErrorAction SilentlyContinue).DefaultProfile
    if ($default) { Write-Host "Default profile  : $default" }
} else {
    Write-Host "No Outlook profiles found in registry" -ForegroundColor Yellow
}

# --- 3. OST files ---
Write-Host "`n--- 3. OST/Data Files ---" -ForegroundColor Green
$ostPath = "$env:LOCALAPPDATA\Microsoft\Outlook"
if (Test-Path $ostPath) {
    $ostFiles = Get-ChildItem $ostPath -Filter *.ost -ErrorAction SilentlyContinue
    $nstFiles = Get-ChildItem $ostPath -Filter *.nst -ErrorAction SilentlyContinue
    $allFiles = @($ostFiles) + @($nstFiles) | Where-Object { $_ }
    if ($allFiles) {
        foreach ($f in $allFiles) {
            $sizeMB = [math]::Round($f.Length / 1MB, 1)
            $sizeGB = [math]::Round($f.Length / 1GB, 2)
            $warn = if ($sizeGB -gt 10) { " <-- LARGE" } else { "" }
            Write-Host "$($f.Name) : $sizeMB MB ($sizeGB GB)$warn" -ForegroundColor $(if ($sizeGB -gt 10) { 'Yellow' } else { 'White' })
        }
    } else {
        Write-Host "No OST/NST files found" -ForegroundColor Yellow
    }
} else {
    Write-Host "Outlook data folder not found" -ForegroundColor Yellow
}

# --- 4. Cached credentials ---
Write-Host "`n--- 4. Cached Credentials (Outlook/Office) ---" -ForegroundColor Green
$creds = cmdkey /list 2>&1 | Select-String -Pattern 'MicrosoftOffice|outlook|office|adal|microsoftonline'
if ($creds) {
    $creds | ForEach-Object { Write-Host $_.Line.Trim() }
} else {
    Write-Host "No Office/Outlook cached credentials found"
}

# --- 5. Windows email accounts ---
Write-Host "`n--- 5. Windows Email Accounts ---" -ForegroundColor Green
$emailAccts = Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\*\9375CFF0413111d3B88A00104B2A6676\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.'Account Name' -or $_.'Email' }
if ($emailAccts) {
    $emailAccts | ForEach-Object {
        $name = $_.'Account Name'
        $email = $_.'Email'
        if ($name -or $email) { Write-Host "$name — $email" }
    }
} else {
    Write-Host "Could not enumerate email accounts from registry"
}

# --- 6. Network connectivity to Exchange Online ---
Write-Host "`n--- 6. Exchange Online Connectivity ---" -ForegroundColor Green
$endpoints = @(
    @{ Name = "Outlook (HTTPS)";     Host = "outlook.office365.com";     Port = 443 }
    @{ Name = "Autodiscover";        Host = "autodiscover-s.outlook.com"; Port = 443 }
    @{ Name = "EWS";                 Host = "outlook.office365.com";     Port = 443 }
)
foreach ($ep in $endpoints) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($ep.Host, $ep.Port)
        $status = "OK"
        $color = "White"
    } catch {
        $status = "FAILED"
        $color = "Red"
    } finally {
        $tcp.Dispose()
    }
    Write-Host ("{0,-22} {1}:{2} — {3}" -f $ep.Name, $ep.Host, $ep.Port, $status) -ForegroundColor $color
}

# --- 7. DNS resolution ---
Write-Host "`n--- 7. DNS Resolution ---" -ForegroundColor Green
$dnsTargets = @('outlook.office365.com', 'autodiscover-s.outlook.com', 'login.microsoftonline.com')
foreach ($target in $dnsTargets) {
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($target) | Select-Object -First 1
        Write-Host "$target → $($resolved.IPAddressToString)"
    } catch {
        Write-Host "$target → FAILED TO RESOLVE" -ForegroundColor Red
    }
}

# --- 8. Office activation ---
Write-Host "`n--- 8. Office Activation ---" -ForegroundColor Green
$clickToRun = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
if (Test-Path $clickToRun) {
    $cfg = Get-ItemProperty $clickToRun
    Write-Host "Channel          : $($cfg.CDNBaseUrl -replace '.*/', '')"
    Write-Host "Version          : $($cfg.VersionToReport)"
    Write-Host "Platform         : $($cfg.Platform)"
}
# Check license status via OSPP if available
$ospp = "${env:ProgramFiles}\Microsoft Office\Office16\ospp.vbs"
$osppX86 = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs"
$c2rOspp = "$env:ProgramFiles\Microsoft Office\root\Office16\ospp.vbs"
$vbsPath = @($c2rOspp, $ospp, $osppX86) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($vbsPath) {
    $licStatus = cscript //nologo $vbsPath /dstatus 2>&1 | Select-String 'LICENSE NAME|LICENSE STATUS|ERROR'
    if ($licStatus) { $licStatus | ForEach-Object { Write-Host $_.Line.Trim() } }
} else {
    Write-Host "Could not locate ospp.vbs for license check" -ForegroundColor Yellow
}

# --- 9. Recent Outlook errors in Event Log ---
Write-Host "`n--- 9. Recent Outlook Events (last 24h) ---" -ForegroundColor Green
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'Microsoft Office 16 Alerts', 'Outlook', 'Microsoft-Windows-User Profiles Service'
    StartTime = (Get-Date).AddDays(-1)
    Level = 1,2,3  # Critical, Error, Warning
} -MaxEvents 10 -ErrorAction SilentlyContinue
if ($events) {
    $events | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
} else {
    Write-Host "No Outlook-related errors/warnings in last 24h"
}

Write-Host "`n=== Diagnostic Complete ===" -ForegroundColor Cyan
