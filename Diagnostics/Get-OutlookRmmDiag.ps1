<#
.SYNOPSIS
    RMM/SYSTEM-context diagnostic for Outlook freezing, send failures, and crash events.

.DESCRIPTION
    Complements Get-OutlookLocalDiagnostic.ps1 (user-context) with SYSTEM-context
    checks that require SID resolution to reach user hive and profile data:
      - KB5074109 (Jan 2026 Outlook/OneDrive crash) and KB5078127 (fix) patch status
      - Office C2R version, channel, and platform
      - MSI vs C2R install type detection
      - Outlook.exe process state and memory
      - OST file size from user profile (SID-resolved path)
      - PST files in OneDrive paths (KB5074109 trigger)
      - COM add-ins from HKLM and HKU (SID-resolved) with LoadBehavior decode
      - Outlook Resiliency disabled-items (crashed add-ins)
      - Outlook profiles via HKU
      - Application event log: Outlook crashes (1000/1002) and Office 16 Alerts

    Runs SYSTEM via the RMM.

.PARAMETER TargetUser
    SamAccountName of the affected user. Used to resolve SID and profile path.
    If empty, auto-detects from Win32_ComputerSystem.UserName.

.PARAMETER Domain
    NetBIOS or FQDN domain name for SID resolution. Leave empty for local accounts.

.NOTES
    Category: Diagnostics
    Context: Commands | RMM (SYSTEM, PS 5.1)

.KEYWORDS
    Outlook, freeze, crash, KB5074109, KB5078127, PST, OneDrive, OST, C2R, add-in,
    resiliency, RMM, SYSTEM, SID
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$TargetUser = '',
    [string]$Domain     = ''
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-OutlookRmmDiag"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# --- Resolve active user and SID ---
if (-not $TargetUser) {
    $cs = Get-CimInstance Win32_ComputerSystem
    $TargetUser = if ($cs.UserName -match '\\') { ($cs.UserName -split '\\')[1] } else { $cs.UserName }
    if (-not $Domain) { $Domain = ($cs.UserName -split '\\')[0] }
}
W ("TargetUser: {0}  Domain: {1}" -f $TargetUser, $Domain)

$sid         = $null
$userProfile = $null

if ($TargetUser) {
    try {
        $ntAcct = if ($Domain) {
            New-Object System.Security.Principal.NTAccount($Domain, $TargetUser)
        } else {
            New-Object System.Security.Principal.NTAccount($TargetUser)
        }
        $sid = $ntAcct.Translate([System.Security.Principal.SecurityIdentifier]).Value
        W ("SID: {0}" -f $sid)
        $plKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        if (Test-Path $plKey) {
            $userProfile = (Get-ItemProperty $plKey).ProfileImagePath
            W ("Profile: {0}" -f $userProfile)
        }
    } catch {
        W ("SID resolution failed: {0}. Profile checks will be limited." -f $_.Exception.Message)
    }
}

# Mount HKU drive
if ($sid -and -not (Test-Path 'HKU:\')) {
    New-PSDrive -PSProvider Registry -Root HKEY_USERS -Name HKU | Out-Null
}

# --- 1. KB patch status ---
Sec "KB PATCH STATUS"
$badKB = Get-HotFix -Id 'KB5074109'
$fixKB = Get-HotFix -Id 'KB5078127'
if ($badKB) {
    W ("KB5074109 : PRESENT (installed {0}) - Jan 2026 patch that breaks Outlook with PST in OneDrive" -f $badKB.InstalledOn.ToString('yyyy-MM-dd'))
} else { W "KB5074109 : Not installed (OK)" }
if ($fixKB) {
    W ("KB5078127 : PRESENT (installed {0}) - fix KB in place" -f $fixKB.InstalledOn.ToString('yyyy-MM-dd'))
} else {
    W "KB5078127 : Not installed"
    if ($badKB) { W "ACTION NEEDED: KB5074109 present without fix KB5078127." }
}

# --- 2. Office / Outlook version ---
Sec "OFFICE / OUTLOOK VERSION"
$c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
if (Test-Path $c2rKey) {
    $c2r = Get-ItemProperty $c2rKey
    W ("Install type : Click-to-Run (C2R)")
    W ("Version      : {0}" -f $c2r.VersionToReport)
    W ("Platform     : {0}" -f $c2r.Platform)
    W ("Channel      : {0}" -f ($c2r.CDNBaseUrl -replace '.*/', ''))
} else {
    W "No C2R key found."
    # Check MSI
    $msiKey = 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook'
    if (Test-Path $msiKey) { W "MSI Outlook 16.0 key present." }
}

# --- 3. Outlook process ---
Sec "OUTLOOK PROCESS"
$olProc = Get-Process OUTLOOK
if ($olProc) {
    W ("Outlook.exe PID {0}   {1} MB RAM   Start {2}" -f $olProc.Id, [math]::Round($olProc.WorkingSet64/1MB,1), $olProc.StartTime)
} else { W "Outlook.exe not running." }
$newOL = Get-Process 'olk'
if ($newOL) { W ("New Outlook (olk) PID {0} also running" -f $newOL.Id) }

# --- 4. OST file size ---
Sec "OST FILE SIZE"
if ($userProfile) {
    $ostDir = "$userProfile\AppData\Local\Microsoft\Outlook"
    if (Test-Path $ostDir) {
        $osts = Get-ChildItem $ostDir -Filter '*.ost'
        if ($osts) {
            foreach ($f in $osts) {
                $gb = [math]::Round($f.Length/1GB,2)
                W ("{0} : {1} GB{2}" -f $f.Name, $gb, $(if ($gb -gt 10) { '  << LARGE' } else { '' }))
            }
        } else { W "No .ost files in $ostDir" }
    } else { W "Outlook data folder not found: $ostDir" }
} else { W "Skipped: user profile not resolved." }

# --- 5. PST in OneDrive paths ---
Sec "PST FILES IN ONEDRIVE (KB5074109 trigger)"
if ($userProfile) {
    $odRoots = @(
        "$userProfile\OneDrive",
        "$userProfile\OneDrive - *"
    )
    $pstFound = $false
    foreach ($pattern in $odRoots) {
        $dirs = Resolve-Path $pattern -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            $psts = Get-ChildItem $dir.Path -Recurse -Filter '*.pst'
            foreach ($p in $psts) {
                W ("PST IN ONEDRIVE: {0}  ({1} MB)  << KB5074109 trigger" -f $p.FullName, [math]::Round($p.Length/1MB,1))
                $pstFound = $true
            }
        }
    }
    if (-not $pstFound) { W "No PST files found in OneDrive paths (OK)." }
} else { W "Skipped: user profile not resolved." }

# --- 6. COM add-ins ---
Sec "COM ADD-INS"
$addInPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins'
)
if ($sid) { $addInPaths += "HKU:\$sid\Software\Microsoft\Office\Outlook\Addins" }

foreach ($path in $addInPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath
            $lb = switch ($props.LoadBehavior) {
                0  { 'Disabled' }
                2  { 'Load at startup (inactive)' }
                3  { 'Enabled (load at startup)' }
                8  { 'Load on demand' }
                16 { 'Connect first time' }
                default { "Unknown ($($props.LoadBehavior))" }
            }
            W ("  {0,-40} Load: {1}  Name: {2}" -f $_.PSChildName, $lb, $props.FriendlyName)
        }
    }
}

# Resiliency disabled items
if ($sid -and (Test-Path "HKU:\$sid\Software\Microsoft\Office\16.0\Outlook\Resiliency\DisabledItems")) {
    W "--- Crashed/Disabled by Outlook Resiliency ---"
    $dis = Get-ItemProperty "HKU:\$sid\Software\Microsoft\Office\16.0\Outlook\Resiliency\DisabledItems"
    $dis.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { W ("  Disabled: {0}" -f $_.Name) }
}

# --- 7. Outlook profiles ---
Sec "OUTLOOK PROFILES"
if ($sid -and (Test-Path "HKU:\$sid\Software\Microsoft\Office\16.0\Outlook\Profiles")) {
    $profiles = Get-ChildItem "HKU:\$sid\Software\Microsoft\Office\16.0\Outlook\Profiles"
    W ("Profile count: {0}" -f $profiles.Count)
    foreach ($p in $profiles) { W ("  - {0}" -f $p.PSChildName) }
    $default = (Get-ItemProperty "HKU:\$sid\Software\Microsoft\Office\16.0\Outlook").DefaultProfile
    if ($default) { W ("Default: {0}" -f $default) }
} else { W "Skipped: SID not resolved or Profiles key absent." }

# --- 8. Event log ---
Sec "EVENT LOG - OUTLOOK CRASHES/HANGS (last 7 days)"
$crashEvts = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    Id        = @(1000, 1002)
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 50 | Where-Object { $_.Message -match 'outlook\.exe' }

if ($crashEvts) {
    W ("Outlook crash/hang events: {0} in last 7 days" -f $crashEvts.Count)
    $crashEvts | Select-Object -First 5 | ForEach-Object {
        W ("  {0}  ID {1}  {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.Id, ($_.Message -split "`r`n|`n")[0])
    }
} else { W "No Outlook crash/hang events in last 7 days." }

$alerts = Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'Microsoft Office 16 Alerts'
    StartTime    = (Get-Date).AddDays(-7)
} -MaxEvents 10
if ($alerts) {
    W ("Office 16 Alert events: {0}" -f $alerts.Count)
    $alerts | Select-Object -First 5 | ForEach-Object {
        W ("  {0}  ID {1}  {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.Id, ($_.Message -split "`r`n|`n")[0])
    }
} else { W "No Office 16 Alert events." }

W ""
W "===== END Get-OutlookRmmDiag ====="
W "For user-context profile/credential/activation checks, run Get-OutlookLocalDiagnostic.ps1 in user session."
