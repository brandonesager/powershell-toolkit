#!ps
#maxlength=100000
#timeout=300000

<#
.SYNOPSIS
    Read-only crash diagnostic for UltraTax, Lacerte, ProSystem, and QuickBooks.
.DESCRIPTION
    Gathers application install records, .NET Framework version, Visual C++
    redistributables, recent hotfixes, Application/CLR crash events, WER report
    archives, SentinelOne status, CS Professional Suite registry paths, per-user
    CSI/Thomson Reuters cache state, and stale lock files in CS data paths.
    Writes a temp file dump and echoes a summary to stdout.
    Run via RMM shell (SYSTEM), read-only.
.PARAMETER AppFilter
    Regex pattern applied to installed-app display names and event log messages.
    Defaults to UltraTax. Set to 'Lacerte' or 'ProSystem' for those products.
    QuickBooks (QBW/qbw32) is always included alongside the primary filter.
.PARAMETER DaysBack
    Number of days to look back for crash events and WER reports. Default 14.
.NOTES
    Category: Diagnostics
    PS 5.1 compatible.
    Context: RMM shell (SYSTEM), read-only.
.KEYWORDS
    UltraTax, Lacerte, ProSystem, QuickBooks, crash, CLR20r3, WER, .NET, CS Professional
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('UltraTax', 'Lacerte', 'ProSystem')]
    [string]$AppFilter = 'UltraTax',

    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 14
)

$ErrorActionPreference = 'SilentlyContinue'
$Since    = (Get-Date).AddDays(-$DaysBack)
$Stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$DumpPath = Join-Path $env:TEMP "ultratax-crash-diag-$Stamp.txt"
$findings = New-Object System.Collections.Generic.List[string]

# Build app-name filter that always includes QuickBooks alongside the primary app
$AppPattern = switch ($AppFilter) {
    'Lacerte'   { 'Lacerte|QuickBooks|QBW|qbw32' }
    'ProSystem' { 'ProSystem|Creative Solutions|QuickBooks|QBW|qbw32' }
    default     { 'UltraTax|UTax|UTCS|CSPro|Thomson Reuters|Creative Solutions|QuickBooks|QBW|qbw32' }
}
$WerPattern = switch ($AppFilter) {
    'Lacerte'   { 'Lacerte|QBW|QuickBooks' }
    'ProSystem' { 'ProSystem|Creative|QBW|QuickBooks' }
    default     { 'UltraTax|UTax|UTCS|QBW|QuickBooks|Creative' }
}
$CrashFilter = "$AppPattern|\.NET Runtime"

function W { param($t) Add-Content -Path $DumpPath -Value $t }
function H { param($t) W "`n===== $t =====" }
function Note { param($t) $findings.Add($t) | Out-Null }

W "$AppFilter + QuickBooks crash diagnostic"
W "Host $env:COMPUTERNAME  Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ---------- 0. Machine / pending reboot ----------
H "MACHINE"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
W "OS $($os.Caption) build $($os.BuildNumber) ver $($os.Version)"
W "Last boot $($os.LastBootUpTime)  Logged user $($cs.UserName)"
$pendingPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
)
$pending = @($pendingPaths | Where-Object { Test-Path $_ })
W "Pending reboot $(if($pending.Count -gt 0){'YES: ' + ($pending -join '; ')}else{'no'})"
if ($pending.Count -gt 0) { Note "Pending reboot detected" }

# ---------- 1. Installed apps ----------
H "INSTALLED $($AppFilter.ToUpper()) / QUICKBOOKS / CS PROFESSIONAL"
$uninstKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = Get-ItemProperty $uninstKeys | Where-Object {
    $_.DisplayName -match $AppPattern
} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName
if ($apps) {
    $apps | Format-Table -AutoSize | Out-String -Width 200 | Set-Variable -Name s
    W $s
    Note "Installed: $(($apps | ForEach-Object { $_.DisplayName }) -join ' | ')"
} else { W "No matching apps found in uninstall keys." }

# ---------- 2. .NET Framework 4.8+ ----------
H "DOT NET FRAMEWORK"
$ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
if ($ndp) {
    W "Release $($ndp.Release)  Version $($ndp.Version)  Install $($ndp.Install)  TargetVersion $($ndp.TargetVersion)"
    $rel = [int]$ndp.Release
    $label = switch ($rel) {
        {$_ -ge 533320} { '.NET Framework 4.8.1' }
        {$_ -ge 528040} { '.NET Framework 4.8' }
        {$_ -ge 461808} { '.NET Framework 4.7.2' }
        default         { 'older than 4.7.2' }
    }
    W "Interpreted: $label (Release=$rel)"
    if ($rel -lt 528040) { Note "BLOCKER: .NET below 4.8 (Release=$rel). $AppFilter requires 4.8." }
} else { W "v4 Full NDP key missing."; Note "BLOCKER: .NET 4.8 NDP key missing" }

H "DOT NET CORE/DESKTOP RUNTIMES"
$dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
if (Test-Path $dotnet) { & $dotnet --list-runtimes 2>$null | ForEach-Object { W $_ } }
else { W "dotnet.exe not present (only .NET Framework installed)." }

# ---------- 3. Visual C++ Redistributables ----------
H "VISUAL CPP REDISTRIBUTABLES"
$vcs = @(Get-ItemProperty $uninstKeys | Where-Object {
    $_.DisplayName -match 'Microsoft Visual C\+\+ \d{4}'
} | Select-Object DisplayName,DisplayVersion | Sort-Object DisplayName -Unique)
if ($vcs.Count -eq 0) { Note "BLOCKER: No Visual C++ Redistributables found" }
$vcs | Format-Table -AutoSize | Out-String -Width 200 | Set-Variable -Name s
W $s
W "VC++ count: $($vcs.Count)"
$hasX86 = $vcs | Where-Object { $_.DisplayName -match '2015-202\d.+x86' }
$hasX64 = $vcs | Where-Object { $_.DisplayName -match '2015-202\d.+x64' }
if (-not $hasX86) { Note "VC++ 2015-2022 x86 NOT present" }
if (-not $hasX64) { Note "VC++ 2015-2022 x64 NOT present" }

# ---------- 4. Recent hotfixes ----------
H "HOTFIXES LAST 30 DAYS"
$hf = Get-HotFix | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) } |
    Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn
if ($hf) {
    $hf | Format-Table -AutoSize | Out-String -Width 200 | Set-Variable -Name s
    W $s
    Note "Recent hotfixes: $(($hf | ForEach-Object { $_.HotFixID }) -join ',')"
} else { W "No hotfixes installed in last 30 days." }

# ---------- 5. Application + .NET Runtime crash events ----------
H "APPLICATION EVENT LOG 1000/1002/1026 LAST $DaysBack DAYS"
$appEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    Id        = 1000,1002,1026
    StartTime = $Since
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match $CrashFilter -or $_.ProviderName -eq '.NET Runtime'
}
if ($appEvents) {
    $byApp = $appEvents |
        Group-Object { ($_.Message -split "`r?`n")[0] -replace '\s+',' ' } |
        Sort-Object Count -Descending | Select-Object Count,Name -First 10
    $byApp | Format-Table -AutoSize | Out-String -Width 200 | Set-Variable -Name s
    W $s
    W "`n--- LATEST 15 EVENTS ---"
    $appEvents | Select-Object -First 15 | ForEach-Object {
        W "[$($_.TimeCreated)] Id $($_.Id) Provider $($_.ProviderName)"
        ($_.Message -split "`r?`n") | Select-Object -First 6 | ForEach-Object { W "  $_" }
    }
    Note "Crash events matched: $($appEvents.Count). Top: $(($byApp | Select-Object -First 3 | ForEach-Object {"$($_.Count)x $($_.Name.Substring(0,[Math]::Min(80,$_.Name.Length)))"}) -join ' | ')"
} else {
    W "No matching crash events in window."
    Note "No matching Application/.NET Runtime crash events in last $DaysBack days"
}

# ---------- 6. WER reports ----------
H "WER REPORT ARCHIVE ($($AppFilter.ToUpper()) / QBW)"
$werRoots = @(
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
)
$werDirs = $werRoots |
    ForEach-Object { Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue } |
    Where-Object { $_.Name -match $WerPattern } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 8
if (-not $werDirs) { W "No matching WER folders." }
$werCount = 0
foreach ($d in $werDirs) {
    $werCount++
    W "`n-- $($d.FullName)  $($d.LastWriteTime)"
    $report = Join-Path $d.FullName 'Report.wer'
    if (Test-Path $report) {
        Get-Content $report -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^(AppName|AppVersion|ModName|ModVersion|Exception|Sig\[\d|EventName)' } |
            Select-Object -First 15 | ForEach-Object { W "  $_" }
    }
}
if ($werCount -gt 0) { Note "WER reports found: $werCount most recent captured" }

# ---------- 7. SentinelOne status ----------
H "SENTINELONE STATUS"
$svc = Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue
if ($svc) {
    W "Service $($svc.Name)  Status $($svc.Status)"
    $sctl = Get-ChildItem 'C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe' `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sctl) {
        & $sctl.FullName status 2>$null | Select-Object -First 15 | ForEach-Object { W "  $_" }
    }
} else { W "SentinelAgent not present." }

# ---------- 8. CS Professional / Thomson Reuters registry paths ----------
H "REGISTRY: CS PROFESSIONAL SUITE PATHS"
$csRoots = @(
    'HKLM:\SOFTWARE\WOW6432Node\Thomson Reuters',
    'HKLM:\SOFTWARE\Thomson Reuters',
    'HKLM:\SOFTWARE\WOW6432Node\Creative Solutions',
    'HKLM:\SOFTWARE\Creative Solutions',
    'HKLM:\SOFTWARE\WOW6432Node\CSI'
)
$csDataPaths = New-Object System.Collections.Generic.List[string]
foreach ($r in $csRoots) {
    if (Test-Path $r) {
        W "`n[$r]"
        try {
            Get-ChildItem $r -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $vals = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                foreach ($p in $vals.PSObject.Properties) {
                    if ($p.Name -match '^(Path|DataPath|InstallPath|SharedPath|UTPath|UTDataPath)$' -and $p.Value) {
                        $line = "$($_.PsPath -replace 'Microsoft.PowerShell.Core\\Registry::','')\$($p.Name) = $($p.Value)"
                        W $line
                        if ($p.Value -match '^[A-Za-z]:\\' -or $p.Value -match '^\\\\') {
                            $csDataPaths.Add($p.Value) | Out-Null
                        }
                    }
                }
            }
        } catch { W "  read failed: $($_.Exception.Message)" }
    }
}
$csDataPaths = @($csDataPaths | Select-Object -Unique)
if ($csDataPaths.Count -gt 0) {
    Note "CS data paths registered: $($csDataPaths.Count) ($(($csDataPaths | Select-Object -First 3) -join ' | '))"
} else { W "No data-path values harvested from registry." }

# ---------- 9. Per-user CSI / Creative Solutions cache ----------
H "PER USER CSI / CREATIVE SOLUTIONS CACHE"
$profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProfileImagePath -match '\\Users\\[^\\]+$' -and
        $_.ProfileImagePath -notmatch 'NetworkService|LocalService|systemprofile'
    } | Select-Object @{n='SID';e={Split-Path $_.PSPath -Leaf}},ProfileImagePath

foreach ($prof in $profiles) {
    $userName = Split-Path $prof.ProfileImagePath -Leaf
    W "`nUser $userName  SID $($prof.SID)"
    $candidates = @(
        Join-Path $prof.ProfileImagePath 'AppData\Local\Creative Solutions',
        Join-Path $prof.ProfileImagePath 'AppData\Roaming\Creative Solutions',
        Join-Path $prof.ProfileImagePath 'AppData\Local\Thomson Reuters',
        Join-Path $prof.ProfileImagePath 'AppData\Roaming\Thomson Reuters'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $items  = Get-ChildItem $c -Recurse -File -ErrorAction SilentlyContinue
            $bytes  = ($items | Measure-Object Length -Sum).Sum
            $lastw  = ($items | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            $sizeMB = [Math]::Round(($bytes / 1MB), 1)
            W "  $c -> $($items.Count) files, ${sizeMB} MB, newest $lastw"
        }
    }
}

# ---------- 10. Stale lock files ----------
H "STALE LOCK FILES IN CS DATA PATHS"
$lockHits = 0
foreach ($d in $csDataPaths) {
    if (-not (Test-Path $d)) { W "missing $d"; continue }
    $locks = Get-ChildItem $d -Recurse -Force -File -Include *.LCK,*.LOCK -ErrorAction SilentlyContinue |
        Select-Object FullName,Length,LastWriteTime
    if ($locks) {
        $lockHits += $locks.Count
        W "`n[$d] $($locks.Count) lock files"
        $locks | Select-Object -First 20 | Format-Table -AutoSize | Out-String -Width 200 | Set-Variable -Name s
        W $s
    } else {
        W "[$d] no lock files"
    }
}
if ($lockHits -gt 0) { Note "Stale .LCK/.LOCK files: $lockHits across CS data paths" }

# ---------- 11. Summary ----------
H "SUMMARY"
W "Findings: $($findings.Count)"
foreach ($f in $findings) { W "  - $f" }

Write-Output "=== $AppFilter diagnostic summary ($(Get-Date -Format 'HH:mm:ss')) ==="
Write-Output "Host $env:COMPUTERNAME  Full dump: $DumpPath"
if ($findings.Count -eq 0) {
    Write-Output "No notable findings flagged."
} else {
    foreach ($f in $findings) { Write-Output "* $f" }
}
Write-Output ""
Write-Output "=== Tail of dump (last 60 lines) ==="
Get-Content $DumpPath -Tail 60 -ErrorAction SilentlyContinue
