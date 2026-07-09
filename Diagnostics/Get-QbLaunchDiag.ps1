<#
.SYNOPSIS
    Read-only diagnostic for QuickBooks Desktop silent-launch failures on a workstation.

.DESCRIPTION
    Covers the five most common causes of QB "launches but nothing appears" on a
    Windows workstation:
      1. Orphaned QB process (prior session never cleanly exited)
      2. SentinelOne quarantine / block
      3. Features.dll or CEF binary damage (WER crash, version mismatch)
      4. MSI 1603 self-heal loop (QB installer thrashing on launch)
      5. QBWUSER.INI zero-byte or missing (profile corruption)

    Also captures installed QB versions, shortcut targets, VC++ redistributables,
    AppLocker state, FIPS policy, and QB services. All reads, no writes.

.PARAMETER TargetUser
    SamAccountName (or local username) of the affected user. Used to scope profile
    and registry reads. Required.

.PARAMETER DayWindow
    Number of days back to search event logs and WER buckets. Default 14.

.NOTES
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1, RMM RMM shell)

.KEYWORDS
    QuickBooks, silent launch, WER, SentinelOne, Features.dll, QBWUSER.INI, MSI, orphan
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$TargetUser,

    [int]$DayWindow = 14
)

$ErrorActionPreference = 'SilentlyContinue'
$Since = (Get-Date).AddDays(-$DayWindow)

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-QbLaunchDiag"
W ("Host {0}   Generated {1}   TargetUser {2}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $TargetUser)

# ---------- Machine baseline ----------
Sec "MACHINE"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
W ("OS {0}  Build {1}  LastBoot {2}" -f $os.Caption, $os.BuildNumber, $os.LastBootUpTime)
W ("Logged-on user (console): {0}" -f $cs.UserName)

# ---------- 1. Orphaned QB processes ----------
Sec "RUNNING QUICKBOOKS PROCESSES"
$qbNames = @('QBW32','QBW','QBWUSER','qbupdate','QBDBMgrN','QBDBMgr','QBCFMonitorService',
             'QBMapi32','QBIDPService','FileManagement','QBW32Pro','IntuitUpdateService','QBLaunchAgent')
$procs = Get-Process | Where-Object { $qbNames -contains $_.Name }
if ($procs) {
    foreach ($p in $procs) {
        $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").GetOwner()
        W ("PID {0,-6} {1,-22} Start {2}  Owner {3}\{4}  Path {5}" -f $p.Id, $p.Name, $p.StartTime, $owner.Domain, $owner.User, $p.Path)
    }
    W ">> Orphaned QB process present. If matching TargetUser or no window, this silently blocks relaunch."
} else {
    W "No QB processes running. Orphaned-process block ruled out."
}

# ---------- 2. QB services ----------
Sec "QUICKBOOKS SERVICES"
$svcs = Get-Service | Where-Object { $_.Name -match 'QB|Intuit|QuickBooks' }
if ($svcs) {
    $svcs | ForEach-Object { W ("{0,-30} {1,-10} StartType {2}" -f $_.Name, $_.Status, $_.StartType) }
} else { W "No QuickBooks/Intuit services found." }

# ---------- 3. Installed QB versions ----------
Sec "INSTALLED QUICKBOOKS"
$uninst = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$qb = Get-ItemProperty $uninst | Where-Object { $_.DisplayName -match 'QuickBooks' } |
      Select-Object DisplayName, DisplayVersion, InstallLocation
if ($qb) {
    foreach ($q in $qb) {
        W ("{0}  v{1}" -f $q.DisplayName, $q.DisplayVersion)
        if ($q.InstallLocation) {
            $exe = @(Join-Path $q.InstallLocation 'QBW32.EXE', (Join-Path $q.InstallLocation 'QBW.EXE')) |
                   Where-Object { Test-Path $_ } | Select-Object -First 1
            W ("   InstallLocation {0}  exe {1}" -f $q.InstallLocation, $(if ($exe) { "OK $exe" } else { 'MISSING' }))
        } else { W "   InstallLocation not recorded" }
    }
} else { W "No QuickBooks entry in Add/Remove Programs." }

# ---------- 4. Shortcut targets ----------
Sec "QUICKBOOKS SHORTCUT TARGETS"
$lnkRoots = @(
    "$env:PUBLIC\Desktop",
    "C:\Users\$TargetUser\Desktop",
    "C:\Users\$TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
)
$sh = New-Object -ComObject WScript.Shell
foreach ($r in $lnkRoots) {
    $lnks = Get-ChildItem -Path $r -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'QuickBooks|QBW' }
    foreach ($l in $lnks) {
        $t = $sh.CreateShortcut($l.FullName).TargetPath
        $ok = if ($t -and (Test-Path $t)) { 'TARGET OK' } else { 'TARGET MISSING' }
        W ("{0}`n   -> {1}  [{2}]" -f $l.FullName, $t, $ok)
    }
}

# ---------- 5. Application event log ----------
Sec "APPLICATION EVENT LOG (QB/.NET/AppError, last $DayWindow days)"
$evt = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since } |
       Where-Object { $_.Message -match 'QBW32|QuickBooks|qbw\.exe' -or
           ($_.ProviderName -match 'Application Error|\.NET Runtime' -and $_.Message -match 'QBW|QuickBooks') } |
       Select-Object -First 15 TimeCreated, Id, ProviderName, @{n='Msg';e={ ($_.Message -split "`n")[0] }}
if ($evt) { $evt | ForEach-Object { W ("{0}  [{1}/{2}]  {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, $_.Msg) } }
else { W "No QB-related Application errors in window." }

# ---------- 6. WER buckets ----------
Sec "WER REPORTS (QBW / QuickBooks)"
$werRoots = @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
              "$env:ProgramData\Microsoft\Windows\WER\ReportQueue")
$wer = foreach ($w in $werRoots) {
    Get-ChildItem $w -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'QBW|QuickBooks' }
}
if ($wer) {
    $wer | Sort-Object LastWriteTime -Descending | Select-Object -First 8 |
        ForEach-Object { W ("{0}   {1}" -f $_.LastWriteTime, $_.Name) }
    # Detail for top 5
    $wer | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
        $rep = Get-ChildItem $_.FullName -Filter 'Report.wer' | Select-Object -First 1
        if ($rep) {
            $lines = Get-Content $rep.FullName |
                     Where-Object { $_ -match 'AppName|AppPath|Sig\[\d\]|ExceptionCode|FaultingModule' }
            W ("--- {0} ---" -f $_.Name)
            $lines | ForEach-Object { W "   $_" }
        }
    }
} else { W "No QB WER buckets (launch may not reach crash, or S1 pre-empts)." }

# ---------- 7. SentinelOne ----------
Sec "SENTINELONE STATUS + RECENT BLOCKS"
$s1ctl = Get-ChildItem 'C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe' | Select-Object -First 1
if ($s1ctl) {
    W "Agent: $($s1ctl.FullName)"
    W (& $s1ctl.FullName status 2>&1 | Out-String).Trim()
} else { W "SentinelCtl.exe not found." }

$q = 'C:\ProgramData\Sentinel\Quarantine'
if (Test-Path $q) {
    $qf = Get-ChildItem $q -Recurse | Where-Object { $_.Name -match 'QB|qbw|intuit' }
    if ($qf) { W ">> QB-related quarantine items:"; $qf | ForEach-Object { W ("   {0}  {1}b  {2}" -f $_.Name, $_.Length, $_.LastWriteTime) } }
    else { W "Quarantine folder present, no QB items." }
} else { W "No Quarantine folder." }

$s1evt = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since } |
         Where-Object { $_.ProviderName -match 'SentinelOne|Sentinel' -and
             $_.Message -match 'QB|QuickBooks|Intuit|block|quarantin|mitigat' } |
         Select-Object -First 10 TimeCreated, Id, @{n='Msg';e={ ($_.Message -split "`n")[0] }}
if ($s1evt) { W ">> S1 events referencing QB:"; $s1evt | ForEach-Object { W ("   {0}  [{1}]  {2}" -f $_.TimeCreated, $_.Id, $_.Msg) } }
else { W "No S1 Application-log events referencing QB." }

# ---------- 8. Features.dll / CEF binaries ----------
Sec "FEATURES.DLL / QB CEF BINARIES (version + write date)"
$intuitRoots = @('C:\Program Files (x86)\Intuit','C:\Program Files\Intuit',
                 'C:\Program Files (x86)\Common Files\Intuit','C:\Program Files\Common Files\Intuit')
$cefNames = @('Features.dll','libcef.dll','chrome_elf.dll','CefAdapter.dll','QBW32.EXE','qbw.exe')
$bins = foreach ($r in $intuitRoots) {
    Get-ChildItem -Path $r -Recurse -Include $cefNames -ErrorAction SilentlyContinue |
        Select-Object FullName, @{n='Ver';e={$_.VersionInfo.FileVersion}}, LastWriteTime, Length
}
if ($bins) {
    $bins | Sort-Object FullName | ForEach-Object {
        W ("{0}`n   Ver {1}  Written {2}  {3} bytes" -f $_.FullName, $_.Ver, $_.LastWriteTime, $_.Length)
    }
} else { W "No Features.dll / CEF binaries found under Intuit roots." }

# ---------- 9. Runtime deps + QBWUSER.INI ----------
Sec "QB DEPENDENCIES + QBWUSER.INI + ENTITLEMENT"
$net = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
W (".NET 4.x Release {0}  Version {1}" -f $net.Release, $net.Version)
$msxml = Get-ChildItem 'C:\Windows\System32\msxml*.dll' | Select-Object -ExpandProperty Name
W ("MSXML present: {0}" -f ($msxml -join ', '))

$vc = Get-ItemProperty $uninst | Where-Object { $_.DisplayName -match 'Visual C\+\+' } |
      Select-Object DisplayName, DisplayVersion | Sort-Object DisplayName -Unique
if ($vc) { $vc | ForEach-Object { W ("{0}  {1}" -f $_.DisplayName, $_.DisplayVersion) } }

$iniFiles = Get-ChildItem "C:\Users\$TargetUser\AppData\Local\Intuit" -Recurse -Filter 'QBWUSER.INI' -ErrorAction SilentlyContinue
if ($iniFiles) { $iniFiles | ForEach-Object { W ("{0}  {1} bytes{2}" -f $_.FullName, $_.Length, $(if ($_.Length -eq 0) { '  << ZERO-BYTE' } else { '' })) } }
else { W "No QBWUSER.INI for $TargetUser." }

$ent = Get-ChildItem 'C:\ProgramData\Intuit\Entitlement Client' -Recurse -Filter 'EntitlementDataStore.ecml' -ErrorAction SilentlyContinue
if ($ent) { $ent | ForEach-Object { W ("{0}  {1} bytes{2}" -f $_.FullName, $_.Length, $(if ($_.Length -eq 0) { '  << ZERO-BYTE (corrupt)' } else { '' })) } }
else { W "No EntitlementDataStore.ecml." }

# ---------- 10. MSI 1603 self-heal events ----------
Sec "MSI 1603 SELF-HEAL EVENTS (last $DayWindow days)"
$msi = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since } |
       Where-Object { $_.ProviderName -match 'MsiInstaller' -and $_.Message -match 'QuickBooks|Intuit' -and $_.Id -in @(1033, 1004, 1008, 11708) } |
       Select-Object -First 10 TimeCreated, Id, @{n='Msg';e={ ($_.Message -split "`n")[0] }}
if ($msi) { $msi | ForEach-Object { W ("{0}  [{1}]  {2}" -f $_.TimeCreated, $_.Id, $_.Msg) } }
else { W "No QB MsiInstaller events in window." }

# ---------- 11. AppLocker / FIPS ----------
Sec "APPLOCKER / FIPS"
try {
    $al = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
    if ($al -match 'Intuit|QuickBooks|QBW') { W ">> AppLocker effective policy references QB/Intuit." }
    elseif ($al -match 'EnforcementMode="Enabled"') { W "AppLocker ENFORCED - no explicit QB rule (default-deny may block QB)." }
    else { W "AppLocker not enforced or no QB-relevant rules." }
} catch { W "AppLocker policy query unavailable." }
$fips = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -ErrorAction SilentlyContinue).Enabled
W ("FIPS Enabled = {0}{1}" -f $fips, $(if ($fips -eq 1) { '  << QB fails silently with FIPS on' } else { '' }))

W ""
W "===== END Get-QbLaunchDiag ====="
