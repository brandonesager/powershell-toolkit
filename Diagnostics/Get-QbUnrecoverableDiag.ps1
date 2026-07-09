<#
.SYNOPSIS
    Diagnose QuickBooks "Unrecoverable Error" caused by CefAdapter.dll / libcef.dll
    version mismatch on RDS hosts.

.DESCRIPTION
    QuickBooks Enterprise 2024 R19+ can receive a silent out-of-band CefAdapter.dll
    hotfix that does not include a matching libcef.dll rebuild. The ABI mismatch
    triggers STATUS_BREAKPOINT (0x80000003) the first time QB initializes an embedded
    Chromium pane. Crash signature: libcef.dll faulting module, fixed offset.

    This script (read-only) collects:
      - QB R-release and CEF file inventory (CefAdapter.dll, libcef.dll, chrome_elf.dll)
      - Cross-date comparison: CefAdapter date vs all other CEF siblings (outlier = hotfix)
      - WER crash events: qbw / libcef / 0x80000003
      - Active user sessions (for RDS multi-host triage)
      - D3DCOMPILER_47.dll version compare (secondary check; separate issue)

    Helper guidance:
      PREP  - Stop QB procs and locking services before a manual Repair.
      VERIFY - After Repair, confirm CefAdapter + libcef dates match.
    Both helpers are inline functions at the bottom; call them manually if needed.

.PARAMETER QbInstallDir
    Path to the QB Enterprise install folder. Defaults to
    "C:\Program Files\Intuit\QuickBooks Enterprise Solutions 24.0".

.PARAMETER TargetUser
    Username to scope WER and session checks. Leave empty to scan all users.

.NOTES
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1, RMM RMM shell)

.KEYWORDS
    QuickBooks, CefAdapter, libcef, Chromium, Unrecoverable Error, RDS, CEF, 0x80000003
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$QbInstallDir = 'C:\Program Files\Intuit\QuickBooks Enterprise Solutions 24.0',
    [string]$TargetUser   = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$Since7 = (Get-Date).AddDays(-7)

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-QbUnrecoverableDiag"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
W ("QB dir: {0}" -f $QbInstallDir)

# --- 1. Host / OS ---
Sec "HOST"
$os = Get-CimInstance Win32_OperatingSystem
W ("OS {0}  Build {1}  Version {2}" -f $os.Caption, $os.BuildNumber, $os.Version)

# --- 2. Active sessions ---
Sec "ACTIVE USER SESSIONS (quser)"
try { & quser 2>&1 | ForEach-Object { W $_ } } catch { W "quser unavailable" }

# --- 3. QB R-release ---
Sec "QB R-RELEASE"
$qbRegPaths = @(
    'HKLM:\SOFTWARE\Intuit\QuickBooks\34.0',
    'HKLM:\SOFTWARE\WOW6432Node\Intuit\QuickBooks\34.0',
    'HKLM:\SOFTWARE\Intuit\QuickBooks Enterprise Solutions 24.0',
    'HKLM:\SOFTWARE\WOW6432Node\Intuit\QuickBooks Enterprise Solutions 24.0'
)
foreach ($r in $qbRegPaths) {
    if (Test-Path $r) {
        W "Found: $r"
        Get-ItemProperty $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | W
    }
}
$qbExe = Get-Item (Join-Path $QbInstallDir 'QBW.exe') -ErrorAction SilentlyContinue
if ($qbExe) { W ("QBW.exe FileVersion: {0}  ProductVersion: {1}" -f $qbExe.VersionInfo.FileVersion, $qbExe.VersionInfo.ProductVersion) }

# --- 4. CEF file inventory (CefAdapter / libcef siblings) ---
Sec "CEF FILE INVENTORY (CefAdapter, libcef + siblings)"
$cefFiles = @('CefAdapter.dll','libcef.dll','chrome_elf.dll','CefSharp.dll',
              'CefSharp.BrowserSubprocess.exe','libEGL.dll','libGLESv2.dll')
$inventory = foreach ($f in $cefFiles) {
    $path = Join-Path $QbInstallDir $f
    $item = Get-Item $path -ErrorAction SilentlyContinue
    if ($item) {
        [PSCustomObject]@{
            File      = $f
            Date      = $item.LastWriteTime
            SizeKB    = [math]::Round($item.Length / 1KB, 0)
            Version   = $item.VersionInfo.FileVersion
        }
    }
}
if ($inventory) {
    $inventory | Sort-Object Date -Descending | Format-Table File, Date, SizeKB, Version -AutoSize | Out-String | W
    # Flag outliers: CefAdapter date differs from modal date of siblings
    $dates = $inventory | Group-Object { $_.Date.ToString('yyyy-MM-dd') } | Sort-Object Count -Descending
    $modalDate = $dates[0].Name
    $outliers  = $inventory | Where-Object { $_.Date.ToString('yyyy-MM-dd') -ne $modalDate }
    if ($outliers) {
        W ">> OUTLIER (date differs from majority $modalDate):"
        $outliers | ForEach-Object { W ("   {0}  {1}  {2}" -f $_.File, $_.Date, $_.Version) }
        W ">> Outlier CefAdapter.dll = likely out-of-band hotfix without matching libcef rebuild."
    } else {
        W ">> All CEF files share the same write date ($modalDate). No obvious mismatch."
    }
} else { W "No CEF files found under $QbInstallDir" }

# --- 5. D3DCOMPILER_47.dll (secondary check) ---
Sec "D3DCOMPILER_47.DLL COMPARE"
$sysDll = Get-Item "$env:WINDIR\System32\D3DCOMPILER_47.dll" -ErrorAction SilentlyContinue
if ($sysDll) { W ("System32: {0}  ({1})" -f $sysDll.VersionInfo.FileVersion, $sysDll.LastWriteTime) }
$qbDll = Get-Item (Join-Path $QbInstallDir 'D3DCOMPILER_47.dll') -ErrorAction SilentlyContinue
if ($qbDll) {
    W ("QB folder: {0}  ({1})" -f $qbDll.VersionInfo.FileVersion, $qbDll.LastWriteTime)
    if ($sysDll -and $qbDll.VersionInfo.FileVersion -ne $sysDll.VersionInfo.FileVersion) {
        W ">> D3DCOMPILER version differs - may cause __CxxFrameHandler4 entry-point error (see Invoke-QBD3DCompilerFix)."
    }
} else { W "D3DCOMPILER_47.dll not found in QB folder." }

# --- 6. WER crash events (libcef / qbw) ---
Sec "WER CRASH EVENTS (last 7 days)"
$werEvents = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since7 } |
             Where-Object {
                 ($_.ProviderName -match 'Application Error' -and $_.Message -match 'qbw|libcef') -or
                 ($_.ProviderName -match 'Windows Error Reporting' -and $_.Message -match 'qbw|QuickBooks')
             } | Select-Object -First 10 TimeCreated, Id, @{n='Snip';e={ ($_.Message -split "`r?`n" | Select-Object -First 4) -join ' | ' }}
if ($werEvents) {
    W "QB crash events:"
    $werEvents | ForEach-Object { W ("{0}  [{1}]  {2}" -f $_.TimeCreated, $_.Id, $_.Snip) }
} else { W "No QB-related crash events in last 7 days." }

# WER bucket files
$werRoots = @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive")
$qbWer = foreach ($w in $werRoots) {
    Get-ChildItem $w -Recurse -Filter 'Report.wer' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $Since7 } | ForEach-Object {
            $content = Get-Content $_.FullName -ErrorAction SilentlyContinue
            if ($content -match 'qbw32|qbw\.exe|qbmapi64|QuickBooks') {
                [PSCustomObject]@{
                    Time = $_.LastWriteTime
                    App  = ($content | Where-Object { $_ -match '^AppName=' }) -replace 'AppName='
                    Mod  = ($content | Where-Object { $_ -match '^Sig\[3\]\.Value=' }) -replace 'Sig\[3\]\.Value='
                    Exc  = ($content | Where-Object { $_ -match '^Sig\[6\]\.Value=' }) -replace 'Sig\[6\]\.Value='
                    Path = $_.FullName
                }
            }
        }
}
if ($qbWer) { $qbWer | Format-Table Time, App, Mod, Exc -AutoSize | Out-String | W }
else { W "No qbw WER report files in last 7 days." }

# --- 7. Running QB procs ---
Sec "RUNNING QB PROCESSES"
$procs = Get-Process | Where-Object { $_.Name -match '^(QBW|qbw|CefSharp|CefAdapter)' }
if ($procs) {
    $procs | ForEach-Object {
        $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner()
        W ("PID {0}  {1}  Session {2}  Owner {3}\{4}" -f $_.Id, $_.Name, $_.SessionId, $owner.Domain, $owner.User)
    }
} else { W "No QB/CEF processes running." }

W ""
W "===== END Get-QbUnrecoverableDiag ====="
W ""
W "--- PREP helper (stop QB procs + QBUpdateMonitorService before Repair) ---"
W "Run separately with approval:"
W "  Stop-Process -Name 'qbw','CefSharp.BrowserSubprocess','qbupdate','QBWebConnector' -Force -ErrorAction SilentlyContinue"
W "  Stop-Service QBUpdateMonitorService -Force -ErrorAction SilentlyContinue"
W ""
W "--- VERIFY helper (confirm CefAdapter + libcef dates match after Repair) ---"
W "  (Get-Item '$QbInstallDir\CefAdapter.dll').LastWriteTime"
W "  (Get-Item '$QbInstallDir\libcef.dll').LastWriteTime"
W "  If both match, the Repair evicted the outlier hotfix. If CefAdapter is still newer, extract manually."
