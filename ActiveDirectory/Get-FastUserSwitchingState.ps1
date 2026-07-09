<#
.SYNOPSIS
    Read all layers that control Fast User Switching: local registry, local GPO result,
    SYSVOL Registry.pol files, and RSOP.

.DESCRIPTION
    Fast User Switching is controlled by HideFastUserSwitching under
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.
    Value 0 = FUS visible (enabled), 1 = FUS hidden (disabled).

    A local registry value set by a prior GPO ("tattoo") can persist and block FUS
    even after the GPO is removed. This script reads every relevant layer:
      - Direct HKLM registry value
      - Winlogon settings
      - gpresult /r /scope:computer summary
      - RSOP GPO list (Win32_RSOP_GPO)
      - SYSVOL Registry.pol scan for HideFastUserSwitching (identifies which GPO set it)
      - Recent Group Policy apply events

    Read-only. No writes.

.PARAMETER DomainFQDN
    FQDN of the domain for SYSVOL UNC path. If empty, attempts to auto-detect from
    Win32_ComputerSystem.Domain.

.NOTES
    Created: 2026-05-29
    Category: ActiveDirectory
    Context: RMM shell (SYSTEM, PS 5.1 on domain member)

.KEYWORDS
    Fast User Switching, HideFastUserSwitching, GPO, tattoo, SYSVOL, Registry.pol,
    logon screen, multiple users
#>
#!ps
#maxlength=100000
#timeout=180000
#Requires -Version 5.1

param(
    [string]$DomainFQDN = ''
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-FastUserSwitchingState"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# Auto-detect domain
if (-not $DomainFQDN) {
    $cs = Get-CimInstance Win32_ComputerSystem
    $DomainFQDN = $cs.Domain
}
W ("Domain: {0}" -f $DomainFQDN)

# --- 1. Host / sessions ---
Sec "HOST / ACTIVE SESSIONS"
$cs = Get-CimInstance Win32_ComputerSystem
$cs | Select-Object Name, Domain, PartOfDomain, UserName | Format-List | Out-String | W
$os = Get-CimInstance Win32_OperatingSystem
W ("OS: {0}  {1}" -f $os.Caption, $os.Version)
W "--- quser ---"
try { & quser 2>&1 | ForEach-Object { W $_ } } catch { W "quser unavailable" }

# --- 2. HKLM registry ---
Sec "HKLM HideFastUserSwitching"
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if (Test-Path $regPath) {
    $val = (Get-ItemProperty $regPath -Name HideFastUserSwitching -ErrorAction SilentlyContinue).HideFastUserSwitching
    if ($null -ne $val) {
        W ("HideFastUserSwitching = {0}  ({1})" -f $val, $(if ($val -eq 0) { 'FUS VISIBLE (enabled)' } elseif ($val -eq 1) { 'FUS HIDDEN (disabled)' } else { 'UNKNOWN' }))
    } else {
        W "HideFastUserSwitching value NOT present (FUS defaults to enabled)."
    }
} else { W "Policies\System key not present." }

# --- 3. Winlogon ---
Sec "WINLOGON SETTINGS"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
    Select-Object LogonType, DontDisplayLastUserName, HideFastUserSwitching, dontdisplaylockedusername |
    Format-List | Out-String | W

# --- 4. gpresult /r /scope:computer ---
Sec "GPRESULT /R /SCOPE COMPUTER"
$gpRaw = (& gpresult /r /scope:computer 2>&1 | Out-String)
if ($gpRaw) { W $gpRaw } else { W "gpresult returned nothing." }

# --- 5. RSOP GPO list ---
Sec "APPLIED GPOs (RSOP)"
try {
    $rsop = Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_GPO -ErrorAction Stop |
            Select-Object Name, FilterAllowed, Enabled, AccessDenied | Sort-Object Name
    if ($rsop) { $rsop | Format-Table -AutoSize | Out-String | W }
    else { W "No RSOP GPO objects." }
} catch { W ("RSOP namespace unavailable: {0}" -f $_.Exception.Message) }

# --- 6. SYSVOL Registry.pol scan ---
Sec "SYSVOL REGISTRY.POL SCAN FOR HideFastUserSwitching"
$sysvolPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies"
if (-not (Test-Path $sysvolPath)) {
    W "SYSVOL path not reachable: $sysvolPath"
} else {
    $gpoDirs = Get-ChildItem $sysvolPath -Directory
    W ("Found {0} GPO GUID folders in SYSVOL." -f $gpoDirs.Count)

    # Try to resolve GPO names
    $nameMap = @{}
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Get-GPO -All -ErrorAction SilentlyContinue | ForEach-Object {
            $nameMap['{' + $_.Id.ToString().ToUpper() + '}'] = $_.DisplayName
        }
        W ("Resolved {0} GPO names via GroupPolicy module." -f $nameMap.Count)
    } catch { W "GroupPolicy module unavailable; GUID-only output." }

    $hits = @()
    foreach ($dir in $gpoDirs) {
        $polFile = Join-Path $dir.FullName 'Machine\Registry.pol'
        if (Test-Path $polFile) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($polFile)
                $text  = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($text -match 'HideFastUserSwitching') {
                    $friendly = if ($nameMap.ContainsKey($dir.Name)) { $nameMap[$dir.Name] } else { '(unresolved)' }
                    $hits += [PSCustomObject]@{
                        GPO      = $friendly
                        GUID     = $dir.Name
                        Modified = (Get-Item $polFile).LastWriteTime
                        PolPath  = $polFile
                    }
                }
            } catch { W ("Read failed: {0}" -f $polFile) }
        }
    }

    if ($hits) {
        W ("MATCH: {0} GPO(s) contain HideFastUserSwitching in Machine\Registry.pol:" -f $hits.Count)
        $hits | Sort-Object Modified -Descending | Format-List GPO, GUID, Modified, PolPath | Out-String | W
    } else {
        W "No Registry.pol in SYSVOL contains HideFastUserSwitching."
        W "Setting is likely a local-only tattoo value, not domain GPO-enforced."
    }
}

# --- 7. Recent GP events ---
Sec "RECENT GROUP POLICY EVENTS (last 24h)"
try {
    Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 20 -ErrorAction Stop |
        Where-Object { $_.Id -in @(4016, 5016, 5126, 8001) -and $_.TimeCreated -gt (Get-Date).AddHours(-24) } |
        Select-Object TimeCreated, Id, LevelDisplayName, @{n='Msg';e={ ($_.Message -split "`n")[0] }} |
        Format-Table -AutoSize | Out-String | W
} catch { W ("GP event query failed: {0}" -f $_.Exception.Message) }

W ""
W "===== END Get-FastUserSwitchingState ====="
W ""
W "If HideFastUserSwitching = 1 is tattooed (no GPO source in SYSVOL), apply via GPO:"
W "  Computer Config > Admin Templates > System > Logon >"
W "  'Hide entry points for Fast User Switching' = Disabled"
W "  This writes HideFastUserSwitching=0 and overrides the tattoo without manual reg edit."
W "  See New-FastUserSwitchingGPO.ps1 to create and link this GPO programmatically."
