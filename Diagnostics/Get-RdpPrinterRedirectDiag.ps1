<#
.SYNOPSIS
    Diagnose missing or blocked printer redirection in an outbound RDP session
    (client-side check on the local PC).

.DESCRIPTION
    When a redirected printer (e.g., "Microsoft Print to PDF (redirected)") is missing
    in an RDP session, the cause is on the client PC. This script checks all layers:

      1. Microsoft Print to PDF optional feature state
      2. Local printer queue list (is PDF printer present locally?)
      3. Print Spooler service state
      4. Active mstsc.exe processes and outbound TCP 3389 connections
      5. HKLM Terminal Services Client - DisablePrinterRedirection kill-switch
      6. HKLM Terminal Services policy - fDisableCpm (GPO disable all redirected printers)
      7. Per-user .rdp file - redirectprinters:i:0/1 flag and target server
      8. HKCU / all-user LocalDevices bitmask per server (per-server printer redirection
         preference stored by mstsc)
      9. Default mstsc RedirectPrinters value per user hive
     10. PrintService Admin event log (last 15 errors/warnings)
     11. Recent Windows updates (in case a KB broke redirect)

    Read-only. No writes.

.NOTES
    Created: 2026-05-29
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1 on client PC)

.KEYWORDS
    RDP, printer, redirect, redirectprinters, PDF, mstsc, LocalDevices, fDisableCpm,
    DisablePrinterRedirection, Microsoft Print to PDF
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

W "Get-RdpPrinterRedirectDiag"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# --- 1. PDF optional feature ---
Sec "MICROSOFT PRINT TO PDF FEATURE STATE"
$pdfFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -match 'PDF|Print' }
if ($pdfFeatures) { $pdfFeatures | Select-Object FeatureName, State | Format-Table -AutoSize | Out-String | W }
else { W "No PDF/Print optional features enumerated." }

# --- 2. Local printers ---
Sec "LOCAL PRINTERS"
Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus | Format-Table -AutoSize | Out-String | W
$pdf = Get-Printer -Name 'Microsoft Print to PDF'
if ($pdf) { W "Microsoft Print to PDF: PRESENT on this PC" }
else { W "Microsoft Print to PDF: NOT PRESENT on this PC (printer will not redirect)" }

# --- 3. Spooler ---
Sec "PRINT SPOOLER"
Get-Service Spooler | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | W

# --- 4. Active mstsc / RDP connections ---
Sec "ACTIVE MSTSC AND TCP 3389"
$mstsc = @(Get-Process mstsc)
if ($mstsc) { $mstsc | Select-Object Id, StartTime, MainWindowTitle | Format-Table -AutoSize | Out-String | W }
else { W "mstsc.exe not running." }
$rdpConn = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -eq 3389 })
if ($rdpConn) {
    foreach ($c in $rdpConn) {
        $proc = Get-Process -Id $c.OwningProcess
        W ("Local {0}:{1}  ->  Remote {2}:{3}  PID {4} ({5})" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.OwningProcess, $proc.ProcessName)
    }
} else { W "No active outbound RDP connections." }

# --- 5. HKLM kill-switch and policy ---
Sec "HKLM RDP CLIENT POLICY"
$hklmKey = 'HKLM:\Software\Microsoft\Terminal Server Client'
if (Test-Path $hklmKey) {
    $v = Get-ItemProperty $hklmKey
    W ("  DisablePrinterRedirection = {0}{1}" -f $v.DisablePrinterRedirection, $(if ($v.DisablePrinterRedirection -eq 1) { '  << ALL printer redirect BLOCKED' } else { '' }))
    W ("  AllowSavePassword         = {0}" -f $v.AllowSavePassword)
} else { W "  HKLM TS Client key absent." }

$polKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
if (Test-Path $polKey) {
    $pv = Get-ItemProperty $polKey
    W ("  Policy fDisableCpm = {0}{1}" -f $pv.fDisableCpm, $(if ($pv.fDisableCpm -eq 1) { '  << GPO blocks all redirected printers' } else { '' }))
} else { W "  No HKLM Terminal Services policy key." }

# --- 6. Per-user data from all loaded profiles ---
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false }

Sec "PER-USER .RDP FILE FLAGS"
$rdpFiles = @()
foreach ($p in $profiles) {
    if (Test-Path $p.LocalPath) {
        $rdpFiles += @(Get-ChildItem $p.LocalPath -Recurse -Include '*.rdp' |
                       Where-Object { $_.FullName -notmatch '\\AppData\\' })
    }
}
$rdpFiles += @(Get-ChildItem 'C:\Users\Public' -Recurse -Include '*.rdp')
if ($rdpFiles) {
    foreach ($f in ($rdpFiles | Sort-Object FullName -Unique)) {
        $content = Get-Content $f.FullName
        $svr     = ($content | Where-Object { $_ -match '^full address' }) -join ' | '
        $redir   = ($content | Where-Object { $_ -match '^redirectprinters' }) -join ' | '
        $dev     = ($content | Where-Object { $_ -match '^devicestoredirect' }) -join ' | '
        W ("{0}  (modified {1})" -f $f.FullName, $f.LastWriteTime)
        W ("  {0}" -f $svr)
        W ("  {0}{1}" -f $redir, $(if ($redir -match ':i:0') { '  << PRINTER REDIRECT DISABLED in this .rdp' } else { '' }))
        if ($dev) { W ("  {0}" -f $dev) }
    }
} else { W "No .rdp files found in user profiles or Public." }

Sec "LOCALDEVICES BITMASK (per-server printer preference)"
foreach ($p in $profiles) {
    $ldKey = "Registry::HKEY_USERS\$($p.SID)\Software\Microsoft\Terminal Server Client\LocalDevices"
    if (Test-Path $ldKey) {
        $user = Split-Path $p.LocalPath -Leaf
        $vals = Get-ItemProperty $ldKey
        foreach ($prop in $vals.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS') {
                W ("  user={0,-20} server={1,-40} bits={2}" -f $user, $prop.Name, $prop.Value)
            }
        }
    }
}

Sec "DEFAULT MSTSC REDIRECTPRINTERS PER USER"
foreach ($p in $profiles) {
    $key = "Registry::HKEY_USERS\$($p.SID)\Software\Microsoft\Terminal Server Client\Default"
    if (Test-Path $key) {
        $user = Split-Path $p.LocalPath -Leaf
        $val  = (Get-ItemProperty $key).RedirectPrinters
        W ("  User {0}: RedirectPrinters = {1}" -f $user, $val)
    }
}

# --- 7. Recent updates ---
Sec "RECENT WINDOWS UPDATES (last 7 days)"
$cutoff = (Get-Date).AddDays(-7)
$updates = Get-HotFix | Where-Object { $_.InstalledOn -and $_.InstalledOn -gt $cutoff } | Sort-Object InstalledOn -Descending
if ($updates) { $updates | Select-Object HotFixID, Description, InstalledOn | Format-Table -AutoSize | Out-String | W }
else { W "No hotfixes recorded in last 7 days." }

# --- 8. PrintService event log ---
Sec "PRINTSERVICE ADMIN EVENT LOG (last 15)"
Get-WinEvent -LogName 'Microsoft-Windows-PrintService/Admin' -MaxEvents 15 |
    Select-Object TimeCreated, Id, LevelDisplayName, @{n='Msg';e={ ($_.Message -split "`n")[0] }} |
    Format-Table -AutoSize -Wrap | Out-String | W

W ""
W "===== END Get-RdpPrinterRedirectDiag ====="
