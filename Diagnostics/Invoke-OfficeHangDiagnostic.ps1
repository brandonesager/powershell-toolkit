#!ps
#maxlength=100000
#timeout=300000

# Invoke-OfficeHangDiagnostic.ps1
# Read-only triage for the Excel/Office symptom cluster: app freezes, renders a
# black/blank screen, and/or cannot print. One pass covers every common root cause
# so a single RMM shell run tells you which fix to stage. Context: remote support session
# RMM shell (SYSTEM, PS 5.1). Plain-text output. NO writes.
#
# Causes covered (with the symptom each explains):
#   1. Default printer offline/unreachable  -> hang on launch/print + print failure
#      (Excel polls the default printer for page metrics; a dead net printer blocks the UI thread)
#   2. Office hardware graphics acceleration -> black/blank panes, black redraw
#   3. Display adapter driver + dock (DisplayLink) driver + MPO (Multiplane Overlay) -> black screen
#   4. Excel COM add-ins (e.g. Adobe PDFMaker) -> freeze
#   5. Stale Office identity/auth cache       -> freeze on cloud/synced-folder open only
# Resolves the logged-in user's SID first so per-user hives read correctly under SYSTEM.

# ---------- Resolve logged-in user + SID ----------
$csUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
if ($csUser) {
    $ntAccount = $csUser
    $localUser = $csUser.Split('\')[-1]
} else {
    # Get-WmiObject (not Get-CimInstance) is required here: .GetOwner() is a WMI method
    # present on ManagementObject, absent on CimInstance.
    $expl = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($expl) { $o = $expl.GetOwner(); $ntAccount = "$($o.Domain)\$($o.User)"; $localUser = $o.User }
}
if (-not $localUser) { Write-Output "ERROR: No interactive user detected -- is a user logged in?"; return }

try {
    $sid = (New-Object Security.Principal.NTAccount($ntAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    $sid = (Get-ChildItem 'Registry::HKEY_USERS' |
        Where-Object { $_.PSChildName -match 'S-1-5-21' -and $_.PSChildName -notmatch '_Classes' } |
        Select-Object -ExpandProperty PSChildName -First 1)
}
$profReg = "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
$userProfile = if ($sid -and (Test-Path $profReg)) { (Get-ItemProperty $profReg).ProfileImagePath } else { "C:\Users\$localUser" }

if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

Write-Output "=== LOGGED-IN USER ==="
Write-Output "Account: $ntAccount"
Write-Output "SID:     $sid"
Write-Output "Profile: $userProfile"

# ---------- 1. PRINTING SUBSYSTEM (top suspect for hang + can't-print) ----------
Write-Output ""
Write-Output "=== PRINT: SPOOLER SERVICE ==="
$sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($sp) { Write-Output "  Spooler: $($sp.Status) / StartType $($sp.StartType)" } else { Write-Output "  Spooler: NOT FOUND" }

Write-Output ""
Write-Output "=== PRINT: PER-USER DEFAULT PRINTER ==="
$winKey = "HKU:\$sid\Software\Microsoft\Windows NT\CurrentVersion\Windows"
if (Test-Path $winKey) {
    $dev = (Get-ItemProperty $winKey -ErrorAction SilentlyContinue).Device
    $legacy = (Get-ItemProperty $winKey -ErrorAction SilentlyContinue).LegacyDefaultPrinterMode
    Write-Output "  Default (HKU Device): $dev"
    # LegacyDefaultPrinterMode=1 means user-managed default; absent/0 means 'Let Windows manage default printer' is ON
    if ($legacy -eq 1) { Write-Output "  'Let Windows manage default printer': OFF (user-managed)" }
    else { Write-Output "  'Let Windows manage default printer': ON (Windows may switch default to last-used / offline printer)" }
} else { Write-Output "  HKU Windows key not found" }

Write-Output ""
Write-Output "=== PRINT: ALL PRINTERS + STATUS (offline = prime suspect) ==="
$prn = Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue
if ($prn) {
    foreach ($pr in $prn) {
        $statusMap = @{1='Other';2='Unknown';3='Idle';4='Printing';5='Warmup';6='Stopped';7='Offline'}
        $ps = $statusMap[[int]$pr.PrinterStatus]; if (-not $ps) { $ps = $pr.PrinterStatus }
        $flag = if ($pr.WorkOffline -or [int]$pr.PrinterStatus -eq 7) { '  <-- OFFLINE' } else { '' }
        $def  = if ($pr.Default) { '[DEFAULT] ' } else { '' }
        Write-Output ("  {0}{1} | status={2} | WorkOffline={3} | net={4}{5}" -f $def,$pr.Name,$ps,$pr.WorkOffline,$pr.Network,$flag)
    }
} else { Write-Output "  No printers enumerated (SYSTEM context may hide per-user net printers; cross-check HKU Device above)" }

# ---------- 2. HARDWARE GRAPHICS ACCELERATION (black-screen suspect) ----------
Write-Output ""
Write-Output "=== OFFICE GRAPHICS / HARDWARE ACCELERATION ==="
$gfx = "HKU:\$sid\Software\Microsoft\Office\16.0\Common\Graphics"
if (Test-Path $gfx) {
    $dha = (Get-ItemProperty $gfx -ErrorAction SilentlyContinue).DisableHardwareAcceleration
    Write-Output "  DisableHardwareAcceleration = $dha  (1=disabled/good for black screen, 0 or absent=HW accel ON)"
} else { Write-Output "  Graphics key absent -> HW acceleration is ON (default). Black-screen candidate." }
$gfxPol = "HKU:\$sid\Software\Policies\Microsoft\office\16.0\common\graphics"
if (Test-Path $gfxPol) {
    $dhaPol = (Get-ItemProperty $gfxPol -ErrorAction SilentlyContinue).disablehardwareacceleration
    Write-Output "  (Policy) disablehardwareacceleration = $dhaPol"
}

# ---------- 3. DISPLAY ADAPTER + DOCK DRIVER + MPO (black-screen suspects) ----------
Write-Output ""
Write-Output "=== DISPLAY ADAPTER DRIVER ==="
Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output ("  {0} | driver {1} | date {2}" -f $_.Name,$_.DriverVersion,$_.DriverDate)
}

Write-Output ""
Write-Output "=== DISPLAYLINK DOCK DRIVER (Win11 24H2/25H2 needs current build; pre-12.1 known to black-screen) ==="
$dl = Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceName LIKE '%DisplayLink%'" -ErrorAction SilentlyContinue
if ($dl) { $dl | ForEach-Object { Write-Output ("  {0} | driver {1} | date {2}" -f $_.DeviceName,$_.DriverVersion,$_.DriverDate) } }
else { Write-Output "  No DisplayLink device bound (dock may be undocked or uses native DP/HDMI)" }
$dlApp = Get-ItemProperty 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                          'Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like '*DisplayLink*' } | Select-Object -First 1
if ($dlApp) { Write-Output "  DisplayLink app: $($dlApp.DisplayName) $($dlApp.DisplayVersion)" }

Write-Output ""
Write-Output "=== MPO (Multiplane Overlay) -- DWM black screen on Win11 24H2/25H2 ==="
$dwm = "Registry::HKLM\SOFTWARE\Microsoft\Windows\Dwm"
$omt = (Get-ItemProperty $dwm -ErrorAction SilentlyContinue).OverlayTestMode
if ($omt -eq 5) { Write-Output "  OverlayTestMode = 5 (MPO already DISABLED)" }
else { Write-Output "  OverlayTestMode = $omt (MPO ENABLED -- black-screen candidate; workaround sets this to 5, then reboot)" }

Write-Output ""
Write-Output "=== NETWORK / SUBNET PLACEMENT (direct-IP printers + cloud-folder mounts depend on correct subnet) ==="
Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address } | ForEach-Object {
    $gw = ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop
    Write-Output ("  {0} | IPv4 {1} | GW {2}" -f $_.InterfaceAlias,($_.IPv4Address.IPAddress -join ','),$gw)
}
Write-Output "  (If the site uses direct-IP print queues with no print server, an off-subnet dock/VLAN breaks print AND synced-folder access at once.)"

# ---------- 4. EXCEL COM ADD-INS (freeze suspect) ----------
Write-Output ""
Write-Output "=== EXCEL COM ADD-INS (LoadBehavior 3 = active; PDFMaker is a common freeze culprit) ==="
$addinRoots = @(
    "HKU:\$sid\Software\Microsoft\Office\Excel\Addins",
    "Registry::HKLM\SOFTWARE\Microsoft\Office\Excel\Addins",
    "Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\Excel\Addins"
)
$foundAddin = $false
foreach ($root in $addinRoots) {
    if (Test-Path $root) {
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $lb = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).LoadBehavior
            $flag = if ($_.PSChildName -match 'PDFMaker|Acrobat|PDFM') { '  <-- Adobe PDFMaker (common freeze culprit; disable to test)' } else { '' }
            Write-Output ("  {0} | LoadBehavior={1} | {2}{3}" -f $_.PSChildName,$lb,($root -replace 'Registry::',''),$flag)
            $foundAddin = $true
        }
    }
}
if (-not $foundAddin) { Write-Output "  No COM add-ins registered" }

# ---------- 5. PROCESS STATE ----------
Write-Output ""
Write-Output "=== EXCEL PROCESS STATE ==="
$excel = Get-Process -Name EXCEL -ErrorAction SilentlyContinue
if ($excel) { $excel | Select-Object Id,@{n='WS_MB';e={[math]::Round($_.WS/1MB,1)}},Responding | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Output $_ } }
else { Write-Output "  Excel.exe: not running" }
Write-Output "=== SYNC-CLIENT PROCESS STATE (OneDrive / Egnyte / etc.) ==="
$sync = Get-Process -Name egnyte*, OneDrive, Dropbox -ErrorAction SilentlyContinue
if ($sync) { $sync | Select-Object Name,Id,Responding | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Output $_ } }
else { Write-Output "  No sync client process running" }

# ---------- 6. OFFICE AUTH CACHE (freeze-on-cloud-open pattern) ----------
Write-Output ""
Write-Output "=== OFFICE AUTH CACHE STATUS ==="
$cachePaths = [ordered]@{
    'WAM-AAD'       = "$userProfile\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts"
    'OfficeLicense' = "$userProfile\AppData\Local\Microsoft\Office\Licensing"
    'OneAuth'       = "$userProfile\AppData\Local\Microsoft\OneAuth"
    'IdentityCache' = "$userProfile\AppData\Local\Microsoft\IdentityCache"
}
foreach ($key in $cachePaths.Keys) {
    $p = $cachePaths[$key]
    if (Test-Path $p) {
        $n = (Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Output "  PRESENT  $key -- $n items"
    } else { Write-Output "  ABSENT   $key" }
}
$idKey = "HKU:\$sid\Software\Microsoft\Office\16.0\Common\Identity"
if (Test-Path $idKey) { Write-Output "  PRESENT  HKU Office Identity key" } else { Write-Output "  ABSENT   HKU Office Identity key" }

# ---------- 7. OFFICE BUILD ----------
Write-Output ""
Write-Output "=== OFFICE BUILD ==="
$cfg = "Registry::HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
if (Test-Path $cfg) {
    $c = Get-ItemProperty $cfg -ErrorAction SilentlyContinue
    Write-Output ("  {0} | {1} | {2}" -f $c.ProductReleaseIds,$c.VersionToReport,$c.CDNBaseUrl)
}

Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue
Write-Output ""
Write-Output "=== DIAG COMPLETE ==="
