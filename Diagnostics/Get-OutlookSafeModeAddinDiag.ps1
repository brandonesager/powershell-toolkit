<#
.SYNOPSIS
    Diagnoses Outlook add-in state, crash events, and Office build for safe-mode and add-in issues.

.DESCRIPTION
    Collects the following data from the local endpoint:
      - Office Click-to-Run version and channel
      - Click-to-Run service status
      - Outlook crash events from the Application event log (last 7 days)
      - MSVCP140.dll references in event log (see known issue EX1254044: Office builds
        at or below 16.0.17328.20142 combined with Teams Meeting Add-in >= 1.26.02603
        trigger a safe-mode crash loop via MSVCP140.dll conflict)
      - Logged-on user SID (falls back to most-recently-used profile if no user is logged on)
      - All Outlook COM add-ins from HKCU and HKLM with load-behavior decoding
      - TeamsAddin.FastConnect registration and DLL version
      - Outlook Resiliency registry key and disabled items
      - OST/PST file names and sizes
      - Office Click-to-Run update history

    Read-only. Deploy via RMM (SYSTEM context) or run interactively.

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1, RMM RMM shell)
    Platform: Windows 10/11 with Microsoft 365 (Click-to-Run)
    PS 5.1 compatible.
    Reference: Known issue EX1254044 (MSVCP140.dll / Teams Meeting Add-in mismatch).

.KEYWORDS
    Outlook, safe mode, add-in, COM, MSVCP140, Teams Meeting Add-in, EX1254044,
    resiliency, disabled items, crash, OST, PST, diagnostics
#>
#!ps
#maxlength=100000
#timeout=90000
#Requires -Version 5.1

Write-Output "=== OFFICE VERSION & BUILD ==="
$c2r = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -ErrorAction SilentlyContinue
if ($c2r) {
    Write-Output "Version:  $($c2r.VersionToReport)"
    Write-Output "Channel:  $($c2r.CDNBaseUrl)"
    Write-Output "Platform: $($c2r.Platform)"
    Write-Output "Culture:  $($c2r.ClientCulture)"
    Write-Output "UpdateUrl: $($c2r.UpdateUrl)"
} else {
    Write-Output "Click-to-Run not found; checking MSI install"
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot" -ErrorAction SilentlyContinue
}

Write-Output "`n=== CLICK-TO-RUN SERVICE STATUS ==="
Get-Service "ClickToRunSvc" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-List

Write-Output "`n=== OUTLOOK CRASH EVENTS (LAST 7 DAYS) ==="
$startDate = (Get-Date).AddDays(-7)
$crashEvents = @(Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$startDate} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'OUTLOOK|outlook\.exe|MSVCP140' } |
    Select-Object -First 10)
if ($crashEvents) {
    foreach ($evt in $crashEvents) {
        Write-Output "---"
        Write-Output "Time:    $($evt.TimeCreated)"
        Write-Output "Source:  $($evt.ProviderName)"
        Write-Output "EventID: $($evt.Id)"
        $msg = $evt.Message
        if ($msg.Length -gt 800) { $msg = $msg.Substring(0, 800) + "..." }
        Write-Output "Message: $msg"
    }
} else {
    Write-Output "No Outlook crash events in past 7 days"
}

Write-Output "`n=== MSVCP140.DLL CHECK ==="
# Known issue EX1254044: Office build <= 16.0.17328.20142 + Teams Add-in >= 1.26.02603
# causes safe-mode loop via MSVCP140.dll conflict. Fix: update Office or disable Teams add-in.
$msvcp = @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startDate} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'MSVCP140' } |
    Select-Object -First 5)
if ($msvcp) {
    Write-Output "MSVCP140.dll referenced in $($msvcp.Count) event(s)"
    $msvcp | ForEach-Object { Write-Output "  $($_.TimeCreated) - EventID $($_.Id) - $($_.ProviderName)" }
} else {
    Write-Output "No MSVCP140.dll references found"
}

Write-Output "`n=== USER SID RESOLUTION ==="
$loggedOn = (Get-CimInstance Win32_ComputerSystem).UserName
Write-Output "Logged-on user: $loggedOn"
if ($loggedOn) {
    $sid = (New-Object System.Security.Principal.NTAccount($loggedOn)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    Write-Output "SID: $sid"
} else {
    Write-Output "No user logged on; using last-logged profile"
    $profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -notmatch 'Admin' } |
        Sort-Object LastUseTime -Descending | Select-Object -First 1
    $sid = $profiles.SID
    Write-Output "Profile SID: $sid (Path: $($profiles.LocalPath))"
}

Write-Output "`n=== OUTLOOK COM ADD-INS ==="
$addinPaths = @(
    "Registry::HKU\$sid\Software\Microsoft\Office\Outlook\Addins",
    "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins"
)
foreach ($path in $addinPaths) {
    if (Test-Path $path) {
        Write-Output "--- $path ---"
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $loadBehavior = $props.LoadBehavior
            $friendly = $props.FriendlyName
            $status = switch ($loadBehavior) {
                0 { "Disabled" }
                1 { "Enabled (not loaded)" }
                2 { "Disabled (crashed)" }
                3 { "Enabled (startup)" }
                9 { "Enabled (on demand)" }
                16 { "Enabled (first time)" }
                default { "LoadBehavior=$loadBehavior" }
            }
            Write-Output "  $($_.PSChildName): $friendly [$status]"
        }
    }
}

Write-Output "`n=== TEAMS MEETING ADD-IN DETAIL ==="
$teamsAddin = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -ErrorAction SilentlyContinue
if (-not $teamsAddin) {
    $teamsAddin = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -ErrorAction SilentlyContinue
}
if ($teamsAddin) {
    Write-Output "Found: TeamsAddin.FastConnect"
    Write-Output "LoadBehavior: $($teamsAddin.LoadBehavior)"
    Write-Output "FriendlyName: $($teamsAddin.FriendlyName)"
    $teamsDll = Get-ChildItem "C:\Program Files*\Microsoft\TeamsMeetingAddin\*\x64\Microsoft.Teams.AddinLoader.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($teamsDll) {
        Write-Output "DLL Path: $($teamsDll.FullName)"
        Write-Output "DLL Version: $($teamsDll.VersionInfo.FileVersion)"
    }
} else {
    Write-Output "TeamsAddin.FastConnect not registered"
}

Write-Output "`n=== OUTLOOK RESILIENCY KEY ==="
$resiliencyPath = "Registry::HKU\$sid\Software\Microsoft\Office\16.0\Outlook\Resiliency"
if (Test-Path $resiliencyPath) {
    Write-Output "Resiliency key EXISTS"
    Get-ChildItem $resiliencyPath -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  Subkey: $($_.PSChildName)"
        $_.GetValueNames() | ForEach-Object {
            Write-Output "    $_"
        }
    }
} else {
    Write-Output "Resiliency key does not exist (clean state)"
}

Write-Output "`n=== OUTLOOK DISABLED ITEMS ==="
$disabledPath = "Registry::HKU\$sid\Software\Microsoft\Office\16.0\Outlook\Resiliency\DisabledItems"
if (Test-Path $disabledPath) {
    $disabled = Get-ItemProperty $disabledPath -ErrorAction SilentlyContinue
    $disabled.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Output "  $($_.Name): $($_.Value)"
    }
} else {
    Write-Output "No disabled items key"
}

Write-Output "`n=== OST/PST FILES ==="
if ($sid) {
    $profile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    $outlookDataPath = Join-Path $profile "AppData\Local\Microsoft\Outlook"
    if (Test-Path $outlookDataPath) {
        Get-ChildItem $outlookDataPath -Filter "*.ost" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "OST: $($_.Name) | Size: $([math]::Round($_.Length/1MB, 1)) MB | Modified: $($_.LastWriteTime)"
        }
        Get-ChildItem $outlookDataPath -Filter "*.pst" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "PST: $($_.Name) | Size: $([math]::Round($_.Length/1MB, 1)) MB | Modified: $($_.LastWriteTime)"
        }
    } else {
        Write-Output "Outlook data path not found at $outlookDataPath"
    }
} else {
    Write-Output "Cannot resolve user profile path"
}

Write-Output "`n=== OFFICE UPDATE HISTORY (LAST 3) ==="
$updatePath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Updates"
if (Test-Path $updatePath) {
    Get-ItemProperty $updatePath -ErrorAction SilentlyContinue | Format-List
} else {
    Write-Output "No update history key"
}

Write-Output "`n=== SUMMARY ==="
Write-Output "Hostname: $env:COMPUTERNAME"
Write-Output "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
if ($c2r) { Write-Output "Office Build: $($c2r.VersionToReport)" }
Write-Output "EX1254044 check: build <= 16.0.17328.20142 + Teams Add-in >= 1.26.02603 = safe-mode loop."
Write-Output "Fix: update Office via Word > File > Account > Update Now, or disable the Teams Meeting Add-in."
