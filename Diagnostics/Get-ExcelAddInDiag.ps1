<#
.SYNOPSIS
    Diagnoses Excel COM add-ins, hardware acceleration, MPO status, and AV process load.

.DESCRIPTION
    Collects the following from the local endpoint:
      - Office Click-to-Run version and channel
      - Excel COM add-ins from HKLM and all HKCU hives (with load-behavior decoding)
      - Per-user hardware acceleration setting (DisableHardwareAcceleration)
      - Multi-Plane Overlay (OverlayTestMode) registry value
      - Installed printer drivers (for print-to-black-screen diagnosis)
      - XLSTART folder contents for each user profile
      - Running security/AV processes (generic check, not limited to one vendor)

    Read-only. Run as SYSTEM via RMM shell for full HKCU coverage.

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1)
    Platform: Windows 10/11 with Microsoft 365 (Click-to-Run)
    PS 5.1 compatible.

.KEYWORDS
    Excel, hang, freeze, COM add-ins, hardware acceleration, MPO, XLSTART, AV, diagnostics
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

Write-Output "=== OFFICE VERSION ==="
$c2r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
if ($c2r) {
    Write-Output "Channel:  $($c2r.CDNBaseUrl -replace '.*/', '')"
    Write-Output "Version:  $($c2r.VersionToReport)"
    Write-Output "Platform: $($c2r.Platform)"
    Write-Output "Update:   $($c2r.UpdateChannel)"
} else {
    Write-Output "ClickToRun not found"
}

Write-Output "`n=== EXCEL COM ADD-INS (HKLM) ==="
$hklmPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Excel\Addins'
)
foreach ($p in $hklmPaths) {
    if (Test-Path $p) {
        Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
            $props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $loaded = switch ($props.LoadBehavior) {
                3 { "Auto-load" }
                2 { "Load at startup" }
                default { "LoadBehavior=$($props.LoadBehavior)" }
            }
            Write-Output "  $($_.PSChildName) [$loaded] - $($props.Description)"
        }
    }
}

Write-Output "`n=== EXCEL COM ADD-INS (HKCU - all user hives) ==="
if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}
$userSIDs = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21.*[^_]$' }
foreach ($sid in $userSIDs) {
    $addinPath = "HKU:\$($sid.PSChildName)\SOFTWARE\Microsoft\Office\Excel\Addins"
    if (Test-Path $addinPath) {
        Get-ChildItem $addinPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $loaded = switch ($props.LoadBehavior) {
                3 { "Auto-load" }
                2 { "Load at startup" }
                default { "LoadBehavior=$($props.LoadBehavior)" }
            }
            Write-Output "  $($_.PSChildName) [$loaded] - $($props.Description)"
        }
    }
}

Write-Output "`n=== HARDWARE ACCELERATION (Excel) ==="
foreach ($sid in $userSIDs) {
    $gfxPath = "HKU:\$($sid.PSChildName)\SOFTWARE\Microsoft\Office\16.0\Common\Graphics"
    if (Test-Path $gfxPath) {
        $disableHW = (Get-ItemProperty $gfxPath -Name 'DisableHardwareAcceleration' -ErrorAction SilentlyContinue).DisableHardwareAcceleration
        Write-Output "$($sid.PSChildName): DisableHardwareAcceleration = $disableHW (1=disabled, 0 or missing=enabled)"
    } else {
        Write-Output "$($sid.PSChildName): Graphics key not found - hardware acceleration is ENABLED (default)"
    }
}

Write-Output "`n=== MULTI-PLANE OVERLAY (MPO) STATUS ==="
$mpo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' -Name 'OverlayTestMode' -ErrorAction SilentlyContinue
if ($mpo) {
    Write-Output "OverlayTestMode: $($mpo.OverlayTestMode) (5=MPO disabled)"
} else {
    Write-Output "OverlayTestMode not set - MPO is ENABLED (default)"
}

Write-Output "`n=== PRINTER DRIVERS ==="
Get-PrinterDriver -ErrorAction SilentlyContinue |
    Select-Object Name, MajorVersion, PrinterEnvironment | Format-Table -AutoSize

Write-Output "`n=== XLSTART FOLDER ==="
$users = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch 'Public|Default|admin' }
foreach ($u in $users) {
    $xlstart = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Excel\XLSTART'
    if (Test-Path $xlstart) {
        $files = Get-ChildItem $xlstart -ErrorAction SilentlyContinue
        if ($files) { Write-Output "$($u.Name): $($files.Name -join ', ')" }
        else         { Write-Output "$($u.Name): (empty)" }
    }
}

Write-Output "`n=== SECURITY / AV PROCESSES ==="
# Generic check for security/AV processes that may interact with Office file access.
# Common vendors: SentinelOne (Sentinel*), Cylance (Cylance*), CrowdStrike (Cs*),
# Defender (MsMpEng), Carbon Black (cb*), Sophos (Sophos*), Trend Micro (Trend*).
$avPatterns = @('Sentinel*','Cylance*','CsAgent*','MsMpEng','cbdefense*','Sophos*','TmListen*','csc_*')
$avProcs = @()
foreach ($p in $avPatterns) {
    $avProcs += Get-Process -Name $p -ErrorAction SilentlyContinue
}
if ($avProcs) {
    $avProcs | Select-Object Name, Id,
        @{N='CPU_s';E={[math]::Round($_.CPU,1)}},
        @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,0)}} |
        Format-Table -AutoSize
} else {
    Write-Output "No recognized AV/EDR processes found."
}
