<#
.SYNOPSIS
    Tabs3 diagnostic and repair for Contoso — SYSTEM remote session (SYSTEM) context.

.DESCRIPTION
    Diagnoses and repairs a gutted Tabs3 local installation from SYSTEM remote session (SYSTEM/PS 5.1).
    Detects the logged-in user, checks share connectivity, inspects local install state,
    copies t3lclcfg.dat if missing, renames stfirm.dat, and runs setup.exe from the server share.

    NOTE: setup.exe running as SYSTEM will produce exit code 2010 if the share is inaccessible
    to the computer account or if shortcut creation requires user-context. If setup fails here,
    switch to Invoke-Tabs3RepairUser.ps1 (Interact tab, elevated user session).

.NOTES
    Context:    SYSTEM remote session (SYSTEM) — PS 5.1
    Tab server: SERVER01 — set per the site's documentation (IP and share path)
#>

# --- Resolve logged-in user ---
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $user) { Write-Host "ERROR: No logged-in user detected"; return }
$username = $user.Split('\')[-1]
$domain   = $user.Split('\')[0]
Write-Host "Logged-in user: $user"

$sid         = (New-Object System.Security.Principal.NTAccount($domain, $username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$userProfile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
Write-Host "User profile: $userProfile"

# --- Check if Tabs3 processes are running ---
$tabs3Procs = @('tabs3', 'practicemaster', 'pm', 'tabs3billing', 'stisvc')
$running    = @(Get-Process -Name $tabs3Procs -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host "WARNING: Tabs3 processes running:"
    $running | ForEach-Object { Write-Host "  $($_.ProcessName) (PID $($_.Id))" }
    Write-Host "Cannot proceed with repair while Tabs3 is open. Ask user to close all Tabs3 products."
    return
}
Write-Host "No Tabs3 processes running — safe to proceed."

# --- Network connectivity to Tabs server ---
# Update $tabsServer and $tabsShare to match the client's Tabs3 server (see site docs)
$tabsServer = 'SERVER01'
$tabsShare  = '\\SERVER01\Tabs3'
try {
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $tcp.Connect($tabsServer, 445)
    Write-Host "SMB connectivity to Tabs server ($tabsServer): OK"
    $tcp.Close()
} catch {
    Write-Host "ERROR: Cannot reach Tabs server on port 445. Check network/VPN."
    return
}

# --- Check share accessibility (SYSTEM = computer account) ---
if (Test-Path $tabsShare) {
    Write-Host "Share accessible: $tabsShare"
} else {
    Write-Host "ERROR: Cannot access $tabsShare as SYSTEM (computer account)."
    Write-Host "Switch to Invoke-Tabs3RepairUser.ps1 (Interact tab) instead."
    return
}

# --- Inspect local Tabs3 installation ---
$tabs3Local = 'C:\Program Files (x86)\Tabs3'
Write-Host "`n=== Local Installation State ==="

if (Test-Path $tabs3Local) {
    Write-Host "Install directory: $tabs3Local"
    foreach ($f in @('t3lclcfg.dat', 'stfirm.dat', 'setup.exe', 'tabs3.exe')) {
        $fp = Join-Path $tabs3Local $f
        if (Test-Path $fp) {
            $fi = Get-Item $fp
            Write-Host "  FOUND: $f ($([math]::Round($fi.Length / 1KB, 1)) KB, modified $($fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
        } else {
            Write-Host "  MISSING: $f"
        }
    }
} else {
    Write-Host "Install directory MISSING: $tabs3Local"
    Write-Host "Full reinstall required — switch to Interact (user context) for shortcut creation."
    return
}

# --- Check desktop shortcuts ---
$userDesktop   = Join-Path $userProfile 'Desktop'
$publicDesktop = 'C:\Users\Public\Desktop'
Write-Host "`n=== Desktop Shortcuts ==="
$shell = New-Object -ComObject WScript.Shell
foreach ($desk in @($userDesktop, $publicDesktop)) {
    $lnks  = @(Get-ChildItem -Path $desk -Filter '*tabs*'    -ErrorAction SilentlyContinue)
    $lnks += @(Get-ChildItem -Path $desk -Filter '*practice*' -ErrorAction SilentlyContinue)
    if ($lnks.Count -gt 0) {
        Write-Host "  $desk :"
        foreach ($lnk in $lnks) {
            $sc = $shell.CreateShortcut($lnk.FullName)
            Write-Host "    $($lnk.Name) -> $($sc.TargetPath)"
        }
    } else {
        Write-Host "  $desk : no Tabs3 shortcuts found"
    }
}

# --- Repair: t3lclcfg.dat ---
Write-Host "`n=== Repair Steps ==="
$localCfg  = Join-Path $tabs3Local 't3lclcfg.dat'
$serverCfg = Join-Path $tabsShare  't3lclcfg.dat'

if (-not (Test-Path $localCfg)) {
    if (Test-Path $serverCfg) {
        Copy-Item -Path $serverCfg -Destination $localCfg -Force
        Write-Host "REPAIRED: Copied t3lclcfg.dat from server share"
    } else {
        Write-Host "WARNING: t3lclcfg.dat not found on server share — check site docs for backup source"
    }
} else {
    Write-Host "t3lclcfg.dat present locally — skipping copy"
}

# --- Repair: rename stfirm.dat ---
$stfirm = Join-Path $tabs3Local 'stfirm.dat'
if (Test-Path $stfirm) {
    Rename-Item -Path $stfirm -NewName 'stfirm.OLD' -Force
    Write-Host "REPAIRED: Renamed stfirm.dat -> stfirm.OLD"
} else {
    Write-Host "stfirm.dat not present — no rename needed"
}

# --- Repair: run setup.exe from server share ---
$setupExe = Join-Path $tabsShare 'setup.exe'
if (Test-Path $setupExe) {
    Write-Host "Running setup.exe from server share (SYSTEM context)..."
    Write-Host "NOTE: If exit code is 2010, rerun from Interact tab (user context) instead."
    $proc = Start-Process -FilePath $setupExe -ArgumentList '/S' -Wait -PassThru -NoNewWindow
    Write-Host "Setup exit code: $($proc.ExitCode)"
    if ($proc.ExitCode -eq 2010) {
        Write-Host "EXIT 2010 — setup requires user context. Switch to Invoke-Tabs3RepairUser.ps1."
    }
} else {
    Write-Host "ERROR: setup.exe not found at $setupExe"
}

# --- Post-repair verification ---
Write-Host "`n=== Post-Repair Verification ==="
$allGood = $true
foreach ($f in @('tabs3.exe', 't3lclcfg.dat')) {
    $fp = Join-Path $tabs3Local $f
    if (Test-Path $fp) {
        Write-Host "  OK: $f present"
    } else {
        Write-Host "  FAIL: $f still missing"
        $allGood = $false
    }
}

if (Test-Path $stfirm) {
    Write-Host "  NOTE: stfirm.dat recreated by setup — expected behavior"
}

if ($allGood) {
    Write-Host "`nRepair complete. Ask user to launch Tabs3 and verify all icons (Billing, GL, AP) visible."
} else {
    Write-Host "`nRepair incomplete — switch to Invoke-Tabs3RepairUser.ps1 (user context)."
}
