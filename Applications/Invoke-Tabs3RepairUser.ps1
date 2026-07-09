<#
.SYNOPSIS
    Tabs3 diagnostic and repair for Contoso — user-context (Interact tab).

.DESCRIPTION
    Diagnoses and repairs a gutted Tabs3 local installation from an elevated user session
    (interactive remote session tab, Run as Administrator). Checks share connectivity, inspects
    local install state, copies t3lclcfg.dat if missing, renames stfirm.dat, and runs
    setup.exe under the current user's identity for correct shortcut creation.

    This is the primary repair script. Use Get-Tabs3RepairAsSystem.ps1 only for initial
    diagnostics — setup.exe must run as the end user to avoid exit code 2010.

.NOTES
    Context:    Interact tab (user-elevated) — PS 5.1
    Tab server: SERVER01 — set per the site's documentation (share path)
#>

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Elevation check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "NOT ELEVATED -- re-run as Administrator" -ForegroundColor Red
    return
}

# --- Check Tabs3 processes ---
$tabs3Procs = @('tabs3', 'practicemaster', 'pm', 'tabs3billing', 'stisvc')
$running    = @(Get-Process -Name $tabs3Procs -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host "Tabs3 processes running:" -ForegroundColor Yellow
    $running | ForEach-Object { Write-Host "  $($_.ProcessName) (PID $($_.Id))" }
    Write-Host "Ask user to close all Tabs3 products before proceeding."
    return
}
Write-Host "No Tabs3 processes running." -ForegroundColor Green

# --- Network connectivity ---
# Update $tabsShare to match the client's Tabs3 server (see site docs)
$tabsShare = '\\SERVER01\Tabs3'
if (Test-Path $tabsShare) {
    Write-Host "Share accessible: $tabsShare" -ForegroundColor Green
} else {
    Write-Host "Cannot access $tabsShare -- check network connectivity." -ForegroundColor Red
    return
}

# --- Local install state ---
$tabs3Local = 'C:\Program Files (x86)\Tabs3'
Write-Host "`n=== Local Installation ==="
if (-not (Test-Path $tabs3Local)) {
    Write-Host "Install directory MISSING: $tabs3Local" -ForegroundColor Red
    Write-Host "Full install needed: right-click $tabsShare\setup.exe > Run as Administrator"
    return
}

foreach ($f in @('t3lclcfg.dat', 'stfirm.dat', 'setup.exe', 'tabs3.exe')) {
    $fp = Join-Path $tabs3Local $f
    if (Test-Path $fp) {
        $fi = Get-Item $fp
        Write-Host "  FOUND: $f ($([math]::Round($fi.Length / 1KB, 1)) KB, $($fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor Green
    } else {
        Write-Host "  MISSING: $f" -ForegroundColor Yellow
    }
}

# --- Desktop shortcuts ---
Write-Host "`n=== Shortcuts ==="
$shell = New-Object -ComObject WScript.Shell
foreach ($desk in @("$env:USERPROFILE\Desktop", 'C:\Users\Public\Desktop')) {
    $lnks  = @(Get-ChildItem -Path $desk -Filter '*tabs*'    -EA SilentlyContinue)
    $lnks += @(Get-ChildItem -Path $desk -Filter '*practice*' -EA SilentlyContinue)
    if ($lnks.Count -gt 0) {
        foreach ($lnk in $lnks) {
            $sc = $shell.CreateShortcut($lnk.FullName)
            Write-Host "  $($lnk.Name) -> $($sc.TargetPath)"
        }
    } else {
        Write-Host "  $desk : none"
    }
}

# --- Repair ---
Write-Host "`n=== Repairs ==="

# 1. t3lclcfg.dat
$localCfg  = Join-Path $tabs3Local 't3lclcfg.dat'
$serverCfg = Join-Path $tabsShare  't3lclcfg.dat'
if (-not (Test-Path $localCfg)) {
    if (Test-Path $serverCfg) {
        Copy-Item -Path $serverCfg -Destination $localCfg -Force
        Write-Host "Copied t3lclcfg.dat from server" -ForegroundColor Green
    } else {
        Write-Host "t3lclcfg.dat not on server -- check site docs for backup source" -ForegroundColor Yellow
    }
} else {
    Write-Host "t3lclcfg.dat present -- skip"
}

# 2. stfirm.dat rename
$stfirm = Join-Path $tabs3Local 'stfirm.dat'
if (Test-Path $stfirm) {
    Rename-Item -Path $stfirm -NewName 'stfirm.OLD' -Force
    Write-Host "Renamed stfirm.dat -> stfirm.OLD" -ForegroundColor Green
} else {
    Write-Host "stfirm.dat absent -- skip"
}

# 3. Run setup from server as current (elevated) user
#    Running as the end user ensures shortcut creation and profile registration succeed.
#    If exit code 2010 appears here, ensure the user has local admin rights and retry.
$setupExe = Join-Path $tabsShare 'setup.exe'
if (Test-Path $setupExe) {
    Write-Host "Running setup.exe from $tabsShare (user context)..."
    $proc = Start-Process -FilePath $setupExe -Wait -PassThru
    Write-Host "Setup exit code: $($proc.ExitCode)"
    if ($proc.ExitCode -eq 2010) {
        Write-Host "EXIT 2010 -- verify user has local admin rights, then retry." -ForegroundColor Red
        Write-Host "Add user: Add-LocalGroupMember -Group Administrators -Member '{DOMAIN}\{username}'"
    }
} else {
    Write-Host "setup.exe not found at $setupExe" -ForegroundColor Red
}

# --- Verify ---
Write-Host "`n=== Verification ==="
$ok = $true
foreach ($f in @('tabs3.exe', 't3lclcfg.dat')) {
    $fp = Join-Path $tabs3Local $f
    if (Test-Path $fp) {
        Write-Host "  OK: $f" -ForegroundColor Green
    } else {
        Write-Host "  MISSING: $f" -ForegroundColor Red
        $ok = $false
    }
}

if ($ok) {
    Write-Host "`nDone. Have user launch Tabs3 -- verify Billing, GL, AP icons visible."
    Write-Host "Remember to remove user from local Administrators if added for this repair."
    Write-Host "  Remove-LocalGroupMember -Group Administrators -Member '{DOMAIN}\{username}'"
} else {
    Write-Host "`nStill broken. Try: Help > About Tabs3 Billing > Open CWD > run setup.exe"
    Write-Host "Or escalate to vendor -- contact in the site's vendor documentation."
}
