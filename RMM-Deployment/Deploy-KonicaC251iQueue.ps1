<#
.SYNOPSIS
    Idempotent SYSTEM remote session script: remove stale Konica queues for a given IP,
    add a named Konica C251i Universal PCL queue with color enabled.

.DESCRIPTION
    Run via SYSTEM remote session or RMM (SYSTEM context). Designed
    for multi-machine fleet deployment where a printer IP was changed, a duplicate
    queue exists, or the color default was never set.

    Steps:
      1. Remove all printer queues pointing to -PrinterIP that do not match -PrinterName.
      2. Remove and re-add the target queue if it already exists (for clean driver refresh).
      3. Clean up orphaned ports for the IP.
      4. Select best available driver from -DriverPriority list.
      5. Create TCP/IP port if absent.
      6. Add printer queue.
      7. Set color = enabled.
      8. Verify and report.

    Exits 0 on success, 1 on failure. Safe to re-run.

.PARAMETER PrinterIP
    IP address of the Konica MFP. Default: 172.22.56.96.

.PARAMETER PrinterName
    Display name for the printer queue. Default: "KONICA MINOLTA bizhub C251i".

.PARAMETER PortName
    TCP/IP port name. Defaults to "IP_<PrinterIP>".

.PARAMETER DriverPriority
    Ordered list of driver names to try. First match wins.

.NOTES
    Created: 2026-05-29
    Category: RMM-Deployment
    Context: RMM | SYSTEM remote session (SYSTEM, PS 5.1)

.KEYWORDS
    Konica, C251i, printer, queue, color, Universal PCL, RMM, deploy, idempotent
#>
#Requires -Version 5.1

param(
    [string]   $PrinterIP      = '172.22.56.96',
    [string]   $PrinterName    = 'KONICA MINOLTA bizhub C251i',
    [string]   $PortName       = '',
    [string[]] $DriverPriority = @('KONICA MINOLTA Universal PCL', 'KONICA MINOLTA C360iSeriesPCL', 'KONICA MINOLTA Universal V4 PCL')
)

$ErrorActionPreference = 'Stop'

if (-not $PortName) { $PortName = "IP_$PrinterIP" }

Write-Output "===== Deploy-KonicaC251iQueue ====="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Target    : $PrinterName @ $PrinterIP"
Write-Output ""

# --- 1. Remove stale queues pointing to the IP ---
Write-Output "--- Step 1: Remove stale queues for $PrinterIP ---"
$stale = Get-Printer -ErrorAction SilentlyContinue | Where-Object {
    ($_.PortName -like "*$PrinterIP*") -and $_.Name -ne $PrinterName
}
if ($stale) {
    foreach ($p in $stale) {
        try { Remove-Printer -Name $p.Name -ErrorAction Stop; Write-Output "  REMOVED: $($p.Name)" }
        catch { Write-Output "  WARN: Could not remove '$($p.Name)' -- $($_.Exception.Message)" }
    }
} else { Write-Output "  (no stale queues)" }

# Remove + re-add target queue for clean state
$existing = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
if ($existing) {
    try { Remove-Printer -Name $PrinterName -ErrorAction Stop; Write-Output "  REMOVED (clean re-add): $PrinterName" }
    catch { Write-Output "  WARN: Could not remove existing queue -- $($_.Exception.Message)" }
}

# --- 2. Clean orphaned ports ---
Write-Output ""
Write-Output "--- Step 2: Clean orphaned ports for $PrinterIP ---"
$activePrinters = Get-Printer -ErrorAction SilentlyContinue
$oldPorts = Get-PrinterPort -ErrorAction SilentlyContinue |
    Where-Object { $_.PrinterHostAddress -eq $PrinterIP -or $_.Name -like "*$PrinterIP*" }
foreach ($port in $oldPorts) {
    if (-not ($activePrinters | Where-Object { $_.PortName -eq $port.Name })) {
        try { Remove-PrinterPort -Name $port.Name -ErrorAction Stop; Write-Output "  REMOVED PORT: $($port.Name)" }
        catch { Write-Output "  WARN: Could not remove port '$($port.Name)' -- $($_.Exception.Message)" }
    }
}

# --- 3. Select driver ---
Write-Output ""
Write-Output "--- Step 3: Select driver ---"
$installed = Get-PrinterDriver -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$driver = $null
foreach ($d in $DriverPriority) {
    if ($installed -contains $d) { $driver = $d; break }
}
if (-not $driver) {
    Write-Output "ERROR: No compatible driver found. Available Konica drivers:"
    $installed | Where-Object { $_ -match 'KONICA|Minolta' } | ForEach-Object { Write-Output "  $_" }
    exit 1
}
Write-Output "  SELECTED: $driver"

# --- 4. Create port ---
Write-Output ""
Write-Output "--- Step 4: Create port $PortName ---"
if (-not (Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue)) {
    Add-PrinterPort -Name $PortName -PrinterHostAddress $PrinterIP -ErrorAction Stop
    Write-Output "  CREATED: $PortName -> $PrinterIP"
} else {
    Write-Output "  EXISTS: $PortName"
}

# --- 5. Add printer queue ---
Write-Output ""
Write-Output "--- Step 5: Add printer queue ---"
Add-Printer -Name $PrinterName -DriverName $driver -PortName $PortName -ErrorAction Stop
Write-Output "  ADDED: $PrinterName"

# --- 6. Set color ---
Write-Output ""
Write-Output "--- Step 6: Set color default ---"
try {
    Set-PrintConfiguration -PrinterName $PrinterName -Color $true -ErrorAction Stop
    Write-Output "  SET: Color = true"
} catch {
    Write-Output "  WARN: Could not set color preference -- $($_.Exception.Message)"
}

# --- 7. Verify ---
Write-Output ""
Write-Output "--- Step 7: Verify ---"
$final = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
$cfg   = $null
try { $cfg = Get-PrintConfiguration -PrinterName $PrinterName -ErrorAction SilentlyContinue } catch {}

if ($final) {
    Write-Output "  Name    : $($final.Name)"
    Write-Output "  Status  : $($final.PrinterStatus)"
    Write-Output "  Driver  : $($final.DriverName)"
    Write-Output "  Port    : $($final.PortName)"
    Write-Output "  Color   : $(if ($cfg -and $cfg.Color) { 'ENABLED' } else { 'NOT CONFIRMED -- check manually' })"
    Write-Output ""
    Write-Output "===== DONE ====="
    exit 0
} else {
    Write-Output "  ERROR: Printer not found after add"
    exit 1
}
