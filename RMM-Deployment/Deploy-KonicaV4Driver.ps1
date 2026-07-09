<#
.SYNOPSIS
    Stage Konica Universal V4 PCL driver from remote support tooling Files, install via
    pnputil, create TCP/IP port, remove stale V3 queue, and add named printer queue.

.DESCRIPTION
    Designed for new MFP deployments or driver upgrades where a V4 Universal PCL
    driver is needed and must be staged from the remote support tooling file transfer area.

    Steps:
      1. Locate the driver ZIP under the remote support tooling SystemTemp staging path.
      2. Extract to C:\Temp\KonicaV4Driver.
      3. Find the x64 PCL6 INF and install via pnputil /add-driver.
      4. Validate driver registration in the print spooler.
      5. Create TCP/IP port if absent.
      6. Remove stale queue on the same port (old V3 or wrong-name queue).
      7. Add new printer queue.
      8. Verify and report.

    Exits 0 on success, 1 on failure. Safe to re-run (idempotent port/queue checks).

.PARAMETER ZipName
    Filename of the Konica driver ZIP to locate. Case-insensitive search.
    Default: "KM_v4UPD_UniversalDriver_PCL_2.9.0.4.zip".

.PARAMETER MfpIp
    IP address of the MFP. Required; no default.

.PARAMETER PrinterName
    Display name for the printer queue.

.PARAMETER DriverName
    Exact driver name string as it appears in the INF / driver store.
    Default: "KONICA MINOLTA Universal V4 PCL".

.NOTES
    Created: 2026-05-29
    Category: RMM-Deployment
    Context: RMM | SYSTEM remote session (SYSTEM, PS 5.1)

.KEYWORDS
    Konica, V4, Universal PCL, pnputil, driver, printer, deploy, RMM, TCP/IP port
#>
#Requires -Version 5.1

param(
    [string]$ZipName    = 'KM_v4UPD_UniversalDriver_PCL_2.9.0.4.zip',
    [Parameter(Mandatory)]
    [string]$MfpIp,
    [Parameter(Mandatory)]
    [string]$PrinterName,
    [string]$DriverName = 'KONICA MINOLTA Universal V4 PCL'
)

$ErrorActionPreference = 'Stop'
$PortName    = "IP_$MfpIp"
$ExtractRoot = 'C:\Temp\KonicaV4Driver'

Write-Output "===== Deploy-KonicaV4Driver ====="
Write-Output "Computer    : $env:COMPUTERNAME"
Write-Output "Timestamp   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "MFP IP      : $MfpIp"
Write-Output "Printer     : $PrinterName"
Write-Output "Driver      : $DriverName"
Write-Output ""

# --- 1. Locate ZIP ---
Write-Output "--- Step 1: Locate driver ZIP ---"
$zip = Get-ChildItem 'C:\Windows\SystemTemp\remote support tooling' -Filter $ZipName -Recurse -ErrorAction SilentlyContinue |
       Select-Object -First 1
if (-not $zip) {
    Write-Output "FAILED: $ZipName not found under C:\Windows\SystemTemp\remote support tooling"
    Write-Output "Upload the ZIP via SC Files tab before running this script."
    exit 1
}
Write-Output "ZIP found: $($zip.FullName)"

# --- 2. Extract ---
Write-Output ""
Write-Output "--- Step 2: Extract ---"
if (Test-Path $ExtractRoot) { Remove-Item $ExtractRoot -Recurse -Force }
Expand-Archive -Path $zip.FullName -DestinationPath $ExtractRoot -Force
Write-Output "Extracted to: $ExtractRoot"

# --- 3. Find x64 PCL6 INF ---
Write-Output ""
Write-Output "--- Step 3: Find x64 PCL6 INF ---"
$inf = @(Get-ChildItem -Path $ExtractRoot -Filter '*.inf' -Recurse |
         Where-Object { $_.FullName -match 'x64.PCL6' -or $_.FullName -match 'x64.PCL' })
if ($inf.Count -eq 0) {
    Write-Output "FAILED: No x64 PCL6 INF found. Contents:"
    Get-ChildItem $ExtractRoot -Recurse -Name | ForEach-Object { Write-Output "  $_" }
    exit 1
}
$infPath = $inf[0].FullName
Write-Output "INF: $infPath"

# --- 4. Install via pnputil ---
Write-Output ""
Write-Output "--- Step 4: pnputil /add-driver ---"
$pnp = pnputil /add-driver $infPath /install 2>&1
Write-Output ($pnp -join ' ')

# Validate
$check = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
if (-not $check) {
    Add-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
    $check = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
}
if (-not $check) {
    Write-Output "FAILED: Driver '$DriverName' not in print spooler after pnputil."
    Write-Output "Available Konica drivers:"
    Get-PrinterDriver | Where-Object { $_.Name -match 'KONICA|Minolta' } | ForEach-Object { Write-Output "  $_" }
    exit 1
}
Write-Output "DRIVER VALIDATED: $($check.Name)"

# --- 5. Create port ---
Write-Output ""
Write-Output "--- Step 5: Create port $PortName ---"
if (-not (Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue)) {
    Add-PrinterPort -Name $PortName -PrinterHostAddress $MfpIp
    Write-Output "PORT CREATED: $PortName -> $MfpIp"
} else {
    Write-Output "PORT EXISTS: $PortName"
}

# --- 6. Remove stale V3 queue ---
Write-Output ""
Write-Output "--- Step 6: Remove stale queue on port $PortName ---"
$stale = @(Get-Printer -ErrorAction SilentlyContinue |
           Where-Object { ($_.PortName -eq $PortName -or $_.PortName -eq $MfpIp) -and $_.Name -ne $PrinterName })
foreach ($old in $stale) {
    Remove-Printer -Name $old.Name -ErrorAction SilentlyContinue
    Write-Output "REMOVED stale queue: $($old.Name)"
}

# --- 7. Add queue ---
Write-Output ""
Write-Output "--- Step 7: Add printer queue ---"
if (-not (Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue)) {
    Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PortName
    Write-Output "ADDED: $PrinterName"
} else {
    Write-Output "EXISTS: $PrinterName (kept)"
}

# --- 8. Verify ---
Write-Output ""
Write-Output "--- Step 8: Verify ---"
$final = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
if ($final) {
    Write-Output ("SUCCESS: {0}  Port: {1}  Driver: {2}  Status: {3}" -f $final.Name, $final.PortName, $final.DriverName, $final.PrinterStatus)
    Write-Output ""
    Write-Output "===== DONE ====="
    exit 0
} else {
    Write-Output "FAILED: Printer queue not found after creation."
    exit 1
}
