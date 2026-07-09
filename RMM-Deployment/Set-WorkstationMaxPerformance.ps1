<#
.SYNOPSIS
    Configure workstation for maximum performance and eliminate power-saving disconnects

.DESCRIPTION
    Applies comprehensive performance configuration to workstations:
    - Activates Ultimate Performance power plan (or High Performance fallback)
    - Disables all sleep, standby, hibernate timeouts
    - Disables NIC power management (prevents network disconnects during remote sessions)
    - Disables USB selective suspend

    Primary use: Remote access workstations, conference room PCs, kiosks, systems experiencing
    intermittent network drops or wake-from-sleep issues.

.NOTES
    Context: RMM (PS 5.1, SYSTEM) or Interactive Admin
    Requires: Administrator privileges
    Exit Codes: 0 = success | 1 = error

#>

#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Workstation Maximum Performance Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 1: Enable Ultimate Performance Power Plan
# -----------------------------------------------------------------------------
Write-Host "[1/4] Configuring Power Plan..." -ForegroundColor Yellow

# Ultimate Performance GUID (hidden by default, need to duplicate it)
$ultimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"

# Try to enable Ultimate Performance
$result = powercfg -duplicatescheme $ultimateGuid 2>&1
if ($result -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
    $newGuid = $Matches[1]
    powercfg -setactive $newGuid
    Write-Host "  - Ultimate Performance plan enabled and activated" -ForegroundColor Green
} else {
    # Fallback to High Performance if Ultimate fails (Modern Standby systems)
    Write-Host "  - Ultimate Performance unavailable, using High Performance" -ForegroundColor Yellow
    $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    powercfg -duplicatescheme $highPerfGuid 2>$null
    powercfg -setactive $highPerfGuid
    Write-Host "  - High Performance plan activated" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# STEP 2: Disable All Sleep/Standby/Hibernate/Monitor Timeouts
# -----------------------------------------------------------------------------
Write-Host "[2/4] Disabling sleep and standby..." -ForegroundColor Yellow

# AC Power (plugged in) - set all to 0 (never)
powercfg -change -standby-timeout-ac 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0

# DC Power (battery) - set all to 0 (never) - included for laptops
powercfg -change -standby-timeout-dc 0
powercfg -change -hibernate-timeout-dc 0
powercfg -change -monitor-timeout-dc 0
powercfg -change -disk-timeout-dc 0

# Disable hibernate entirely (frees up disk space too)
powercfg -h off 2>$null

Write-Host "  - Sleep, hibernate, and monitor timeouts disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# STEP 3: Disable NIC Power Management (Prevent Network Disconnects)
# -----------------------------------------------------------------------------
Write-Host "[3/4] Disabling NIC power management..." -ForegroundColor Yellow

# Method 1: Use Disable-NetAdapterPowerManagement cmdlet
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    try {
        Disable-NetAdapterPowerManagement -Name $adapter.Name -NoRestart -ErrorAction SilentlyContinue
        Write-Host "  - Disabled power management on: $($adapter.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  - Cmdlet failed for $($adapter.Name), using registry method" -ForegroundColor Yellow
    }
}

# Method 2: Registry method (more reliable, catches what cmdlet misses)
# PnPCapabilities = 0x18 (24) disables power management
# PnPCapabilities = 0x118 (280) also disables "Allow to wake computer"
$nicRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
$subkeys = Get-ChildItem -Path $nicRegPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match "^\d{4}$" }

foreach ($subkey in $subkeys) {
    $driverDesc = (Get-ItemProperty -Path $subkey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
    if ($driverDesc) {
        Set-ItemProperty -Path $subkey.PSPath -Name "PnPCapabilities" -Value 0x18 -Type DWord -ErrorAction SilentlyContinue
    }
}
Write-Host "  - Registry-based NIC power management disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# STEP 4: Disable USB Selective Suspend
# -----------------------------------------------------------------------------
Write-Host "[4/4] Disabling USB selective suspend..." -ForegroundColor Yellow

# Get active power scheme GUID
$activeScheme = (powercfg -getactivescheme) -replace ".*GUID: ([a-f0-9-]+).*",'$1'

# USB Selective Suspend setting GUID
# Sub-group: USB settings = 2a737441-1930-4402-8d77-b2bebba308a3
# Setting: USB selective suspend = 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
powercfg -setacvalueindex $activeScheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setdcvalueindex $activeScheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setactive $activeScheme

Write-Host "  - USB selective suspend disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Configuration Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Active Power Plan:" -ForegroundColor White
powercfg -getactivescheme
Write-Host ""
Write-Host "Settings Applied:" -ForegroundColor White
Write-Host "  [X] Ultimate/High Performance power plan" -ForegroundColor Green
Write-Host "  [X] Sleep disabled (AC and DC)" -ForegroundColor Green
Write-Host "  [X] Hibernate disabled" -ForegroundColor Green
Write-Host "  [X] Monitor timeout disabled" -ForegroundColor Green
Write-Host "  [X] NIC power management disabled" -ForegroundColor Green
Write-Host "  [X] USB selective suspend disabled" -ForegroundColor Green
Write-Host ""
Write-Host "NOTE: A restart is recommended to ensure all NIC settings take effect." -ForegroundColor Yellow
Write-Host ""

exit 0
