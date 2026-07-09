#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Chrome print environment diagnostics for RMM deployment.
.DESCRIPTION
    Gathers printer status, spooler health, Chrome installation info, and network
    printer reachability. Designed for RMM SYSTEM-context execution.
    Output is formatted for copy/paste from the RMM script results pane.
.SOURCE
    claude.ai conversation extraction — Printer headers and footers toggle configuration
.NOTES
    Context: RMM (PS 5.1, SYSTEM)
    Exit 0 = diagnostics collected
    Exit 1 = fatal error
#>

$ErrorActionPreference = 'SilentlyContinue'

try {
    $computer = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    Write-Output "========================================"
    Write-Output "CHROME PRINT DIAGNOSTICS"
    Write-Output "Computer: $computer"
    Write-Output "Generated: $timestamp"
    Write-Output "========================================"

    # Logged-in user (safe in SYSTEM context)
    $loggedInUser = (Get-CimInstance Win32_ComputerSystem).UserName -replace '.*\\'
    Write-Output "`n=== LOGGED-IN USER ==="
    Write-Output $loggedInUser

    # Installed printers
    Write-Output "`n=== INSTALLED PRINTERS ==="
    $defaultPrinter = (Get-CimInstance Win32_Printer | Where-Object { $_.Default }).Name
    Get-Printer | ForEach-Object {
        $label = if ($_.Name -eq $defaultPrinter) { " [DEFAULT]" } else { "" }
        Write-Output "  Name: $($_.Name)$label"
        Write-Output "    Driver: $($_.DriverName)"
        Write-Output "    Port: $($_.PortName)"
        Write-Output "    Status: $($_.PrinterStatus)"
        Write-Output ""
    }

    # Print Spooler
    Write-Output "=== PRINT SPOOLER SERVICE ==="
    $spooler = Get-Service Spooler
    Write-Output "  Status: $($spooler.Status)"
    Write-Output "  StartType: $($spooler.StartType)"

    # Recent print errors
    Write-Output "`n=== RECENT PRINT ERRORS (Last 24h) ==="
    $errors = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Level     = 2, 3
        StartTime = (Get-Date).AddDays(-1)
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Print|Spooler' }

    if ($errors) {
        $errors | Select-Object -First 5 | ForEach-Object {
            Write-Output "  $($_.TimeCreated) — $($_.Message)"
        }
    } else {
        Write-Output "  No print errors in last 24 hours"
    }

    # Chrome installation
    Write-Output "`n=== CHROME INSTALLATION ==="
    $chromePaths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    $chromeExe = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($chromeExe) {
        $ver = (Get-Item $chromeExe).VersionInfo.FileVersion
        Write-Output "  Version: $ver"
        Write-Output "  Path: $chromeExe"
    } else {
        Write-Output "  Chrome not found"
    }

    # Chrome user profile
    Write-Output "`n=== CHROME USER PROFILE ==="
    if ($loggedInUser) {
        $profileBase = "C:\Users\$loggedInUser\AppData\Local\Google\Chrome\User Data"
        $prefsFile   = "$profileBase\Default\Preferences"
        Write-Output "  User Data folder: $(if (Test-Path $profileBase) { 'EXISTS' } else { 'NOT FOUND' })"
        Write-Output "  Preferences file: $(if (Test-Path $prefsFile) { 'EXISTS' } else { 'NOT FOUND' })"
    } else {
        Write-Output "  Could not determine logged-in user"
    }

    # Network printer ping
    Write-Output "`n=== NETWORK PRINTER CONNECTIVITY ==="
    Get-Printer | Where-Object { $_.PortName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' } |
        ForEach-Object {
            $ip = $_.PortName
            $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet
            $status = if ($ping) { 'REACHABLE' } else { 'UNREACHABLE' }
            Write-Output "  $($_.Name) ($ip): $status"
        }

    Write-Output "`n========================================"
    Write-Output "END DIAGNOSTICS"
    Write-Output "========================================"
    exit 0
} catch {
    Write-Output "FATAL: $($_.Exception.Message)"
    exit 1
}
