<#
.SYNOPSIS
    Collects Chrome printing diagnostics for troubleshooting

.DESCRIPTION
    Gathers printer configuration, spooler status, recent print errors,
    and Chrome installation info for troubleshooting browser printing issues.
    Designed for RMM deployment.

.NOTES
    Date: 2025-12-03
    Version: 1.0
    Category: Diagnostics
.KEYWORDS
    printer, Chrome, diagnose, RMM, SYSTEM
#>

$ErrorActionPreference = "Stop"

try {
    $output = @()

    # Get logged-in user
    $cs = Get-WmiObject Win32_ComputerSystem
    $loggedInUser = if ($cs.UserName) { $cs.UserName -replace '.*\\' } else { "No user logged in" }

    $output += "========================================"
    $output += "CHROME PRINT DIAGNOSTICS"
    $output += "Computer: $env:COMPUTERNAME"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += "========================================"
    $output += ""

    # Logged-in user
    $output += "=== LOGGED-IN USER ==="
    $output += $loggedInUser
    $output += ""

    # Installed printers
    $output += "=== INSTALLED PRINTERS ==="
    $printers = Get-WmiObject Win32_Printer | Select-Object Name, DriverName, PortName, PrinterStatus, Default
    if ($printers) {
        foreach ($p in $printers) {
            $default = if ($p.Default) { " [DEFAULT]" } else { "" }
            $output += "  Name: $($p.Name)$default"
            $output += "    Driver: $($p.DriverName)"
            $output += "    Port: $($p.PortName)"
            $output += "    Status: $($p.PrinterStatus)"
            $output += ""
        }
    } else {
        $output += "  No printers found"
        $output += ""
    }

    # Print Spooler status
    $output += "=== PRINT SPOOLER SERVICE ==="
    $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($spooler) {
        $output += "  Status: $($spooler.Status)"
        $output += "  StartType: $($spooler.StartType)"
    } else {
        $output += "  Spooler service not found"
    }
    $output += ""

    # Recent print errors (last 24 hours)
    $output += "=== RECENT PRINT ERRORS (Last 24h) ==="
    try {
        $printErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Print'
            Level = 2,3
            StartTime = (Get-Date).AddDays(-1)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($printErrors) {
            foreach ($err in $printErrors) {
                $output += "  [$($err.TimeCreated)] $($err.Message)"
            }
        } else {
            $output += "  No print errors in last 24 hours"
        }
    } catch {
        $output += "  No print errors in last 24 hours"
    }
    $output += ""

    # Chrome installation
    $output += "=== CHROME INSTALLATION ==="
    $chromePaths = @(
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    $chromeFound = $false
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            $version = (Get-Item $path).VersionInfo.FileVersion
            $output += "  Version: $version"
            $output += "  Path: $path"
            $chromeFound = $true
            break
        }
    }
    if (-not $chromeFound) {
        $output += "  Chrome NOT INSTALLED"
    }
    $output += ""

    # Chrome user profile exists
    $output += "=== CHROME USER PROFILE ==="
    if ($loggedInUser -ne "No user logged in") {
        $chromePrefPath = "$env:SystemDrive\Users\$loggedInUser\AppData\Local\Google\Chrome\User Data\Default\Preferences"
        $chromeUserData = "$env:SystemDrive\Users\$loggedInUser\AppData\Local\Google\Chrome\User Data"

        if (Test-Path $chromeUserData) {
            $output += "  User Data folder: EXISTS"
            if (Test-Path $chromePrefPath) {
                $output += "  Preferences file: EXISTS"
            } else {
                $output += "  Preferences file: NOT FOUND"
            }
        } else {
            $output += "  User Data folder: NOT FOUND (Chrome may not have been launched by this user)"
        }
    } else {
        $output += "  Cannot check - no user logged in"
    }
    $output += ""

    # Network connectivity to printer ports (if network printers exist)
    $output += "=== NETWORK PRINTER CONNECTIVITY ==="
    $networkPrinters = Get-WmiObject Win32_Printer | Where-Object { $_.PortName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' }
    if ($networkPrinters) {
        foreach ($np in $networkPrinters) {
            $ip = $np.PortName -replace ':.*'
            $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
            $status = if ($pingResult) { "REACHABLE" } else { "UNREACHABLE" }
            $output += "  $($np.Name) ($ip): $status"
        }
    } else {
        $output += "  No network printers detected"
    }
    $output += ""
    $output += "========================================"
    $output += "END DIAGNOSTICS"
    $output += "========================================"

    # Output all results
    $output | ForEach-Object { Write-Output $_ }

    exit 0

} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
