<#
.SYNOPSIS
    Get-PrinterConnectivityDiag-RMM — RMM-ready printer connectivity and driver diagnostic

.DESCRIPTION
    Verifies printer network connectivity, port status, and driver configuration.
    Designed for RMM deployment (PowerShell 5.1, SYSTEM context).
    Customize the $Printers array for your environment.

.NOTES
    Category: Diagnostics

.KEYWORDS
    printer, diagnose, RMM, SYSTEM, connectivity
#>

$ErrorActionPreference = "Stop"
$ExitCode = 0

try {
    # CUSTOMIZE: Add/modify printers for your environment
    $Printers = @(
        @{Name = "Printer-01"; IP = "192.168.254.28"; Model = "Model-A"}
        @{Name = "Printer-02"; IP = "192.168.254.27"; Model = "Model-B"}
    )

    $Results = @()

    foreach ($Printer in $Printers) {
        $Result = [PSCustomObject]@{
            PrinterName     = $Printer.Name
            IPAddress       = $Printer.IP
            Pingable        = $false
            Port9100Open    = $false
            PrinterExists   = $false
            DriverName      = "N/A"
            DriverInstalled = $false
            PortName        = "N/A"
            Status          = "N/A"
        }

        $Ping = Test-Connection -ComputerName $Printer.IP -Count 2 -Quiet -ErrorAction SilentlyContinue
        $Result.Pingable = $Ping

        $TcpTest = New-Object System.Net.Sockets.TcpClient
        try {
            $TcpTest.Connect($Printer.IP, 9100)
            $Result.Port9100Open = $TcpTest.Connected
            $TcpTest.Close()
        } catch {
            $Result.Port9100Open = $false
        }

        $InstalledPrinter = Get-Printer -ErrorAction SilentlyContinue | Where-Object {
            $_.PortName -match [regex]::Escape($Printer.IP) -or $_.Name -like "*$($Printer.Model)*" -or $_.Name -like "*$($Printer.Name)*"
        } | Select-Object -First 1

        if ($InstalledPrinter) {
            $Result.PrinterExists = $true
            $Result.DriverName = $InstalledPrinter.DriverName
            $Result.PortName = $InstalledPrinter.PortName
            $Result.Status = $InstalledPrinter.PrinterStatus
        }

        $DriverCheck = Get-PrinterDriver -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "*Ricoh*" -and ($_.Name -like "*C2510*" -or $_.Name -like "*7000*" -or $_.Name -like "*PCL6*" -or $_.Name -like "*Universal*")
        }
        if ($DriverCheck -or ($InstalledPrinter -and $InstalledPrinter.DriverName)) {
            $Result.DriverInstalled = $true
        }

        $Results += $Result
    }

    Write-Output "========== PRINTER CONNECTIVITY DIAGNOSTIC =========="
    Write-Output "Computer: $env:COMPUTERNAME"
    Write-Output "User: $env:USERNAME"
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    foreach ($R in $Results) {
        Write-Output "--- $($R.PrinterName) ---"
        Write-Output "  IP Address:     $($R.IPAddress)"
        Write-Output "  Pingable:       $(if($R.Pingable){'YES'}else{'NO - CHECK NETWORK'})"
        Write-Output "  Port 9100:      $(if($R.Port9100Open){'OPEN'}else{'CLOSED - FIREWALL OR PRINTER OFFLINE'})"
        Write-Output "  Printer Added:  $(if($R.PrinterExists){'YES'}else{'NO - NEEDS INSTALLATION'})"
        Write-Output "  Driver:         $($R.DriverName)"
        Write-Output "  Port Config:    $($R.PortName)"
        Write-Output ""
    }

    Write-Output "========== INSTALLED RICOH DRIVERS =========="
    $RicohDrivers = Get-PrinterDriver -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Ricoh*"}
    if ($RicohDrivers) {
        $RicohDrivers | ForEach-Object { Write-Output "  $($_.Name)" }
    } else {
        Write-Output "  (none found)"
    }

    Write-Output ""
    Write-Output "========== ALL PRINTERS ON SYSTEM =========="
    $AllPrinters = Get-Printer -ErrorAction SilentlyContinue
    if ($AllPrinters) {
        $AllPrinters | ForEach-Object { Write-Output "  [$($_.PrinterStatus)] $($_.Name) -> $($_.PortName)" }
    } else {
        Write-Output "  (no printers installed)"
    }

    $FailedPrinters = $Results | Where-Object {-not $_.Pingable -or -not $_.Port9100Open -or -not $_.PrinterExists}

    Write-Output ""
    Write-Output "========== SUMMARY =========="

    if ($FailedPrinters.Count -eq 0) {
        Write-Output "STATUS: PASS - All printers connectivity and configuration verified"
    } else {
        Write-Output "STATUS: FAIL - Issues detected"
        foreach ($F in $FailedPrinters) {
            $Issues = @()
            if (-not $F.Pingable) { $Issues += "NOT PINGABLE" }
            if (-not $F.Port9100Open) { $Issues += "PORT 9100 CLOSED" }
            if (-not $F.PrinterExists) { $Issues += "NOT INSTALLED" }
            Write-Output "  PROBLEM: $($F.PrinterName) - $($Issues -join ', ')"
        }
        $ExitCode = 1
    }

} catch {
    Write-Output "SCRIPT ERROR: $($_.Exception.Message)"
    Write-Output "Line: $($_.InvocationInfo.ScriptLineNumber)"
    $ExitCode = 1
}

exit $ExitCode

<#
.NOTES
Common symptom mapping:
| Symptom                              | Likely Cause                          |
|--------------------------------------|---------------------------------------|
| Ping fails                           | Wrong VLAN, firewall, printer offline |
| Port 9100 closed but ping works      | Printer sleep mode, port disabled     |
| Printer not added                    | Never deployed or removed by user     |
| Wrong driver                         | Generic driver = feature loss         |

RMM Exit Codes:
  0 = All printers pingable, port 9100 open, and installed
  1 = One or more printers failed checks OR script error
#>
