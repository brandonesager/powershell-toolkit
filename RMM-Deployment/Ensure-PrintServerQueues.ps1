#Requires -Version 5.1

<#
.SYNOPSIS
    Ensure-PrintServerQueues — Idempotent printer queue creation on a print server

.DESCRIPTION
    Ensures printer queues exist with correct drivers, ports, and sharing.
    Safe to re-run — only takes action where needed.

    For each printer in the configuration:
    1. Creates TCP/IP port if missing (idempotent)
    2. Evaluates existing queue state:
       - Bad driver (e.g., Microsoft IPP Class Driver): DELETE queue, RECREATE
       - Acceptable driver, not shared: FIX SHARING only
       - Acceptable driver, shared: SKIP (no-op)
       - Unknown driver: SKIP with warning (manual review)
       - Queue missing: CREATE with specified driver

    Pre-flight checks verify all required drivers are installed before
    making any changes.

.PARAMETER Printers
    Array of hashtables defining printers. Each hashtable must contain:
      ShareName  - Queue/share name
      IP         - Printer IP address
      Driver     - Print driver name
      Location   - (Optional) Location string
      Comment    - (Optional) Comment/description

.PARAMETER BadDrivers
    Array of driver names that should trigger queue replacement.
    Default: @('Microsoft IPP Class Driver')

.PARAMETER AcceptableDrivers
    Array of driver names considered valid. If not specified, falls back to
    the Driver value from each printer's config entry (auto-populated).

.PARAMETER PortNamePrefix
    Prefix for TCP/IP port names. Default: '' (uses IP as port name).
    Set to 'IP_' for standard Windows port naming convention.

.EXAMPLE
    $printers = @(
        @{ ShareName = 'OFFICE-HP';   IP = '10.0.1.50'; Driver = 'HP Universal Printing PCL6'; Location = 'Main Office' }
        @{ ShareName = 'WAREHOUSE';   IP = '10.0.1.51'; Driver = 'HP Universal Printing PCL6'; Location = 'Warehouse' }
    )
    .\Ensure-PrintServerQueues.ps1 -Printers $printers

.EXAMPLE
    # With custom bad/acceptable driver lists
    .\Ensure-PrintServerQueues.ps1 -Printers $printers `
        -BadDrivers @('Microsoft IPP Class Driver', 'Generic / Text Only') `
        -AcceptableDrivers @('HP Universal Printing PCL6', 'Lexmark Universal v2 XL')

.NOTES
    Date: 2026-02-09
    Category: RMM-Deployment
    Context: SYSTEM (RMM) or interactive (requires admin)
    PS Version: 5.1
    Exit Codes: 0=All configured, 1=All failed, 112=Partial success

.KEYWORDS
    printer, queue, idempotent, print-server, RMM
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [hashtable[]]$Printers,

    [string[]]$BadDrivers = @('Microsoft IPP Class Driver'),

    [string[]]$AcceptableDrivers,

    [string]$PortNamePrefix = ''
)

$ErrorActionPreference = "Stop"

#region Auto-populate AcceptableDrivers if not specified
if (-not $AcceptableDrivers -or $AcceptableDrivers.Count -eq 0) {
    $AcceptableDrivers = @($Printers | ForEach-Object { $_.Driver } | Select-Object -Unique)
}
#endregion

#region Functions
function Test-PrinterPortExists {
    param([string]$PortName)
    $port = Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
    return ($null -ne $port)
}

function Get-PrinterState {
    param([string]$PrinterName)
    $p = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return @{
        Driver   = $p.DriverName
        Shared   = $p.Shared
        PortName = $p.PortName
    }
}

function New-TcpPrinterPort {
    param(
        [string]$PortName,
        [string]$PrinterIP
    )

    if (Test-PrinterPortExists -PortName $PortName) {
        Write-Output "  Port '$PortName' already exists - skipping"
        return $true
    }

    try {
        Add-PrinterPort -Name $PortName -PrinterHostAddress $PrinterIP -ErrorAction Stop
        Write-Output "  Port '$PortName' created"
        return $true
    }
    catch {
        Write-Output "  ERROR creating port '$PortName': $($_.Exception.Message)"
        return $false
    }
}

function Ensure-PrinterCorrect {
    param(
        [string]$PrinterName,
        [string]$PortName,
        [string]$DriverName,
        [string]$Location,
        [string]$Comment,
        [string[]]$BadDriverList,
        [string[]]$AcceptableDriverList
    )

    $current = Get-PrinterState -PrinterName $PrinterName

    if ($null -ne $current) {
        $driverIsBad = $BadDriverList -contains $current.Driver
        $driverIsAcceptable = $AcceptableDriverList -contains $current.Driver

        if ($driverIsBad) {
            Write-Output "  Queue exists with bad driver ($($current.Driver)) - replacing"
            try {
                Remove-Printer -Name $PrinterName -ErrorAction Stop
                Write-Output "  Removed existing queue"
            }
            catch {
                Write-Output "  ERROR removing queue: $($_.Exception.Message)"
                return $false
            }
            # Fall through to create
        }
        elseif ($driverIsAcceptable) {
            if (-not $current.Shared) {
                Write-Output "  Queue exists with acceptable driver ($($current.Driver)), fixing sharing"
                try {
                    Set-Printer -Name $PrinterName -Shared $true -ShareName $PrinterName -ErrorAction Stop
                    Write-Output "  Sharing enabled"
                }
                catch {
                    Write-Output "  ERROR enabling sharing: $($_.Exception.Message)"
                    return $false
                }
            }
            else {
                Write-Output "  Queue '$PrinterName' already correct (driver: $($current.Driver), shared) - skipping"
            }
            return $true
        }
        else {
            Write-Output "  WARNING: Unknown driver '$($current.Driver)' - skipping (manual review needed)"
            return $true
        }
    }

    # Create new queue
    try {
        $addParams = @{
            Name       = $PrinterName
            PortName   = $PortName
            DriverName = $DriverName
            Shared     = $true
            ShareName  = $PrinterName
            Published  = $false
        }
        if ($Location) { $addParams['Location'] = $Location }
        if ($Comment)  { $addParams['Comment'] = $Comment }

        Add-Printer @addParams -ErrorAction Stop
        Write-Output "  Queue '$PrinterName' created"
        return $true
    }
    catch {
        Write-Output "  ERROR creating queue: $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Pre-flight
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

Write-Output "=== Printer Queue Deployment ==="
Write-Output "Server: $env:COMPUTERNAME"
Write-Output "Time: $timestamp"
Write-Output "Printers: $($Printers.Count)"
Write-Output "================================="
Write-Output ""

# Verify drivers
Write-Output "Checking required drivers..."
$requiredDrivers = $Printers | ForEach-Object { $_.Driver } | Select-Object -Unique
$driversMissing = $false

foreach ($driver in $requiredDrivers) {
    $driverObj = Get-PrinterDriver -Name $driver -ErrorAction SilentlyContinue
    if ($null -eq $driverObj) {
        Write-Output "  [MISSING] $driver"
        $driversMissing = $true
    }
    else {
        Write-Output "  [OK] $driver"
    }
}

if ($driversMissing) {
    Write-Output ""
    Write-Output "ERROR: One or more required drivers not installed."
    exit 1
}
Write-Output ""
#endregion

#region Main
$successCount = 0
$failCount = 0

foreach ($printer in $Printers) {
    $shareName = $printer.ShareName
    $ip = $printer.IP
    $driver = $printer.Driver
    $location = if ($printer.Location) { $printer.Location } else { '' }
    $comment = if ($printer.Comment) { $printer.Comment } else { '' }
    $portName = "$PortNamePrefix$ip"

    Write-Output "--- $shareName ($ip) ---"

    $portResult = New-TcpPrinterPort -PortName $portName -PrinterIP $ip
    if (-not $portResult) {
        Write-Output "  FAILED: Could not create port"
        $failCount++
        Write-Output ""
        continue
    }

    $printerResult = Ensure-PrinterCorrect -PrinterName $shareName `
        -PortName $portName -DriverName $driver `
        -Location $location -Comment $comment `
        -BadDriverList $BadDrivers -AcceptableDriverList $AcceptableDrivers

    if ($printerResult) { $successCount++ } else { $failCount++ }
    Write-Output ""
}
#endregion

#region Results
Write-Output "================================="
Write-Output "RESULTS: $successCount/$($Printers.Count) printers configured"
Write-Output "================================="

if ($failCount -eq 0) {
    Write-Output "All printers configured successfully."
    exit 0
}
elseif ($successCount -gt 0) {
    Write-Output "Partial success. Review failures above."
    exit 112
}
else {
    Write-Output "All configurations failed."
    exit 1
}
#endregion
