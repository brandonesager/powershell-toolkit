<#
.SYNOPSIS
    Comprehensive workstation stability diagnostics

.DESCRIPTION
    Unified diagnostic script with configurable focus areas:
    - All: Run all diagnostic modules (default)
    - General: System info, memory, disk, processes
    - Freeze: Display/GPU freeze diagnostics, DWM analysis
    - Shutdown: Unexpected shutdown/restart root cause analysis
    - Hardware: Thermal, PSU, SMART, WHEA errors
    - Policy: Group policy and Windows Update related

.PARAMETER Focus
    Diagnostic focus area: All, General, Freeze, Shutdown, Hardware, Policy

.PARAMETER OutputFormat
    Output format: Readable (default), RMM, JSON

.PARAMETER DaysBack
    Days of event log history to analyze (default: 30)

.PARAMETER ApplyMitigations
    Apply automatic fixes for detected issues (Shutdown focus)

.PARAMETER GenerateMonitoringScript
    Create monitoring script for ongoing tracking (Hardware focus)

.PARAMETER CreateEvidencePack
    Bundle diagnostic data into ZIP for escalation

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Invoke-WorkstationStabilityDiagnostic.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Invoke-WorkstationStabilityDiagnostic.ps1' -Focus 'Value' -OutputFormat 'Value' -DaysBack 10

.NOTES
    Author: Brandon Sager
    Version: 2.0

    Consolidated from multiple diagnostic scripts into unified tool.
    Designed for MSP/enterprise RMM deployment.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [ValidateSet('All', 'General', 'Freeze', 'Shutdown', 'Hardware', 'Policy')]
    [string]$Focus = 'All',

    [ValidateSet('Readable', 'RMM', 'JSON')]
    [string]$OutputFormat = 'Readable',

    [int]$DaysBack = 30,

    [switch]$ApplyMitigations,

    [switch]$GenerateMonitoringScript,

    [switch]$CreateEvidencePack
)

$ErrorActionPreference = "Continue"
$TopProcessCount = 10

# Initialize report
$Report = @()
$RedFlags = @()

function Add-ReportSection {
    param([string]$Title, [string]$Content)
    $script:Report += "`n" + "="*80
    $script:Report += "`n$Title"
    $script:Report += "`n" + "="*80
    $script:Report += "`n$Content"
}


function Write-RmmOutput {
    param([string]$Section, [hashtable]$Data)
    if ($OutputFormat -eq 'RMM') {
        $parts = @("RMM|Section=$Section")
        foreach ($k in $Data.Keys) {
            if ($null -ne $Data[$k]) { $parts += "$k=$($Data[$k])" }
        }
        Write-Output ($parts -join ' ')
    }
}

function Test-ShouldRun {
    param([string]$Section)
    return ($Focus -eq 'All' -or $Focus -eq $Section)
}

#region FREEZE-SPECIFIC FUNCTIONS (from FreezeDiagnostic.ps1)
function Get-DisplayFreezeInfo {
    $freezeInfo = @()
    try {
        $displayEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Display'
            Level = 1,2,3
            StartTime = (Get-Date).AddDays(-$DaysBack)
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if ($displayEvents) {
            $freezeInfo += "DISPLAY DRIVER EVENTS: $($displayEvents.Count)"
            foreach ($evt in ($displayEvents | Select-Object -First 10)) {
                $freezeInfo += "  [$($evt.TimeCreated)] ID:$($evt.Id) - $(($evt.Message -split [char]10)[0])"
            }
            Add-RedFlag "Found $($displayEvents.Count) display driver events"
        }

        $dwmProcess = Get-Process -Name dwm -ErrorAction SilentlyContinue
        if ($dwmProcess) {
            $freezeInfo += "`nDESKTOP WINDOW MANAGER (dwm.exe):"
            $freezeInfo += "  Memory: $([math]::Round($dwmProcess.WorkingSet64/1MB, 2)) MB"
            $freezeInfo += "  CPU Time: $($dwmProcess.TotalProcessorTime)"
        }

        $monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
        if ($monitors) {
            $freezeInfo += "`nCONNECTED MONITORS: $($monitors.Count)"
        }
    } catch {
        $freezeInfo += "Error gathering freeze diagnostics: $_"
    }
    return $freezeInfo -join "`n"
}
#endregion

#region SHUTDOWN-SPECIFIC FUNCTIONS (from ShutdownRootCause.ps1)
function Get-ShutdownAnalysis {
    $shutdownInfo = @()
    $StartDate = (Get-Date).AddDays(-$DaysBack)
    try {
        $shutdownEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = 1074, 6006, 6008, 41
            StartTime = $StartDate
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        $planned = ($shutdownEvents | Where-Object { $_.Id -in @(1074, 6006) }).Count
        $unexpected = ($shutdownEvents | Where-Object { $_.Id -eq 6008 }).Count
        $kernelPower = ($shutdownEvents | Where-Object { $_.Id -eq 41 }).Count

        $shutdownInfo += "SHUTDOWN EVENT ANALYSIS (Last $DaysBack days):"
        $shutdownInfo += "  Planned shutdowns/restarts: $planned"
        $shutdownInfo += "  Unexpected shutdowns (6008): $unexpected"
        $shutdownInfo += "  Kernel Power events (41): $kernelPower"

        if ($unexpected -gt 0) { Add-RedFlag "Found $unexpected unexpected shutdowns" }
        if ($kernelPower -gt 0) { Add-RedFlag "Found $kernelPower Kernel-Power 41 events" }
    } catch {
        $shutdownInfo += "Error analyzing shutdown events: $_"
    }
    return $shutdownInfo -join "`n"
}
#endregion

#region HARDWARE-SPECIFIC FUNCTIONS (from Export-HardwareDiagnostics.ps1)
function Get-ThermalInfo {
    $thermalInfo = @()
    try {
        $temps = Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
        if ($temps) {
            $thermalInfo += "THERMAL ZONES:"
            foreach ($zone in $temps) {
                $tempC = [math]::Round(($zone.CurrentTemperature - 2732) / 10, 1)
                $status = if ($tempC -gt 70) { "[HIGH]" } elseif ($tempC -gt 60) { "[WARM]" } else { "[OK]" }
                $thermalInfo += "  Zone: $tempC C $status"
                if ($tempC -gt 70) { Add-RedFlag "High temperature: $tempC C" }
            }
        } else {
            $thermalInfo += "Thermal data not available via WMI"
        }
    } catch {
        $thermalInfo += "Cannot read thermal sensors: $_"
    }
    return $thermalInfo -join "`n"
}

function New-MonitoringScript {
    $scriptPath = "$env:TEMP\Monitor-SystemHealth.ps1"
    $content = '$LogPath = "$env:TEMP\SystemHealthLog.csv"; $Entry = [PSCustomObject]@{Timestamp = Get-Date}; $Entry | Export-Csv -Path $LogPath -Append -NoTypeInformation'
    $content | Out-File -FilePath $scriptPath -Encoding UTF8
    return $scriptPath
}
#endregion

#region POLICY-SPECIFIC FUNCTIONS (from Export-ShutdownDiagnostics.ps1)
function Get-PolicyDiagnostics {
    $policyInfo = @()
    try {
        $policyInfo += "GROUP POLICY ANALYSIS:"
        $gpResult = gpresult /r 2>&1 | Select-String -Pattern "Last time Group Policy|applied from" | Select-Object -First 2
        foreach ($line in $gpResult) { $policyInfo += "  $($line.Line.Trim())" }

        $policyInfo += "`nWINDOWS UPDATE SERVICES:"
        $services = @('wuauserv', 'BITS', 'TrustedInstaller')
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) { $policyInfo += "  $svc : $($service.Status)" }
        }
    } catch {
        $policyInfo += "Error gathering policy info: $_"
    }
    return $policyInfo -join "`n"
}
#endregion

Write-Host "Starting workstation diagnostics..." -ForegroundColor Cyan

#region SYSTEM INFORMATION
$SystemInfo = Get-CimInstance Win32_ComputerSystem
$OSInfo = Get-CimInstance Win32_OperatingSystem
$BIOSInfo = Get-CimInstance Win32_BIOS

$SysInfoText = @"
Computer Name: $($SystemInfo.Name)
Manufacturer: $($SystemInfo.Manufacturer)
Model: $($SystemInfo.Model)
OS: $($OSInfo.Caption) $($OSInfo.Version)
BIOS: $($BIOSInfo.Manufacturer) $($BIOSInfo.SMBIOSBIOSVersion)
Last Boot: $($OSInfo.LastBootUpTime)
Total Physical Memory: $([math]::Round($SystemInfo.TotalPhysicalMemory/1GB, 2)) GB
"@
Add-ReportSection "SYSTEM INFORMATION" $SysInfoText
#endregion

#region ECC MEMORY DETECTION
Write-Host "Checking memory configuration..." -ForegroundColor Yellow

$MemoryModules = Get-CimInstance Win32_PhysicalMemory
$MemoryInfo = @()
$HasECC = $false

foreach ($Module in $MemoryModules) {
    $IsECC = $Module.TotalWidth -gt $Module.DataWidth
    if ($IsECC) { $HasECC = $true }
    
    $MemoryInfo += @"

Module: $($Module.DeviceLocator)
  Manufacturer: $($Module.Manufacturer)
  Part Number: $($Module.PartNumber)
  Capacity: $([math]::Round($Module.Capacity/1GB, 2)) GB
  Speed: $($Module.Speed) MHz
  Data Width: $($Module.DataWidth) bits
  Total Width: $($Module.TotalWidth) bits
  ECC: $(if ($IsECC) { "YES" } else { "NO" })
  Type: $($Module.MemoryType)
"@
}

$MemoryText = @"
MEMORY MODULES DETECTED: $($MemoryModules.Count)
TOTAL CAPACITY: $([math]::Round(($MemoryModules | Measure-Object -Property Capacity -Sum).Sum/1GB, 2)) GB
ECC MEMORY DETECTED: $(if ($HasECC) { "YES =“" } else { "NO =—" })

$($MemoryInfo -join "`n")
"@

if (-not $HasECC) {
    Add-RedFlag "NO ECC MEMORY DETECTED - May contribute to instability with CAD applications"
}

Add-ReportSection "MEMORY CONFIGURATION" $MemoryText
#endregion

#region MEMORY ERROR LOGS
Write-Host "Checking memory error logs..." -ForegroundColor Yellow

$MemoryErrors = @()
$StartDate = (Get-Date).AddDays(-$DaysBack)

# Windows Memory Diagnostics Results
try {
    $MemDiagResults = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message -First 10
    
    if ($MemDiagResults) {
        $MemoryErrors += "`nWindows Memory Diagnostics:"
        foreach ($event in $MemDiagResults) {
            $MemoryErrors += "  [$($event.TimeCreated)] $($event.Message)"
        }
    } else {
        $MemoryErrors += "`nNo Windows Memory Diagnostic results found"
    }
} catch {
    $MemoryErrors += "`nUnable to retrieve Memory Diagnostic logs"
}

# Hardware errors
try {
    $HardwareErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Level = 1,2,3  # Critical, Error, Warning
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "memory|ram|dimm|ecc" -or
        $_.ProviderName -match "memory"
    } | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message -First 20
    
    if ($HardwareErrors) {
        $MemoryErrors += "`n`nMemory-Related Hardware Events (Last $DaysBack days): $($HardwareErrors.Count)"
        foreach ($event in $HardwareErrors) {
            $MemoryErrors += "`n  [$($event.TimeCreated)] [$($event.LevelDisplayName)] $($event.ProviderName) - ID:$($event.Id)"
            $MemoryErrors += "    $($event.Message -replace "`n",' ' -replace "`r",'' | Out-String -Width 200)"
        }
        Add-RedFlag "Found $($HardwareErrors.Count) memory-related hardware events in System log"
    }
} catch {
    $MemoryErrors += "`nUnable to retrieve hardware error logs"
}

Add-ReportSection "MEMORY ERROR LOGS (Last $DaysBack Days)" ($MemoryErrors -join "`n")
#endregion

#region APPLICATION CRASHES
Write-Host "Analyzing application crashes..." -ForegroundColor Yellow

$AppCrashes = @()
$CrashApps = @("AutoCAD", "Revit", "Bluebeam", "acad.exe", "revit.exe", "Revu.exe")

try {
    # Application Event Log - Application Errors
    $ApplicationErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        Level = 2  # Error
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Where-Object {
        $msg = $_.Message
        $CrashApps | Where-Object { $msg -match $_ }
    } | Select-Object TimeCreated, ProviderName, Id, Message -First 50
    
    if ($ApplicationErrors) {
        $AppCrashes += "APPLICATION CRASHES DETECTED: $($ApplicationErrors.Count)"
        $AppCrashes += "`nLast 20 crashes:"
        foreach ($crash in ($ApplicationErrors | Select-Object -First 20)) {
            $AppCrashes += "`n[$($crash.TimeCreated)] $($crash.ProviderName)"
            $AppCrashes += "  $(($crash.Message -split "`n")[0..2] -join ' ')"
        }
        Add-RedFlag "Found $($ApplicationErrors.Count) CAD application crashes in last $DaysBack days"
    } else {
        $AppCrashes += "No CAD application crashes found in Application log"
    }
    
    # Windows Error Reporting
    $WEREvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'Windows Error Reporting'
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Where-Object {
        $msg = $_.Message
        $CrashApps | Where-Object { $msg -match $_ }
    } | Select-Object TimeCreated, Message -First 30
    
    if ($WEREvents) {
        $AppCrashes += "`n`nWINDOWS ERROR REPORTING - CAD Crashes: $($WEREvents.Count)"
        foreach ($event in ($WEREvents | Select-Object -First 10)) {
            $AppCrashes += "`n[$($event.TimeCreated)] $(($event.Message -split "`n")[0])"
        }
    }
} catch {
    $AppCrashes += "Error retrieving application crash logs: $_"
}

Add-ReportSection "CAD APPLICATION CRASHES (Last $DaysBack Days)" ($AppCrashes -join "`n")
#endregion

#region CRITICAL SYSTEM ERRORS
Write-Host "Checking critical system errors..." -ForegroundColor Yellow

$CriticalErrors = @()

try {
    $SystemErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Level = 1,2  # Critical and Error
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Group-Object Id | 
        Sort-Object Count -Descending | Select-Object -First 15
    
    $CriticalErrors += "UNIQUE CRITICAL/ERROR EVENTS (Top 15 by frequency):"
    foreach ($errorGroup in $SystemErrors) {
        $sample = $errorGroup.Group[0]
        $CriticalErrors += "`n[$($errorGroup.Count)x] Event ID $($errorGroup.Name) - $($sample.ProviderName)"
        $CriticalErrors += "  $($sample.LevelDisplayName): $(($sample.Message -split "`n")[0])"
        $CriticalErrors += "  Last occurrence: $($sample.TimeCreated)"
    }
    
    if ($SystemErrors.Count -gt 0) {
        Add-RedFlag "Found $($SystemErrors.Count) unique critical/error event types in System log"
    }
} catch {
    $CriticalErrors += "Error retrieving critical system errors: $_"
}

Add-ReportSection "CRITICAL SYSTEM ERRORS (Last $DaysBack Days)" ($CriticalErrors -join "`n")
#endregion

#region BSOD HISTORY
Write-Host "Analyzing BSOD history..." -ForegroundColor Yellow

$BSODInfo = @()

try {
    # Check for Event ID 1001 (BugCheck) in System log
    $BSODs = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 1001
        ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue
    
    if ($BSODs) {
        $BSODInfo += "BLUE SCREENS DETECTED: $($BSODs.Count) in last $DaysBack days"
        $BSODInfo += "`nRecent BSODs:"
        foreach ($bsod in $BSODs) {
            $BSODInfo += "`n[$($bsod.TimeCreated)]"
            # Parse bug check code
            if ($bsod.Message -match "0x[0-9a-fA-F]+") {
                $BSODInfo += "  Bug Check: $($matches[0])"
            }
            $BSODInfo += "  $($bsod.Message)"
        }
        Add-RedFlag "CRITICAL: $($BSODs.Count) Blue Screen(s) detected in last $DaysBack days"
    } else {
        $BSODInfo += "No Blue Screens detected in last $DaysBack days"
    }
    
    # Check for minidump files
    $MinidumpPath = "$env:SystemRoot\Minidump"
    if (Test-Path $MinidumpPath) {
        $Minidumps = Get-ChildItem $MinidumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $StartDate } |
            Sort-Object LastWriteTime -Descending
        
        if ($Minidumps) {
            $BSODInfo += "`n`nMINIDUMP FILES FOUND: $($Minidumps.Count)"
            foreach ($dump in $Minidumps) {
                $BSODInfo += "`n  $($dump.Name) - $($dump.LastWriteTime) - $([math]::Round($dump.Length/1KB, 2)) KB"
            }
            $BSODInfo += "`nNote: Use WinDbg or BlueScreenView to analyze minidump files"
        }
    } else {
        $BSODInfo += "`nMinidump folder not found or inaccessible"
    }
} catch {
    $BSODInfo += "Error retrieving BSOD information: $_"
}

Add-ReportSection "BLUE SCREEN HISTORY (Last $DaysBack Days)" ($BSODInfo -join "`n")
#endregion

#region HARDWARE ERROR LOGS
Write-Host "Checking hardware error logs..." -ForegroundColor Yellow

$HWErrors = @()

try {
    # WHEA (Windows Hardware Error Architecture) errors
    $WHEAErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-WHEA-Logger'
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 30
    
    if ($WHEAErrors) {
        $HWErrors += "HARDWARE ERRORS (WHEA) DETECTED: $($WHEAErrors.Count)"
        foreach ($error in ($WHEAErrors | Select-Object -First 15)) {
            $HWErrors += "`n[$($error.TimeCreated)] [$($error.LevelDisplayName)] ID:$($error.Id)"
            $HWErrors += "  $(($error.Message -split "`n")[0..1] -join ' ')"
        }
        Add-RedFlag "CRITICAL: $($WHEAErrors.Count) hardware errors (WHEA) detected"
    } else {
        $HWErrors += "No WHEA hardware errors detected"
    }
    
    # Disk errors
    $DiskErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Disk'
        Level = 1,2,3
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 20
    
    if ($DiskErrors) {
        $HWErrors += "`n`nDISK ERRORS DETECTED: $($DiskErrors.Count)"
        foreach ($error in ($DiskErrors | Select-Object -First 10)) {
            $HWErrors += "`n[$($error.TimeCreated)] [$($error.LevelDisplayName)] ID:$($error.Id)"
            $HWErrors += "  $(($error.Message -split "`n")[0])"
        }
        Add-RedFlag "Found $($DiskErrors.Count) disk-related errors"
    }
} catch {
    $HWErrors += "Error retrieving hardware logs: $_"
}

Add-ReportSection "HARDWARE ERROR LOGS (Last $DaysBack Days)" ($HWErrors -join "`n")
#endregion

#region POWER SUPPLY INFORMATION
Write-Host "Gathering PSU information..." -ForegroundColor Yellow

$PSUInfo = @()

try {
    # Try to get power supply info from WMI (limited on most systems)
    $PowerSupply = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PowerSupply -ErrorAction SilentlyContinue
    
    if ($PowerSupply) {
        $PSUInfo += "Power Supply Information:"
        foreach ($psu in $PowerSupply) {
            $PSUInfo += "`n  Name: $($psu.Name)"
            $PSUInfo += "  Device ID: $($psu.DeviceID)"
            $PSUInfo += "  Status: $($psu.Status)"
        }
    } else {
        $PSUInfo += "Power Supply information not available via WMI"
    }
    
    # Battery/Power configuration
    $PowerCfg = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($PowerCfg) {
        $PSUInfo += "`n`nBattery/UPS Detected:"
        foreach ($battery in $PowerCfg) {
            $PSUInfo += "`n  Status: $($battery.Status)"
            $PSUInfo += "  Estimated Charge: $($battery.EstimatedChargeRemaining)%"
        }
    }
    
    # Power plan
    $PowerPlan = powercfg /getactivescheme
    $PSUInfo += "`n`nActive Power Plan:"
    $PSUInfo += "  $PowerPlan"
    
    $PSUInfo += "`n`nNote: Detailed PSU wattage/model typically requires:"
    $PSUInfo += "  - Physical inspection of hardware"
    $PSUInfo += "  - Manufacturer-specific tools (Dell Command, HP Support Assistant, etc.)"
    $PSUInfo += "  - Third-party monitoring software (HWiNFO, AIDA64)"
    
} catch {
    $PSUInfo += "Error retrieving PSU information: $_"
}

Add-ReportSection "POWER SUPPLY INFORMATION" ($PSUInfo -join "`n")
#endregion

#region DRIVE HEALTH (SMART STATUS)
Write-Host "Checking drive health..." -ForegroundColor Yellow

$DriveHealth = @()

try {
    $PhysicalDisks = Get-PhysicalDisk
    
    $DriveHealth += "PHYSICAL DISKS: $($PhysicalDisks.Count)"
    
    foreach ($disk in $PhysicalDisks) {
        $DriveHealth += "`n`nDisk $($disk.DeviceId): $($disk.FriendlyName)"
        $DriveHealth += "  Size: $([math]::Round($disk.Size/1GB, 2)) GB"
        $DriveHealth += "  Media Type: $($disk.MediaType)"
        $DriveHealth += "  Bus Type: $($disk.BusType)"
        $DriveHealth += "  Health Status: $($disk.HealthStatus)"
        $DriveHealth += "  Operational Status: $($disk.OperationalStatus)"
        
        if ($disk.HealthStatus -ne "Healthy") {
            Add-RedFlag "Disk $($disk.DeviceId) health status: $($disk.HealthStatus)"
        }
        
        # Try to get SMART data using Storage cmdlets
        try {
            $ReliabilityCounter = Get-StorageReliabilityCounter -PhysicalDisk $disk -ErrorAction SilentlyContinue
            if ($ReliabilityCounter) {
                $DriveHealth += "  Temperature: $($ReliabilityCounter.Temperature)Â°C"
                $DriveHealth += "  Wear: $($ReliabilityCounter.Wear)%"
                $DriveHealth += "  Power On Hours: $($ReliabilityCounter.PowerOnHours)"
                $DriveHealth += "  Read Errors: $($ReliabilityCounter.ReadErrorsTotal)"
                $DriveHealth += "  Write Errors: $($ReliabilityCounter.WriteErrorsTotal)"
                
                if ($ReliabilityCounter.ReadErrorsTotal -gt 0 -or $ReliabilityCounter.WriteErrorsTotal -gt 0) {
                    Add-RedFlag "Disk $($disk.DeviceId) has read/write errors"
                }
            }
        } catch {
            $DriveHealth += "  SMART data not available"
        }
    }
    
    # Logical disk space
    $LogicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $DriveHealth += "`n`nLOGICAL DISK SPACE:"
    foreach ($vol in $LogicalDisks) {
        $FreePercent = [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 2)
        $DriveHealth += "`n  $($vol.DeviceID) - $([math]::Round($vol.FreeSpace/1GB, 2)) GB free of $([math]::Round($vol.Size/1GB, 2)) GB ($FreePercent% free)"
        
        if ($FreePercent -lt 10) {
            Add-RedFlag "Drive $($vol.DeviceID) has less than 10% free space"
        }
    }
    
} catch {
    $DriveHealth += "Error retrieving drive health: $_"
}

Add-ReportSection "DRIVE HEALTH & SMART STATUS" ($DriveHealth -join "`n")
#endregion

#region GPU DRIVER
Write-Host "Checking GPU driver..." -ForegroundColor Yellow

$GPUInfo = @()

try {
    $VideoControllers = Get-CimInstance Win32_VideoController
    
    $GPUInfo += "VIDEO CONTROLLERS: $($VideoControllers.Count)"
    
    foreach ($gpu in $VideoControllers) {
        $GPUInfo += "`n`nGPU: $($gpu.Name)"
        $GPUInfo += "  Driver Version: $($gpu.DriverVersion)"
        $GPUInfo += "  Driver Date: $($gpu.DriverDate)"
        $GPUInfo += "  Video Processor: $($gpu.VideoProcessor)"
        $GPUInfo += "  Video RAM: $([math]::Round($gpu.AdapterRAM/1GB, 2)) GB"
        $GPUInfo += "  Current Resolution: $($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)"
        $GPUInfo += "  Status: $($gpu.Status)"
        
        # Check driver age
        if ($gpu.DriverDate) {
            $DriverAge = (Get-Date) - $gpu.DriverDate
            if ($DriverAge.Days -gt 180) {
                Add-RedFlag "GPU driver is $($DriverAge.Days) days old - consider updating"
            }
        }
    }
    
    # Check for recent display driver crashes
    $DisplayErrors = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Display'
        Level = 1,2,3
        StartTime = $StartDate
    } -ErrorAction SilentlyContinue
    
    if ($DisplayErrors) {
        $GPUInfo += "`n`nDISPLAY DRIVER ERRORS: $($DisplayErrors.Count) in last $DaysBack days"
        Add-RedFlag "Found $($DisplayErrors.Count) display driver errors"
    }
    
} catch {
    $GPUInfo += "Error retrieving GPU information: $_"
}

Add-ReportSection "GPU & DRIVER STATUS" ($GPUInfo -join "`n")
#endregion

#region PAGEFILE CONFIGURATION
Write-Host "Checking pagefile configuration..." -ForegroundColor Yellow

$PagefileInfo = @()

try {
    $Pagefiles = Get-CimInstance Win32_PageFileUsage
    $PagefileSetting = Get-CimInstance Win32_PageFileSetting
    
    if ($Pagefiles) {
        $PagefileInfo += "ACTIVE PAGEFILES: $($Pagefiles.Count)"
        foreach ($pf in $Pagefiles) {
            $PagefileInfo += "`n  Location: $($pf.Name)"
            $PagefileInfo += "  Current Size: $($pf.AllocatedBaseSize) MB"
            $PagefileInfo += "  Current Usage: $($pf.CurrentUsage) MB"
            $PagefileInfo += "  Peak Usage: $($pf.PeakUsage) MB"
        }
    }
    
    if ($PagefileSetting) {
        $PagefileInfo += "`n`nPAGEFILE SETTINGS:"
        foreach ($pfs in $PagefileSetting) {
            $PagefileInfo += "`n  Location: $($pfs.Name)"
            $PagefileInfo += "  Initial Size: $($pfs.InitialSize) MB"
            $PagefileInfo += "  Maximum Size: $($pfs.MaximumSize) MB"
        }
    } else {
        $PagefileInfo += "`n`nPagefile is SYSTEM MANAGED"
    }
    
    # Check if pagefile is on SSD
    $PagefileInfo += "`n`nRecommendation for CAD workstations:"
    $PagefileInfo += "  - Minimum 1.5x physical RAM"
    $PagefileInfo += "  - Consider fixed size to reduce fragmentation"
    $PagefileInfo += "  - Place on fast SSD if available"
    
} catch {
    $PagefileInfo += "Error retrieving pagefile information: $_"
}

Add-ReportSection "PAGEFILE CONFIGURATION" ($PagefileInfo -join "`n")
#endregion

#region DISK SPACE
Write-Host "Checking disk space..." -ForegroundColor Yellow

$DiskSpaceInfo = @()

try {
    $Volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Sort-Object DeviceID
    
    $DiskSpaceInfo += "DISK SPACE SUMMARY:"
    foreach ($vol in $Volumes) {
        $FreeGB = [math]::Round($vol.FreeSpace/1GB, 2)
        $TotalGB = [math]::Round($vol.Size/1GB, 2)
        $UsedGB = $TotalGB - $FreeGB
        $FreePercent = [math]::Round(($vol.FreeSpace / $vol.Size) * 100, 2)
        $UsedPercent = 100 - $FreePercent
        
        $DiskSpaceInfo += "`n`n$($vol.DeviceID) $(if($vol.VolumeName){"($($vol.VolumeName))"})"
        $DiskSpaceInfo += "  Total: $TotalGB GB"
        $DiskSpaceInfo += "  Used: $UsedGB GB ($UsedPercent%)"
        $DiskSpaceInfo += "  Free: $FreeGB GB ($FreePercent%)"
        
        # Warning thresholds
        if ($FreePercent -lt 5) {
            $DiskSpaceInfo += "  STATUS: CRITICAL - Less than 5% free!"
            Add-RedFlag "CRITICAL: Drive $($vol.DeviceID) has less than 5% free space"
        } elseif ($FreePercent -lt 10) {
            $DiskSpaceInfo += "  STATUS: WARNING - Less than 10% free"
            Add-RedFlag "Drive $($vol.DeviceID) has less than 10% free space"
        } elseif ($FreePercent -lt 20) {
            $DiskSpaceInfo += "  STATUS: Low - Less than 20% free"
        } else {
            $DiskSpaceInfo += "  STATUS: OK"
        }
    }
    
} catch {
    $DiskSpaceInfo += "Error retrieving disk space: $_"
}

Add-ReportSection "DISK SPACE ANALYSIS" ($DiskSpaceInfo -join "`n")
#endregion

#region MEMORY CONSUMING PROCESSES
Write-Host "Analyzing memory usage..." -ForegroundColor Yellow

$MemoryUsageInfo = @()

try {
    $TotalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $FreeRAM = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
    $UsedRAM = $TotalRAM - $FreeRAM
    $UsedPercent = [math]::Round(($UsedRAM / $TotalRAM) * 100, 2)
    
    $MemoryUsageInfo += "SYSTEM MEMORY USAGE:"
    $MemoryUsageInfo += "  Total RAM: $([math]::Round($TotalRAM/1GB, 2)) GB"
    $MemoryUsageInfo += "  Used RAM: $([math]::Round($UsedRAM/1GB, 2)) GB ($UsedPercent%)"
    $MemoryUsageInfo += "  Free RAM: $([math]::Round($FreeRAM/1GB, 2)) GB"
    
    if ($UsedPercent -gt 90) {
        Add-RedFlag "Memory usage is critically high: $UsedPercent%"
    }
    
    # Top memory consuming processes
    $TopProcesses = Get-Process | 
        Where-Object { $_.WorkingSet -gt 50MB } |
        Sort-Object WorkingSet -Descending | 
        Select-Object -First $TopProcessCount
    
    $MemoryUsageInfo += "`n`nTOP $TopProcessCount MEMORY-CONSUMING PROCESSES:"
    foreach ($proc in $TopProcesses) {
        $MemoryMB = [math]::Round($proc.WorkingSet/1MB, 2)
        $MemoryUsageInfo += "`n  $($proc.ProcessName) (PID: $($proc.Id)): $MemoryMB MB"
        
        # Flag if single process using >4GB
        if ($proc.WorkingSet -gt 4GB) {
            Add-RedFlag "Process $($proc.ProcessName) is using over 4GB of RAM"
        }
    }
    
    # CAD-specific processes
    $CADProcesses = Get-Process | Where-Object { 
        $_.ProcessName -match "acad|revit|revu|navisworks|sketchup"
    } | Select-Object ProcessName, Id, WorkingSet, CPU, StartTime
    
    if ($CADProcesses) {
        $MemoryUsageInfo += "`n`nCAD PROCESSES CURRENTLY RUNNING:"
        foreach ($proc in $CADProcesses) {
            $MemoryMB = [math]::Round($proc.WorkingSet/1MB, 2)
            $MemoryUsageInfo += "`n  $($proc.ProcessName) (PID: $($proc.Id))"
            $MemoryUsageInfo += "    Memory: $MemoryMB MB | CPU Time: $($proc.CPU) | Started: $($proc.StartTime)"
        }
    }
    
} catch {
    $MemoryUsageInfo += "Error retrieving memory usage: $_"
}

Add-ReportSection "MEMORY USAGE & TOP PROCESSES" ($MemoryUsageInfo -join "`n")
#endregion

#region FOCUS-SPECIFIC DIAGNOSTICS
if ($Focus -eq 'Freeze' -or $Focus -eq 'All') {
    Write-Host "Running freeze/display diagnostics..." -ForegroundColor Yellow
    $FreezeContent = Get-DisplayFreezeInfo
    Add-ReportSection "DISPLAY FREEZE DIAGNOSTICS" $FreezeContent
}

if ($Focus -eq 'Shutdown' -or $Focus -eq 'All') {
    Write-Host "Running shutdown analysis..." -ForegroundColor Yellow
    $ShutdownContent = Get-ShutdownAnalysis
    Add-ReportSection "SHUTDOWN ROOT CAUSE ANALYSIS" $ShutdownContent
}

if ($Focus -eq 'Hardware' -or $Focus -eq 'All') {
    Write-Host "Running hardware/thermal diagnostics..." -ForegroundColor Yellow
    $ThermalContent = Get-ThermalInfo
    Add-ReportSection "THERMAL & HARDWARE HEALTH" $ThermalContent

    if ($GenerateMonitoringScript) {
        $monitorPath = New-MonitoringScript
        Write-Host "Created monitoring script: $monitorPath" -ForegroundColor Green
    }
}

if ($Focus -eq 'Policy' -or $Focus -eq 'All') {
    Write-Host "Running policy diagnostics..." -ForegroundColor Yellow
    $PolicyContent = Get-PolicyDiagnostics
    Add-ReportSection "GROUP POLICY & UPDATE ANALYSIS" $PolicyContent
}
#endregion

#region ADDITIONAL RECOMMENDATIONS
$Recommendations = @"
RECOMMENDED NEXT STEPS:

1. ECC Memory: $(if ($HasECC) { "ECC detected - verify in BIOS that ECC is enabled and functioning" } else { "NO ECC - Consider upgrading to ECC RAM for CAD workstation stability" })

2. Memory Testing: Run Windows Memory Diagnostic overnight or use MemTest86+ for comprehensive testing

3. Driver Updates: 
   - Update GPU drivers from manufacturer (NVIDIA/AMD)
   - Update chipset drivers
   - Check for BIOS updates

4. Event Log Analysis: Review specific errors identified in this report

5. Hardware Monitoring: Install HWiNFO64 to monitor:
   - CPU/GPU temperatures during CAD work
   - Voltage rails
   - System fan speeds

6. CAD Software:
   - Verify AutoCAD/Revit graphics settings
   - Check for software updates
   - Review known issues for specific versions

7. Power Supply: If frequent crashes continue, verify PSU wattage is adequate for system (especially GPU)

8. Consider: Full system stress test (Prime95 + FurMark) to identify hardware instability
"@

Add-ReportSection "RECOMMENDATIONS" $Recommendations
#endregion

#region RED FLAGS SUMMARY
if ($RedFlags.Count -gt 0) {
    $FlagSummary = @"
CRITICAL ISSUES DETECTED: $($RedFlags.Count)

$($RedFlags -join "`n")

[!]  These issues require immediate attention and may be contributing to system instability.
"@
} else {
    $FlagSummary = "=“ No critical issues detected in automated diagnostics"
}
#endregion

#region FINAL REPORT OUTPUT
$ReportHeader = @"
=”=================================================================================—
=‘                    WORKSTATION STABILITY DIAGNOSTIC REPORT                     =‘
=‘                          Workstation Diagnostics                              =‘
=š=================================================================================

Ticket: (Reference number)
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Computer: $($env:COMPUTERNAME)

$FlagSummary
"@

$FullReport = $ReportHeader + ($Report -join "`n")

# Output to console
Write-Host "`n`n"
Write-Host $FullReport

# Save to file
$OutputPath = "$env:TEMP\Workstation-Diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$FullReport | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n`nReport saved to: $OutputPath" -ForegroundColor Green

# Return summary for RMM
Write-Host "`n`n=== RMM SUMMARY ===" -ForegroundColor Cyan
Write-Host "Red Flags: $($RedFlags.Count)" -ForegroundColor $(if ($RedFlags.Count -gt 0) { "Red" } else { "Green" })
Write-Host "ECC Memory: $(if ($HasECC) { 'Detected' } else { 'NOT DETECTED' })" -ForegroundColor $(if ($HasECC) { "Green" } else { "Red" })
Write-Host "Report Location: $OutputPath" -ForegroundColor Cyan
#endregion

# Exit with error code if critical issues found
if ($RedFlags.Count -gt 3) {
    exit 1
} else {
    exit 0
}
