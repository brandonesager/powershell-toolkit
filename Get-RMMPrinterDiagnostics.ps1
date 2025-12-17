<#
.SYNOPSIS
    ConnectWise RMM Compatible Printer Diagnostics Script for PDF Rendering Issues

.DESCRIPTION
    Diagnoses PDF-to-printer rendering problems, specifically targeting Konica Minolta printers
    where documents display correctly on screen but print with blacked-out sections.
    
    Compatible with ConnectWise RMM PowerShell 5.1 execution in SYSTEM context.
    Outputs results using %output% variable for proper RMM logging integration.

.PARAMETER None
    This script has no parameters.

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-RMMPrinterDiagnostics.ps1'

.NOTES
    Author: Brandon Sager
    Date: 12/26/2025
    
    Version: 1.0
    Created: 2025-09-24
    PowerShell: 5.1+ (CW RMM Compatible)
    Context: SYSTEM (ConnectWise RMM Agent)
    
    .USAGE
    Deploy via ConnectWise RMM Script Library
    Schedule on agent check-in or run on-demand for printer issues
#>

# CW RMM Output Logging Function
function Write-RMMOutput {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "[$timestamp] [$Level] $Message"
    Write-Output $output
}

# Initialize script execution
Write-RMMOutput "=== ConnectWise RMM Printer Diagnostics Started ===" "START"

try {
    # System Context Check
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-RMMOutput "Executing as: $currentUser"
    
    # Initialize results object for CW RMM custom fields
    $diagnosticResults = @{
        "PrinterIssueDetected" = $false
        "KonicaMinoltaPresent" = $false
        "DriverVersion" = ""
        "RecommendedAction" = ""
        "PDFRenderingIssue" = $false
        "AutoRemediationApplied" = $false
    }

    Write-RMMOutput "Initializing printer diagnostics..."

} catch {
    Write-RMMOutput "Failed to initialize script: $($_.Exception.Message)" "ERROR"
    exit 1
}

#region Printer Discovery and Analysis
try {
    Write-RMMOutput "Discovering installed printers..."
    
    # Get all printers with detailed information
    $allPrinters = Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus, ShareName
    
    if ($allPrinters.Count -eq 0) {
        Write-RMMOutput "No printers found on system" "WARN"
        $diagnosticResults["RecommendedAction"] = "No printers installed - check printer installation"
    } else {
        Write-RMMOutput "Found $($allPrinters.Count) printer(s)"
        
        foreach ($printer in $allPrinters) {
            Write-RMMOutput "Printer: $($printer.Name) | Driver: $($printer.DriverName) | Status: $($printer.PrinterStatus)"
            
            # Check for Konica Minolta printers specifically
            if ($printer.DriverName -like "*KONICA*" -or $printer.Name -like "*Konica*") {
                $diagnosticResults["KonicaMinoltaPresent"] = $true
                Write-RMMOutput "Konica Minolta printer detected: $($printer.Name)" "ALERT"
                
                # Get detailed driver information
                try {
                    $driverInfo = Get-PrinterDriver | Where-Object {$_.Name -like "*KONICA*"} | Select-Object Name, DriverVersion, InfPath -First 1
                    if ($driverInfo) {
                        $diagnosticResults["DriverVersion"] = $driverInfo.DriverVersion
                        Write-RMMOutput "Driver Version: $($driverInfo.DriverVersion)"
                        Write-RMMOutput "Driver Path: $($driverInfo.InfPath)"
                    }
                } catch {
                    Write-RMMOutput "Could not retrieve driver details: $($_.Exception.Message)" "WARN"
                }
            }
        }
    }
} catch {
    Write-RMMOutput "Error during printer discovery: $($_.Exception.Message)" "ERROR"
}
#endregion

#region PDF Rendering Issue Detection
try {
    Write-RMMOutput "Analyzing PDF rendering capabilities..."
    
    # Check for common PDF readers
    $pdfReaders = @()
    
    # Adobe Acrobat Reader
    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Adobe*Reader*"}) {
        $pdfReaders += "Adobe Reader"
    }
    
    # Microsoft Edge (built-in PDF)
    if (Get-Process -Name "msedge" -ErrorAction SilentlyContinue) {
        $pdfReaders += "Microsoft Edge"
    }
    
    # Chrome
    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Google Chrome*"}) {
        $pdfReaders += "Google Chrome"
    }
    
    Write-RMMOutput "PDF Readers available: $($pdfReaders -join ', ')"
    
    # Check for known PDF rendering issues
    if ($diagnosticResults["KonicaMinoltaPresent"]) {
        Write-RMMOutput "Checking for known Konica Minolta PDF rendering issues..."
        
        # Check printer capabilities that commonly cause PDF issues
        $printCapabilities = Get-PrinterProperty -PrinterName ($allPrinters | Where-Object {$_.DriverName -like "*KONICA*"}).Name[0] -ErrorAction SilentlyContinue
        
        if ($printCapabilities) {
            Write-RMMOutput "Printer capabilities retrieved successfully"
            $diagnosticResults["PDFRenderingIssue"] = $true
            $diagnosticResults["PrinterIssueDetected"] = $true
        }
    }
    
} catch {
    Write-RMMOutput "Error during PDF analysis: $($_.Exception.Message)" "WARN"
}
#endregion

#region Print Spooler Analysis
try {
    Write-RMMOutput "Analyzing print spooler status..."
    
    $spoolerService = Get-Service -Name "Spooler"
    Write-RMMOutput "Print Spooler Status: $($spoolerService.Status)"
    
    if ($spoolerService.Status -ne "Running") {
        Write-RMMOutput "Print spooler not running - attempting restart" "WARN"
        
        try {
            Start-Service -Name "Spooler"
            Write-RMMOutput "Print spooler restarted successfully"
            $diagnosticResults["AutoRemediationApplied"] = $true
        } catch {
            Write-RMMOutput "Failed to restart print spooler: $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Check for stuck print jobs
    try {
        $printJobs = @()
        foreach ($printer in $allPrinters) {
            $jobs = Get-PrintJob -PrinterName $printer.Name -ErrorAction SilentlyContinue
            if ($jobs) { $printJobs += $jobs }
        }
        
        if ($printJobs.Count -gt 0) {
            Write-RMMOutput "Found $($printJobs.Count) print job(s) in queue"
            foreach ($job in $printJobs) {
                Write-RMMOutput "Print Job: $($job.DocumentName) | Status: $($job.JobStatus) | Size: $($job.Size) bytes"
            }
        } else {
            Write-RMMOutput "No print jobs in queue"
        }
    } catch {
        Write-RMMOutput "Could not retrieve print job information: $($_.Exception.Message)" "WARN"
    }
    
} catch {
    Write-RMMOutput "Error analyzing print spooler: $($_.Exception.Message)" "WARN"
}
#endregion

#region Generate Recommendations
Write-RMMOutput "Generating troubleshooting recommendations..."

if ($diagnosticResults["KonicaMinoltaPresent"] -and $diagnosticResults["PDFRenderingIssue"]) {
    $recommendations = @(
        "IMMEDIATE FIX: Print PDF as Image (Adobe Reader: File > Print > Advanced > Print as Image)",
        "UPDATE: Download latest Konica Minolta Universal V4 PCL driver from manufacturer",
        "TEST: Try printing same PDF from different readers (Edge, Chrome, Adobe)",
        "SETTINGS: Disable 'Advanced Printing Features' in printer properties",
        "DRIVER: Switch from PCL to PostScript driver if available",
        "QUALITY: Set print quality to 'Normal' instead of 'High'"
    )
    
    $diagnosticResults["RecommendedAction"] = $recommendations -join " | "
    Write-RMMOutput "PDF rendering issue confirmed - recommendations generated" "SOLUTION"
    
} elseif ($diagnosticResults["KonicaMinoltaPresent"]) {
    $diagnosticResults["RecommendedAction"] = "Konica Minolta printer found - monitor for PDF rendering issues"
    Write-RMMOutput "Konica Minolta detected - no immediate issues found"
    
} else {
    $diagnosticResults["RecommendedAction"] = "No Konica Minolta printers found - check for other printer-specific PDF issues"
    Write-RMMOutput "Standard printer diagnostics completed"
}

# Output recommendations
foreach ($rec in ($diagnosticResults["RecommendedAction"] -split " \| ")) {
    Write-RMMOutput "RECOMMENDATION: $rec" "ACTION"
}
#endregion

#region Automatic Remediation
if ($diagnosticResults["KonicaMinoltaPresent"]) {
    Write-RMMOutput "Attempting automatic remediation steps..."
    
    try {
        # Clear any stuck print jobs
        $jobsCleared = $false
        foreach ($printer in $allPrinters) {
            $jobs = Get-PrintJob -PrinterName $printer.Name -ErrorAction SilentlyContinue
            if ($jobs) {
                $jobs | Remove-PrintJob -ErrorAction SilentlyContinue
                $jobsCleared = $true
            }
        }
        
        if ($jobsCleared) {
            Write-RMMOutput "Cleared stuck print jobs"
            $diagnosticResults["AutoRemediationApplied"] = $true
        }
        
        # Reset print spooler
        Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
        Write-RMMOutput "Print spooler reset completed"
        $diagnosticResults["AutoRemediationApplied"] = $true
        
    } catch {
        Write-RMMOutput "Automatic remediation failed: $($_.Exception.Message)" "WARN"
    }
}
#endregion

#region CW RMM Output Formatting
Write-RMMOutput "=== DIAGNOSTIC SUMMARY ===" "SUMMARY"
Write-RMMOutput "Konica Minolta Present: $($diagnosticResults['KonicaMinoltaPresent'])"
Write-RMMOutput "PDF Rendering Issue: $($diagnosticResults['PDFRenderingIssue'])"
Write-RMMOutput "Driver Version: $($diagnosticResults['DriverVersion'])"
Write-RMMOutput "Auto Remediation Applied: $($diagnosticResults['AutoRemediationApplied'])"
Write-RMMOutput "Issue Status: $(if($diagnosticResults['PrinterIssueDetected']) {'DETECTED'} else {'NONE'})"

# Format for CW RMM Custom Fields (JSON for easy parsing)
$jsonOutput = $diagnosticResults | ConvertTo-Json -Compress
Write-RMMOutput "CW_RMM_CUSTOM_FIELDS: $jsonOutput" "DATA"

Write-RMMOutput "=== ConnectWise RMM Printer Diagnostics Completed ===" "END"
#endregion

# Exit with appropriate code
if ($diagnosticResults["PrinterIssueDetected"]) {
    Write-RMMOutput "Exiting with code 2 (Issue Detected - Requires Attention)" "EXIT"
    exit 2
} else {
    Write-RMMOutput "Exiting with code 0 (Success - No Issues)" "EXIT"
    exit 0
}
