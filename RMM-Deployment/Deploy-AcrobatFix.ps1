<#
.SYNOPSIS
    Deploy Adobe Acrobat white screen remediation via RMM

.DESCRIPTION
    Deployment script with comprehensive safety checkpoints,
    error handling, and rollback mechanisms. Designed for RMM
    deployment with full logging and client safety protections.

    Supports two modes:
    - Diagnostic: Analyze system and create backup (no changes)
    - AutoRemediate: Apply fixes automatically (default)

.PARAMETER Mode
    Deployment mode: Diagnostic or AutoRemediate (default: AutoRemediate)

.PARAMETER CaseID
    PSA ticket/case ID for logging and tracking

.PARAMETER ClientName
    Client identifier for enhanced logging (auto-detected from hostname if not provided)

.PARAMETER SkipSafetyChecks
    Skip pre-deployment safety validations (not recommended)

.PARAMETER MaxExecutionTime
    Maximum script execution time in minutes (default: 10 minutes)

.PARAMETER ClientCode
    Client identifier for enhanced logging (auto-detected if not provided)

.EXAMPLE
    .\Deploy-AcrobatFix.ps1 -CaseID "12345" -ClientName "Jane Doe"

.EXAMPLE
    .\Deploy-AcrobatFix.ps1 -CaseID "12345" -ClientName "Jane Doe" -Mode Diagnostic

.NOTES
    Date: 2026-02-06
    Category: RMM-Deployment

.KEYWORDS
    Acrobat, remediate, RMM, SYSTEM, Adobe
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet("Diagnostic", "AutoRemediate")]
    [string]$Mode = "AutoRemediate",

    [Parameter(Mandatory)]
    [string]$CaseID,

    [Parameter(Mandatory)]
    [string]$ClientName,

    [switch]$SkipSafetyChecks,
    [int]$MaxExecutionTime = 10,
    [string]$ClientCode = "AUTO-DETECT"
)

$ErrorActionPreference = "Stop"

# Global Configuration
$Script:DeploymentConfig = @{
    CaseID = $CaseID
    ClientName = $ClientName
    ScriptVersion = "1.0"
    MaxExecutionTimeSeconds = $MaxExecutionTime * 60
    StartTime = Get-Date
    LogPrefix = "[RMM]"
    SafetyChecksPassed = $false
    BackupCreated = $false
    ChangesApplied = $false
}

# Safety Check Configuration
$Script:SafetyChecks = @{
    MinimumFreeSpace = 1GB
    RequiredServices = @("Themes", "AudioSrv")  # Basic Windows services
    ForbiddenProcesses = @("outlook.exe", "excel.exe", "winword.exe", "powerpnt.exe")  # Don't run during Office use
    MaxSystemLoad = 80  # CPU percentage
}

function Write-DeploymentLog {
    param(
        [string]$Level = "INFO",
        [string]$Code = "DEPLOY",
        [string]$Message,
        [hashtable]$Data = @{}
    )

    $LogData = $Data.Clone()
    $LogData["case_id"] = $Script:DeploymentConfig.CaseID
    $LogData["client"] = $Script:DeploymentConfig.ClientName
    $LogData["script_version"] = $Script:DeploymentConfig.ScriptVersion
    $LogData["timestamp"] = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $LogData["execution_mode"] = $Mode

    $JsonData = ($LogData | ConvertTo-Json -Compress) -replace '"', '\"'
    Write-Output "$($Script:DeploymentConfig.LogPrefix)|$Level|$Code|$Message|$JsonData"
}

function Test-ExecutionTimeout {
    $ElapsedTime = (Get-Date) - $Script:DeploymentConfig.StartTime
    if ($ElapsedTime.TotalSeconds -gt $Script:DeploymentConfig.MaxExecutionTimeSeconds) {
        Write-DeploymentLog -Level "ERROR" -Code "TIMEOUT" -Message "Script execution timeout exceeded" -Data @{
            "elapsed_seconds" = [int]$ElapsedTime.TotalSeconds
            "max_seconds" = $Script:DeploymentConfig.MaxExecutionTimeSeconds
        }
        return $false
    }
    return $true
}

function Invoke-PreDeploymentSafetyChecks {
    if ($SkipSafetyChecks) {
        Write-DeploymentLog -Level "WARN" -Code "SAFETY" -Message "Safety checks skipped per parameter - proceeding at risk"
        $Script:DeploymentConfig.SafetyChecksPassed = $true
        return $true
    }

    Write-DeploymentLog -Code "SAFETY" -Message "Executing pre-deployment safety checks"

    $SafetyResults = @{
        "disk_space_check" = $false
        "system_load_check" = $false
        "critical_services_check" = $false
        "process_conflict_check" = $false
        "admin_privileges_check" = $false
        "overall_result" = $false
    }

    try {
        # Check 1: Sufficient disk space
        $SystemDrive = $env:SystemDrive
        $FreeSpace = (Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $SystemDrive}).FreeSpace
        if ($FreeSpace -gt $Script:SafetyChecks.MinimumFreeSpace) {
            $SafetyResults.disk_space_check = $true
        } else {
            Write-DeploymentLog -Level "ERROR" -Code "SAFETY" -Message "Insufficient disk space for safe operation" -Data @{
                "free_space_gb" = [math]::Round($FreeSpace / 1GB, 2)
                "required_gb" = [math]::Round($Script:SafetyChecks.MinimumFreeSpace / 1GB, 2)
            }
        }

        # Check 2: System load acceptable
        $CPULoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        if ($CPULoad -lt $Script:SafetyChecks.MaxSystemLoad) {
            $SafetyResults.system_load_check = $true
        } else {
            Write-DeploymentLog -Level "WARN" -Code "SAFETY" -Message "High system load detected" -Data @{
                "cpu_load_percent" = $CPULoad
                "max_load_percent" = $Script:SafetyChecks.MaxSystemLoad
            }
        }

        # Check 3: Critical services running
        $ServiceStatus = $true
        foreach ($ServiceName in $Script:SafetyChecks.RequiredServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $Service -or $Service.Status -ne "Running") {
                $ServiceStatus = $false
                Write-DeploymentLog -Level "WARN" -Code "SAFETY" -Message "Required service not running" -Data @{
                    "service_name" = $ServiceName
                    "status" = $Service.Status
                }
                break
            }
        }
        $SafetyResults.critical_services_check = $ServiceStatus

        # Check 4: No conflicting processes
        $ConflictingProcesses = @()
        foreach ($ProcessName in $Script:SafetyChecks.ForbiddenProcesses) {
            $Process = Get-Process -Name $ProcessName.Replace(".exe", "") -ErrorAction SilentlyContinue
            if ($Process) {
                $ConflictingProcesses += $ProcessName
            }
        }

        if ($ConflictingProcesses.Count -eq 0) {
            $SafetyResults.process_conflict_check = $true
        } else {
            Write-DeploymentLog -Level "WARN" -Code "SAFETY" -Message "Potentially conflicting processes detected" -Data @{
                "processes" = $ConflictingProcesses
                "recommendation" = "Consider running during maintenance window"
            }
            # Allow to proceed but with warning
            $SafetyResults.process_conflict_check = $true
        }

        # Check 5: Administrative privileges (for registry operations)
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $SafetyResults.admin_privileges_check = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $SafetyResults.admin_privileges_check) {
            Write-DeploymentLog -Level "ERROR" -Code "SAFETY" -Message "Administrative privileges required for registry modifications"
        }

        # Overall safety assessment
        $CriticalChecks = @($SafetyResults.disk_space_check, $SafetyResults.admin_privileges_check)
        $SafetyResults.overall_result = $CriticalChecks -notcontains $false

        if ($SafetyResults.overall_result) {
            Write-DeploymentLog -Level "SUCCESS" -Code "SAFETY" -Message "Pre-deployment safety checks passed" -Data $SafetyResults
            $Script:DeploymentConfig.SafetyChecksPassed = $true
        } else {
            Write-DeploymentLog -Level "ERROR" -Code "SAFETY" -Message "Pre-deployment safety checks failed" -Data $SafetyResults
        }

        return $SafetyResults.overall_result

    } catch {
        Write-DeploymentLog -Level "ERROR" -Code "SAFETY" -Message "Safety check execution failed" -Data @{
            "error" = $_.Exception.Message
        }
        return $false
    }
}

function Get-ClientEnvironmentInfo {
    Write-DeploymentLog -Code "ENV_DETECT" -Message "Detecting client environment information"

    try {
        $EnvInfo = @{
            "computer_name" = $env:COMPUTERNAME
            "domain" = $env:USERDOMAIN
            "username" = $env:USERNAME
            "os_version" = (Get-CimInstance Win32_OperatingSystem).Caption
            "architecture" = $env:PROCESSOR_ARCHITECTURE
            "powershell_version" = $PSVersionTable.PSVersion.ToString()
            "execution_policy" = Get-ExecutionPolicy
        }

        # Auto-detect client code if not provided
        if ($ClientCode -eq "AUTO-DETECT") {
            # Try various methods to identify client
            $DetectedClient = $env:COMPUTERNAME

            # Check for common client naming patterns
            if ($env:COMPUTERNAME -match '^([A-Z]{2,4})-') {
                $DetectedClient = $Matches[1]
            } elseif ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
                $DetectedClient = $env:USERDOMAIN
            }

            $Script:DeploymentConfig.ClientName = $DetectedClient
            $EnvInfo["detected_client_code"] = $DetectedClient
        } else {
            $Script:DeploymentConfig.ClientName = $ClientCode
            $EnvInfo["provided_client_code"] = $ClientCode
        }

        Write-DeploymentLog -Code "ENV_DETECT" -Message "Client environment detected" -Data $EnvInfo
        return $EnvInfo

    } catch {
        Write-DeploymentLog -Level "ERROR" -Code "ENV_DETECT" -Message "Failed to detect client environment" -Data @{
            "error" = $_.Exception.Message
        }
        return @{}
    }
}

function Invoke-DiagnosticScript {
    Write-DeploymentLog -Code "DIAGNOSTIC" -Message "Executing diagnostic script"

    try {
        # Check if diagnostic script exists in same directory
        $DiagnosticScript = Join-Path (Split-Path $MyInvocation.ScriptName) "Diagnose-AcrobatWhiteScreen.ps1"

        if (-not (Test-Path $DiagnosticScript)) {
            Write-DeploymentLog -Level "ERROR" -Code "DIAGNOSTIC" -Message "Diagnostic script not found" -Data @{
                "expected_path" = $DiagnosticScript
            }
            return $false
        }

        # Execute diagnostic with appropriate parameters
        $DiagnosticParams = @{
            BackupConfig = $true
            SkipPluginScan = $false
        }

        if ($Mode -eq "AutoRemediate") {
            $DiagnosticParams.AutoRemediate = $true
        }

        Write-DeploymentLog -Code "DIAGNOSTIC" -Message "Launching diagnostic script" -Data $DiagnosticParams

        # Execute the diagnostic script
        $DiagnosticOutput = & $DiagnosticScript @DiagnosticParams 2>&1

        # Parse the output for success indicators
        $SuccessPattern = "\[RMM\]\|SUCCESS\|COMPLETE\|"
        $ErrorPattern = "\[RMM\]\|ERROR\|"

        $HasSuccess = $DiagnosticOutput -match $SuccessPattern
        $HasErrors = $DiagnosticOutput -match $ErrorPattern

        if ($HasSuccess -and -not $HasErrors) {
            Write-DeploymentLog -Level "SUCCESS" -Code "DIAGNOSTIC" -Message "Diagnostic script completed successfully"
            $Script:DeploymentConfig.ChangesApplied = $Mode -eq "AutoRemediate"
            return $true
        } elseif ($HasErrors) {
            Write-DeploymentLog -Level "ERROR" -Code "DIAGNOSTIC" -Message "Diagnostic script reported errors"
            return $false
        } else {
            Write-DeploymentLog -Level "WARN" -Code "DIAGNOSTIC" -Message "Diagnostic script completed with unknown status"
            return $true  # Proceed cautiously
        }

    } catch {
        Write-DeploymentLog -Level "ERROR" -Code "DIAGNOSTIC" -Message "Diagnostic script execution failed" -Data @{
            "error" = $_.Exception.Message
        }
        return $false
    }
}

function Invoke-EmergencyRollback {
    Write-DeploymentLog -Level "WARN" -Code "ROLLBACK" -Message "Initiating emergency rollback procedures"

    try {
        # Look for backup files in temp directory
        $BackupPattern = "C:\Temp\AcrobatBackup_*.json"
        $BackupFiles = Get-ChildItem -Path $BackupPattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending

        if ($BackupFiles) {
            $LatestBackup = $BackupFiles[0].FullName
            Write-DeploymentLog -Code "ROLLBACK" -Message "Found recent backup file" -Data @{
                "backup_file" = $LatestBackup
                "backup_age_minutes" = [int]((Get-Date) - $BackupFiles[0].LastWriteTime).TotalMinutes
            }

            # Check if rollback script exists
            $RollbackScript = Join-Path (Split-Path $MyInvocation.ScriptName) "Restore-AcrobatSettings.ps1"

            if (Test-Path $RollbackScript) {
                Write-Output "Executing emergency rollback..."
                & $RollbackScript -BackupFile $LatestBackup -Force

                Write-DeploymentLog -Level "SUCCESS" -Code "ROLLBACK" -Message "Emergency rollback completed"
            } else {
                Write-DeploymentLog -Level "ERROR" -Code "ROLLBACK" -Message "Rollback script not found - manual intervention required"
                Write-Output "ERROR: Rollback script not found. Manual restoration required."
                Write-Output "Backup file location: $LatestBackup"
            }
        } else {
            Write-DeploymentLog -Level "ERROR" -Code "ROLLBACK" -Message "No backup files found for rollback"
            Write-Output "ERROR: No backup files found. Cannot perform automatic rollback."
        }

    } catch {
        Write-DeploymentLog -Level "ERROR" -Code "ROLLBACK" -Message "Emergency rollback failed" -Data @{
            "error" = $_.Exception.Message
        }
        Write-Output "CRITICAL ERROR: Rollback failed. Manual intervention required."
    }
}

# Main execution flow
try {
    Write-DeploymentLog -Code "START" -Message "Adobe Acrobat remediation deployment starting" -Data @{
        "mode" = $Mode
        "skip_safety_checks" = $SkipSafetyChecks.IsPresent
        "max_execution_minutes" = $MaxExecutionTime
    }

    # Get client environment information
    $EnvInfo = Get-ClientEnvironmentInfo

    # Execute pre-deployment safety checks
    if (-not (Invoke-PreDeploymentSafetyChecks)) {
        Write-DeploymentLog -Level "ERROR" -Code "ABORT" -Message "Safety checks failed - deployment aborted"
        Write-Output "DEPLOYMENT ABORTED: Safety checks failed. Review log output for details."
        exit 1
    }

    # Check execution timeout
    if (-not (Test-ExecutionTimeout)) {
        Write-Output "TIMEOUT: Maximum execution time exceeded. Exiting."
        exit 1
    }

    # Handle deployment modes
    switch ($Mode) {
        "Diagnostic" {
            Write-Output "Running diagnostic analysis..."
            $Success = Invoke-DiagnosticScript
            if ($Success) {
                Write-Output "Diagnostic completed successfully. Review output above for findings."
            } else {
                Write-Output "Diagnostic encountered issues. Check log output for details."
                exit 1
            }
        }

        "AutoRemediate" {
            Write-Output "Applying automated remediation..."
            $Success = Invoke-DiagnosticScript
            if ($Success) {
                Write-Output "Auto-remediation completed. Please test Adobe Acrobat functionality."
                Write-Output "User should restart Adobe Acrobat and test with a PDF file."
            } else {
                Write-Output "Auto-remediation failed. Consider manual approach or escalation."
                Invoke-EmergencyRollback
                exit 1
            }
        }
    }

    Write-DeploymentLog -Level "SUCCESS" -Code "COMPLETE" -Message "Deployment workflow completed" -Data @{
        "mode" = $Mode
        "safety_checks_passed" = $Script:DeploymentConfig.SafetyChecksPassed
        "changes_applied" = $Script:DeploymentConfig.ChangesApplied
        "execution_time_minutes" = [math]::Round(((Get-Date) - $Script:DeploymentConfig.StartTime).TotalMinutes, 2)
    }

    exit 0

} catch {
    Write-DeploymentLog -Level "ERROR" -Code "EXCEPTION" -Message "Unhandled exception during deployment" -Data @{
        "error" = $_.Exception.Message
        "stack_trace" = $_.ScriptStackTrace
    }

    Write-Output "CRITICAL ERROR: Unhandled exception occurred."
    Write-Output "Error: $($_.Exception.Message)"

    if ($Script:DeploymentConfig.ChangesApplied) {
        Write-Output "Changes were applied before error. Attempting rollback..."
        Invoke-EmergencyRollback
    }

    exit 1
}
