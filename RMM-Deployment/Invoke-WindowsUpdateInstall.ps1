#Requires -Version 5.1
#Requires -Modules PSWindowsUpdate

<#
.SYNOPSIS
    Invoke-WindowsUpdateInstall — Downloads and installs all available Windows Updates silently using PSWindowsUpdate

.DESCRIPTION
    Performs prerequisite checks, installs the PSWindowsUpdate module if needed,
    then uses it to find and install all available Windows Updates. Attempts to
    suppress immediate reboots initiated by the script, logs the process, and
    reports the outcome including whether a reboot is indicated by Windows Update.
    Logs are saved to the specified output path.

.PARAMETER OutputBasePath
    Specifies the base directory for logs. Default: C:\temp

.EXAMPLE
    .\Invoke-WindowsUpdateInstall.ps1
    Uses default output path C:\temp.

.EXAMPLE
    .\Invoke-WindowsUpdateInstall.ps1 -OutputBasePath "C:\Logs\WU"
    Specifies a custom output path.

.NOTES
    Category: RMM-Deployment
    - Uses the third-party PSWindowsUpdate module. Will attempt to install it if not found.
    - While the script uses '-IgnoreReboot', Windows Update itself may still register a reboot requirement.
    - Running Windows Updates can take a very long time.

.KEYWORDS
    update, RMM, SYSTEM, reboot, WindowsUpdate
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputBasePath = 'C:\temp'
)

# --- Configuration ---
$scriptStartTime = Get-Date
$logFileName = "WindowsUpdate_Install_Log_$($scriptStartTime.ToString('yyyyMMdd_HHmmss')).log"
$transcriptPath = Join-Path -Path $OutputBasePath -ChildPath $logFileName
$moduleName = "PSWindowsUpdate"

# --- Pre-Checks and Setup ---

# 1. Check for Administrator Privileges
Write-Verbose "Checking Administrator privileges..."
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with Administrator privileges. Please re-launch PowerShell as Administrator." -ErrorAction Stop
} else {
    Write-Verbose "Running with Administrator privileges."
}

# 2. Create Output Directory if it doesn't exist
Write-Verbose "Checking and creating output directory: $OutputBasePath"
if (-not (Test-Path -Path $OutputBasePath -PathType Container)) {
    New-Item -Path $OutputBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Verbose "Created directory: $OutputBasePath"
} else {
    Write-Verbose "Directory exists: $OutputBasePath"
}

# 3. Start Transcript Logging
Write-Verbose "Starting transcript logging to: $transcriptPath"
Start-Transcript -Path $transcriptPath -Force

Write-Host "--------------------------------------------------"
Write-Host "Starting Windows Update Installation Process"
Write-Host "Script Start Time: $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Output Base Path: $OutputBasePath"
Write-Host "Transcript Log: $logFileName"
Write-Host "--------------------------------------------------"

# 4. Check Execution Policy for Process Scope
Write-Verbose "Checking current process execution policy..."
$currentPolicy = Get-ExecutionPolicy -Scope Process -ErrorAction SilentlyContinue
Write-Verbose "Current Process Execution Policy: $currentPolicy"
if ($currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Bypass') {
    Write-Warning "Current process execution policy is '$currentPolicy'. Attempting to set to 'Bypass' for this session only."
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    Write-Verbose "Process Execution Policy set to Bypass for this session."
}

# 5. Check and Install PSWindowsUpdate Module
Write-Verbose "Checking if module '$moduleName' is installed..."
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Warning "Module '$moduleName' not found. Attempting to install..."
    Write-Host "This requires an internet connection and depends on PowerShellGet."
    Write-Verbose "Checking/Installing PowerShellGet..."
    Install-Module PowerShellGet -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
    Write-Verbose "Ensuring NuGet provider is installed..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop

    Write-Verbose "Installing $moduleName..."
    Install-Module -Name $moduleName -Scope CurrentUser -Force -AcceptLicense -SkipPublisherCheck -ErrorAction Stop
    Write-Host "Module '$moduleName' installed successfully for the current user."
} else {
    Write-Verbose "Module '$moduleName' is already installed."
}

# 6. Import the Module
Write-Verbose "Importing module '$moduleName'..."
Import-Module $moduleName -ErrorAction Stop
Write-Verbose "Module '$moduleName' imported successfully."

# 7. Basic Internet Connectivity Check for Windows Update
Write-Verbose "Performing basic connectivity check to Windows Update servers..."
$testWUServer = "fe2.update.microsoft.com"
$connectivityResult = Test-NetConnection -ComputerName $testWUServer -Port 443 -InformationLevel Quiet -ErrorAction Stop
if ($connectivityResult) {
    Write-Verbose "Connectivity check to a Windows Update server ($testWUServer) successful."
} else {
    Write-Warning "Connectivity check to $testWUServer failed. Updates may not download."
}

# --- Check for Updates ---
Write-Host "Checking for available Windows Updates..."
Write-Progress -Activity "Windows Update" -Status "Checking for available updates..." -PercentComplete 10

$availableUpdates = Get-WindowsUpdate -Verbose -ErrorAction Stop
Write-Host "Found $($availableUpdates.Count) available update(s)."

if ($availableUpdates.Count -gt 0) {
    Write-Host "Available Updates:"
    $availableUpdates | Format-Table -AutoSize Title, KB, Size
} else {
    Write-Host "No applicable Windows Updates found at this time."
    Write-Progress -Activity "Windows Update" -Status "No updates found." -PercentComplete 100 -Completed
    Stop-Transcript
    exit 0
}

# --- Install Updates ---
Write-Host "Attempting to download and install $($availableUpdates.Count) update(s)..."
Write-Host "This process can take a very long time and consume significant bandwidth/CPU."
Write-Progress -Activity "Windows Update" -Status "Downloading and Installing Updates..." -PercentComplete 30

$installResults = @()
$overallSuccess = $true
$rebootIsRequired = $false

try {
    $installResults = Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose -ErrorAction Stop

    Write-Verbose "Installation command completed. Analyzing results..."
    Write-Progress -Activity "Windows Update" -Status "Analyzing installation results..." -PercentComplete 90

    # Analyze results
    if ($null -ne $installResults -and $installResults.Count -gt 0) {
        Write-Host "Installation Results Summary:"
        if ($installResults[0].PSObject.Properties.Name -contains 'KBArticleID') {
            $installResults | Format-Table -AutoSize KBArticleID, Title, Status, RebootRequired
        } elseif ($installResults[0].PSObject.Properties.Name -contains 'KB') {
            $installResults | Format-Table -AutoSize KB, Title, Status, RebootRequired
        } else {
            $installResults | Format-Table -AutoSize Title, Status, RebootRequired
        }

        foreach ($result in $installResults) {
            if ($result.Status -ne 'Success' -and $result.Status -ne 'Installed') {
                $overallSuccess = $false
                $kbInfo = if ($result.PSObject.Properties.Name -contains 'KBArticleID') {$result.KBArticleID} elseif ($result.PSObject.Properties.Name -contains 'KB') {$result.KB} else {'N/A'}
                Write-Warning "Update $($kbInfo) ($($result.Title)) did not report success. Status: $($result.Status)"
            }
            if ($result.PSObject.Properties.Name -contains 'RebootRequired' -and $result.RebootRequired -eq $true) {
                $rebootIsRequired = $true
            }
        }
    } elseif ($null -eq $installResults) {
        Write-Warning "Install-WindowsUpdate returned no detailed results object. Checking if updates are still available..."
        $checkAgain = Get-WindowsUpdate -ErrorAction SilentlyContinue
        if ($checkAgain -and $checkAgain.Count -gt 0) {
            Write-Error "Updates still appear available after installation attempt. Installation likely failed or requires further action."
            $overallSuccess = $false
            if ($checkAgain | Where-Object { $_.RebootRequired -eq $true }) {
                $rebootIsRequired = $true
                Write-Warning "Some remaining updates indicate a reboot is required."
            }
        } else {
            Write-Host "No remaining applicable updates found after installation attempt. Assuming success."
            try {
                $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
                if ($autoUpdate.RebootRequired) {
                    $rebootIsRequired = $true
                    Write-Warning "WUA API confirms a reboot is required."
                }
            } catch {
                Write-Verbose "Could not check WUA API for reboot status: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-Error "An error occurred during the Windows Update installation process. Error: $($_.Exception.Message)"
    $overallSuccess = $false
}

Write-Progress -Activity "Windows Update" -Status "Installation process finished." -PercentComplete 100 -Completed

# --- Final Status Reporting ---
Write-Host "--------------------------------------------------"
Write-Host "Windows Update Installation Process Finished"

if ($overallSuccess) {
    Write-Host "Overall Status: SUCCESS"
    if ($rebootIsRequired) {
        Write-Warning "A REBOOT IS REQUIRED by Windows Update for installed updates to take full effect."
    } else {
        Write-Host "No immediate reboot indicated by the update process."
    }
} else {
    Write-Error "Overall Status: FAILURE"
    Write-Error "One or more updates failed to install or an error occurred during the process. Review the log above."
    if ($rebootIsRequired) {
        Write-Warning "A reboot might still be required for any updates that *did* succeed before the failure."
    }
}

# --- Completion ---
$scriptEndTime = Get-Date
$scriptDuration = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime
Write-Host "Script End Time: $($scriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Total Duration: $($scriptDuration.ToString())"
Write-Host "Full script transcript saved to: $transcriptPath"
Write-Host "--------------------------------------------------"

Stop-Transcript
