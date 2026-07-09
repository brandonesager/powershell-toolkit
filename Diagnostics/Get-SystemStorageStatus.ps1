<#
.SYNOPSIS
    Gets disk space information for a specified drive.

.DESCRIPTION
    Retrieves detailed disk space information including total space, free space, and used space.

.PARAMETER None
    This script has no parameters.

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-SystemStorageStatus.ps1'

.NOTES
    Author: Brandon Sager
    Date: 2025-12-16
    
    Version : 1.0
    
    Requires:
    - PowerShell 5.1+
    - No external modules required
#>

function Get-SystemStorageStatus {
    
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Specify the drive letter to check (default is C)")]
        [ValidatePattern("^[A-Za-z]$")]
        [ValidateLength(1, 1)]
        [string]$DriveLetter = "C"
    )
    
    begin {
        Write-Verbose "Starting Get-SystemStorageStatus with DriveLetter: $DriveLetter"
    }
    
    process {
        try {
            Write-Verbose "Getting storage status for drive ${DriveLetter}:"
            
            # Log the operation if Write-LogText is available
            if (Get-Command Write-LogText -ErrorAction SilentlyContinue) {
                $logPath = Join-Path -Path $env:TEMP -ChildPath "ClearSystemStorage.log"
                Write-LogText -Message "Getting storage status for drive ${DriveLetter}:" -Level "INFO" -LogPath $logPath
            }
            
            $drive = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DeviceID -eq "${DriveLetter}:" }
            if ($drive) {
                $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                $totalGB = [math]::Round($drive.Size / 1GB, 2)
                $usedGB = [math]::Round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
                $percentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
                
                Write-Verbose "Drive ${DriveLetter}: - Total: ${totalGB}GB, Free: ${freeGB}GB, Used: ${usedGB}GB (${percentFree}%)"
                
                # Log the result if Write-LogText is available
                if (Get-Command Write-LogText -ErrorAction SilentlyContinue) {
                    Write-LogText -Message "Drive ${DriveLetter}: - Total: ${totalGB}GB, Free: ${freeGB}GB, Used: ${usedGB}GB (${percentFree}%)" -Level "INFO" -LogPath $logPath
                }
                
                return [PSCustomObject]@{
                    FreeGB      = $freeGB
                    TotalGB     = $totalGB
                    UsedGB      = $usedGB
                    PercentFree = $percentFree
                    Drive       = $DriveLetter
                }
            }
            else {
                $errorMessage = "Drive ${DriveLetter}: not found"
                
                # Log the error if Write-LogText is available
                if (Get-Command Write-LogText -ErrorAction SilentlyContinue) {
                    $logPath = Join-Path -Path $env:TEMP -ChildPath "ClearSystemStorage.log"
                    Write-LogText -Message $errorMessage -Level "ERROR" -LogPath $logPath
                }
                
                $exception = New-Object System.Management.Automation.ItemNotFoundException $errorMessage
                $errorId = "DriveNotFound"
                $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $DriveLetter
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $errorMessage = "Failed to query disk information. CIM/WMI services may not be available."
            
            # Log the error if Write-LogText is available
            if (Get-Command Write-LogText -ErrorAction SilentlyContinue) {
                $logPath = Join-Path -Path $env:TEMP -ChildPath "ClearSystemStorage.log"
                Write-LogText -Message $errorMessage -Level "ERROR" -LogPath $logPath
            }
            
            $exception = New-Object System.InvalidOperationException $errorMessage
            $errorId = "CimServiceUnavailable"
            $errorCategory = [System.Management.Automation.ErrorCategory]::ResourceUnavailable
            $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $DriveLetter
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        catch {
            $errorMessage = "Failed to get storage status for drive ${DriveLetter}: $($_.Exception.Message)"
            
            # Log the error if Write-LogText is available
            if (Get-Command Write-LogText -ErrorAction SilentlyContinue) {
                $logPath = Join-Path -Path $env:TEMP -ChildPath "ClearSystemStorage.log"
                Write-LogText -Message $errorMessage -Level "ERROR" -LogPath $logPath
            }
            
            $exception = New-Object System.InvalidOperationException $errorMessage
            $errorId = "GetStorageStatusFailed"
            $errorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified
            $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $DriveLetter
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
    
    end {
        Write-Verbose "Finished Get-SystemStorageStatus"
    }
}
