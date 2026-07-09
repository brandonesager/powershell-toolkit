#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Invoke-IntuneDeviceWipe — Issue Intune remote wipe for target managed devices

.DESCRIPTION
    Sends Intune Wipe command to specified managed device IDs. Confirms each device
    name before issuing the wipe. Includes a verification pass to check wipe status
    after a brief wait.

    DESTRUCTIVE — wipes devices to factory reset (OOBE). Use with care.
    Supports -WhatIf for safe testing.

.PARAMETER DeviceIds
    Array of Intune managed device IDs (GUIDs). Required.
    Obtain from Find-IntuneDevicesByManufacturer.ps1 or Intune portal.

.PARAMETER KeepEnrollmentData
    Switch to preserve Intune enrollment record. Default: $false (full wipe).

.PARAMETER KeepUserData
    Switch to preserve user data during wipe. Default: $false (full wipe).

.EXAMPLE
    .\Invoke-IntuneDeviceWipe.ps1 -DeviceIds @("abc-123...", "def-456...")
    Prompts for confirmation then wipes all devices in the array

.EXAMPLE
    .\Invoke-IntuneDeviceWipe.ps1 -DeviceIds @("abc-123...") -WhatIf
    Shows what devices would be wiped without executing

.NOTES
    Date: 2026-02-06
    Category: M365-Entra
    Permissions Required: DeviceManagementManagedDevices.PrivilegedOperations.All

.KEYWORDS
    Intune, device, wipe, remediate, factory-reset
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$DeviceIds,

    [Parameter(Mandatory = $false)]
    [switch]$KeepEnrollmentData,

    [Parameter(Mandatory = $false)]
    [switch]$KeepUserData
)

$ErrorActionPreference = 'Stop'

if ($DeviceIds.Count -eq 0) {
    Write-Error "No device IDs specified. Provide at least one Intune managed device ID."
    return
}

#region Connect
$requiredScopes = @(
    'DeviceManagementManagedDevices.ReadWrite.All'
    'DeviceManagementManagedDevices.PrivilegedOperations.All'
)
$context = Get-MgContext
if ($context) {
    $hasPrivileged = $context.Scopes -contains 'DeviceManagementManagedDevices.PrivilegedOperations.All'
    if (-not $hasPrivileged) {
        Write-Host "Existing session lacks PrivilegedOperations scope — reconnecting..." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        $context = $null
    }
}
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes
}
#endregion

#region Pre-Wipe Confirmation
Write-Host "`n=== PRE-WIPE DEVICE LIST ===" -ForegroundColor Red
Write-Host "The following devices will be FACTORY RESET:`n" -ForegroundColor Red

$devices = foreach ($id in $DeviceIds) {
    try {
        $dev = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $id `
            -Property 'DeviceName,Model,UserDisplayName,SerialNumber,Id' -ErrorAction Stop
        [PSCustomObject]@{
            DeviceName      = $dev.DeviceName
            Model           = $dev.Model
            User            = $dev.UserDisplayName
            SerialNumber    = $dev.SerialNumber
            Id              = $dev.Id
        }
    } catch {
        Write-Warning "Could not retrieve device $id : $_"
    }
}

if ($devices.Count -eq 0) {
    Write-Error "No valid devices found. Verify device IDs."
    return
}

$devices | Format-Table -AutoSize
#endregion

#region Issue Wipe Commands
$results = foreach ($dev in $devices) {
    if ($PSCmdlet.ShouldProcess("$($dev.DeviceName) ($($dev.User))", "Intune Wipe")) {
        try {
            $wipeBody = @{
                keepEnrollmentData = $KeepEnrollmentData.IsPresent
                keepUserData = $KeepUserData.IsPresent
            } | ConvertTo-Json

            Invoke-MgGraphRequest -Method POST `
                "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($dev.Id)/wipe" `
                -ContentType 'application/json' -Body $wipeBody

            Write-Host "  Wipe initiated: $($dev.DeviceName) ($($dev.User))" -ForegroundColor Green
            [PSCustomObject]@{ Device = $dev.DeviceName; Status = 'Wipe Sent' }
        } catch {
            Write-Warning "  FAILED to wipe $($dev.DeviceName): $_"
            [PSCustomObject]@{ Device = $dev.DeviceName; Status = "FAILED: $_" }
        }
    }
}
#endregion

#region Results Summary
Write-Host "`n=== WIPE RESULTS ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
#endregion

#region Verification Pass
if (-not $WhatIfPreference) {
    Write-Host "Waiting 30 seconds before checking device status..." -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    Write-Host "`n=== POST-WIPE STATUS ===" -ForegroundColor Yellow
    $(foreach ($id in $DeviceIds) {
        try {
            $dev = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $id `
                -Property 'DeviceName,ManagementState,ComplianceState,LastSyncDateTime' -ErrorAction Stop
            [PSCustomObject]@{
                DeviceName      = $dev.DeviceName
                ManagementState = $dev.ManagementState
                ComplianceState = $dev.ComplianceState
                LastSync        = $dev.LastSyncDateTime
            }
        } catch {
            Write-Warning "Could not retrieve post-wipe status for $id"
        }
    }) | Format-Table -AutoSize

    Write-Host "Re-run the status check in a few minutes if devices haven't updated yet." -ForegroundColor Cyan
}
#endregion
