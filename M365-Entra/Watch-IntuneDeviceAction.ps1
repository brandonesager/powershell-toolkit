#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Watch-IntuneDeviceAction — Poll Intune device status until action completes

.DESCRIPTION
    Polls managedDevice status at a configurable interval until all target devices
    reach a terminal state or the max poll count is reached. Handles 404 (device
    removed from Intune) as a successful terminal state rather than an error.

    Idempotent — safe to re-run at any time. Devices already in a terminal state
    are reported immediately without waiting.

.SOURCE
    Date: 2026-02-06
    Promoted: 2026-02-09

.PARAMETER DeviceIds
    Array of Intune managed device IDs (GUIDs) to monitor.

.PARAMETER PendingStates
    Management states that indicate the action is still in progress.
    Default: @('wipePending', 'wipePending_RetirePending', 'retirePending')

.PARAMETER PollIntervalSeconds
    Seconds between each status check. Default: 30.

.PARAMETER MaxPolls
    Maximum polling iterations before stopping. Default: 20 (~10 min at 30s).

.EXAMPLE
    .\Watch-IntuneDeviceAction.ps1 -DeviceIds @("abc-123...", "def-456...")
    Polls wipe status every 30 seconds, up to 20 times

.EXAMPLE
    .\Watch-IntuneDeviceAction.ps1 -DeviceIds @("abc-123...") -PollIntervalSeconds 60 -MaxPolls 30
    Polls every 60 seconds for up to 30 minutes

.EXAMPLE
    .\Watch-IntuneDeviceAction.ps1 -DeviceIds @("abc-123...") -PendingStates @('retirePending')
    Monitor a retire action instead of a wipe

.NOTES
    Date: 2026-02-09
    Category: M365-Entra

.KEYWORDS
    Intune, device, wipe, retire, poll, status, idempotent
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$DeviceIds,

    [string[]]$PendingStates = @('wipePending', 'wipePending_RetirePending', 'retirePending'),

    [ValidateRange(5, 600)]
    [int]$PollIntervalSeconds = 30,

    [ValidateRange(1, 999)]
    [int]$MaxPolls = 20
)

$ErrorActionPreference = 'Stop'

#region Connect
$context = Get-MgContext
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -NoWelcome
}
#endregion

$stillPending = @()

for ($i = 1; $i -le $MaxPolls; $i++) {
    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "`n=== POLL $i/$MaxPolls [$timestamp] ===" -ForegroundColor Yellow

    $statuses = foreach ($id in $DeviceIds) {
        try {
            $dev = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $id `
                -Property 'DeviceName,ManagementState,ComplianceState,LastSyncDateTime' -ErrorAction Stop
            [PSCustomObject]@{
                DeviceName      = $dev.DeviceName
                ManagementState = $dev.ManagementState
                ComplianceState = $dev.ComplianceState
                LastSync        = $dev.LastSyncDateTime
                Id              = $id
                Removed         = $false
            }
        } catch {
            if ($_ -match '404|NotFound|ResourceNotFound') {
                [PSCustomObject]@{
                    DeviceName      = "(id: $($id.Substring(0,8))...)"
                    ManagementState = 'Removed from Intune'
                    ComplianceState = '-'
                    LastSync        = '-'
                    Id              = $id
                    Removed         = $true
                }
            } else { throw }
        }
    }

    $statuses | Format-Table DeviceName, ManagementState, ComplianceState, LastSync -AutoSize

    $stillPending = $statuses | Where-Object {
        -not $_.Removed -and $_.ManagementState -in $PendingStates
    }

    if ($stillPending.Count -eq 0) {
        Write-Host "All devices have reached terminal state." -ForegroundColor Green
        break
    }

    Write-Host "$($stillPending.Count) device(s) still pending." -ForegroundColor Cyan

    if ($i -lt $MaxPolls) {
        Start-Sleep -Seconds $PollIntervalSeconds
    }
}

#region Final Summary
if ($stillPending.Count -gt 0) {
    Write-Host "`nMax polls reached. $($stillPending.Count) device(s) still pending:" -ForegroundColor Yellow
    $stillPending | Format-Table DeviceName, ManagementState -AutoSize
    Write-Host "Devices may be offline. Re-run later or check Intune portal." -ForegroundColor Cyan
}

# Return structured results for pipeline use
$statuses
#endregion
