#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Find-IntuneDevicesByManufacturer — Locate Intune devices by manufacturer with client-side filtering

.DESCRIPTION
    Queries all devices for a given manufacturer via server-side filter, then applies
    client-side filtering to identify target users, models, or compliance states.

    The Intune API only supports limited OData filters (eq on manufacturer works;
    contains on model and userDisplayName does not), so client-side filtering is required
    for advanced queries.

    Interactive script — requires Graph authentication with device read permissions.

.PARAMETER Manufacturer
    Manufacturer name (e.g., "Microsoft Corporation", "Dell Inc."). Required.

.PARAMETER TargetUsers
    Array of user display name patterns to flag (e.g., @('User1', 'User2')).
    Optional. Performs case-insensitive regex match.

.PARAMETER TargetModels
    Array of model name patterns to flag (e.g., @('Surface Pro 6', 'Surface Pro 7')).
    Optional. Performs case-insensitive regex match.

.PARAMETER IncludeUnassigned
    Switch to flag devices with no assigned user or assigned to service account.
    Optional.

.EXAMPLE
    .\Find-IntuneDevicesByManufacturer.ps1 -Manufacturer "Microsoft Corporation" -TargetUsers @('User1', 'User2', 'User3')
    Finds all Microsoft devices and flags those assigned to target users

.EXAMPLE
    .\Find-IntuneDevicesByManufacturer.ps1 -Manufacturer "Dell Inc." -TargetModels @('Latitude 5420') -IncludeUnassigned
    Finds Dell Latitude 5420 devices and unassigned Dell devices

.NOTES
    Date: 2026-02-06
    Category: M365-Entra

.KEYWORDS
    Intune, device, diagnose, audit, manufacturer
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manufacturer,

    [Parameter(Mandatory = $false)]
    [string[]]$TargetUsers = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$TargetModels = @(),

    [Parameter(Mandatory = $false)]
    [switch]$IncludeUnassigned
)

$ErrorActionPreference = 'Stop'

#region Connect
$context = Get-MgContext
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -NoWelcome
}
#endregion

#region Query Devices
$selectProps = @(
    'DeviceName', 'Model', 'Manufacturer', 'SerialNumber',
    'UserDisplayName', 'UserPrincipalName',
    'LastSyncDateTime', 'ComplianceState', 'ManagementState',
    'EnrolledDateTime', 'OperatingSystem', 'OsVersion',
    'Id'
)

Write-Host "`nQuerying Intune for '$Manufacturer' devices..." -ForegroundColor Cyan

$allDevices = Get-MgDeviceManagementManagedDevice `
    -Filter "manufacturer eq '$Manufacturer'" `
    -Property ($selectProps -join ',') `
    -All

if (-not $allDevices) {
    Write-Host "No devices found for manufacturer '$Manufacturer'." -ForegroundColor Red
    return
}

Write-Host "Found $($allDevices.Count) total $Manufacturer device(s).`n" -ForegroundColor DarkGray
#endregion

#region Client-Side Filtering
$tagged = $allDevices | ForEach-Object {
    $flags = @()

    # Check user match
    if ($TargetUsers.Count -gt 0) {
        foreach ($pattern in $TargetUsers) {
            if ($_.UserDisplayName -match $pattern) {
                $flags += "USER: $pattern"
            }
        }
    }

    # Check model match
    if ($TargetModels.Count -gt 0) {
        foreach ($pattern in $TargetModels) {
            if ($_.Model -match $pattern) {
                $flags += "MODEL: $pattern"
            }
        }
    }

    # Check unassigned
    if ($IncludeUnassigned) {
        $isUnassigned = [string]::IsNullOrWhiteSpace($_.UserDisplayName) -or
                        $_.UserDisplayName -match 'Svc|Service Account|Admin'
        if ($isUnassigned) {
            $flags += "UNASSIGNED"
        }
    }

    [PSCustomObject]@{
        DeviceName  = $_.DeviceName
        Model       = $_.Model
        User        = $_.UserDisplayName
        Serial      = $_.SerialNumber
        LastSync    = if ($_.LastSyncDateTime) { $_.LastSyncDateTime.ToString('yyyy-MM-dd') } else { 'Never' }
        Compliance  = $_.ComplianceState
        Enrolled    = if ($_.EnrolledDateTime) { $_.EnrolledDateTime.ToString('yyyy-MM-dd') } else { '—' }
        OS          = "$($_.OperatingSystem) $($_.OsVersion)"
        Id          = $_.Id
        Flags       = if ($flags.Count -gt 0) { $flags -join ', ' } else { '' }
    }
} | Sort-Object Flags, User, DeviceName
#endregion

#region Display Results
Write-Host "=== ALL DEVICES ===" -ForegroundColor Yellow
$tagged | Format-Table DeviceName, Model, User, Serial, LastSync, Compliance, Flags -AutoSize

Write-Host "`n=== FLAGGED DEVICES ===" -ForegroundColor Red
$flagged = $tagged | Where-Object { $_.Flags -ne '' }

if ($flagged) {
    $flagged | Format-Table DeviceName, Model, User, Serial, Compliance, Id, Flags -AutoSize
    Write-Host "`nFound $($flagged.Count) flagged device(s). Copy the Id values for further action." -ForegroundColor Cyan
} else {
    Write-Host "No devices match the specified criteria." -ForegroundColor DarkYellow
}
#endregion
