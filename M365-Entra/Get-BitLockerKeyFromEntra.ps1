<#
.SYNOPSIS
    Retrieve a BitLocker recovery key from Entra ID by Recovery Key ID, with device-name fallback.

.DESCRIPTION
    Primary lookup: matches by Recovery Key ID (partial or full GUID) across all tenant keys.
    Fallback: if -DeviceName is supplied and the key ID lookup returns no results, searches
    by device display name in active Entra directory and then in the deleted-devices recycle bin.

    Prints key ID, device ID, creation date, volume type, and the recovery password.
    Run from an already-connected Microsoft Graph session (BitLockerKey.Read.All and
    Device.Read.All scopes required).

.PARAMETER KeyId
    Recovery Key ID shown on the BitLocker recovery screen. Accepts full or partial GUID.
    When omitted, the script searches by -DeviceName only.

.PARAMETER DeviceName
    Fallback device display name to search when key ID lookup returns no results.

.NOTES
    Context:  Cloud (Microsoft Graph PowerShell, already connected)
    Platform: Microsoft 365 / Entra ID
    PS 5.1 compatible.

.KEYWORDS
    BitLocker, Entra, Graph, recovery key, device, purged, Get-MgInformationProtectionBitlockerRecoveryKey
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$KeyId = '',

    [string]$DeviceName = ''
)

function Show-KeyDetail {
    param($Key)
    $full = Get-MgInformationProtectionBitlockerRecoveryKey `
        -BitlockerRecoveryKeyId $Key.Id -Property 'key' -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        KeyId           = $Key.Id
        DeviceId        = $Key.DeviceId
        CreatedDateTime = $Key.CreatedDateTime
        VolumeType      = $Key.VolumeType
        RecoveryKey     = $full.Key
    } | Format-List
}

Write-Host "`n=== Fetching all BitLocker keys ===" -ForegroundColor Cyan
$allKeys = Get-MgInformationProtectionBitlockerRecoveryKey -All -ErrorAction Stop

$matched = @()

# Primary: Key ID match
if ($KeyId) {
    Write-Host "Searching by Key ID: $KeyId" -ForegroundColor Cyan
    $matched = @($allKeys | Where-Object { $_.Id -like "*$KeyId*" })

    if ($matched) {
        Write-Host "Found $($matched.Count) key(s) matching Key ID." -ForegroundColor Green
        foreach ($k in $matched) { Show-KeyDetail $k }
        return
    } else {
        Write-Host "No key matched by ID." -ForegroundColor Yellow
    }
}

# Fallback: device name
if ($DeviceName) {
    Write-Host "`nSearching by device name: $DeviceName" -ForegroundColor Cyan
    $device = Get-MgDevice -Filter "displayName eq '$DeviceName'" -ErrorAction SilentlyContinue

    if ($device) {
        Write-Host "Device found: $($device.DisplayName) | DeviceId: $($device.DeviceId)" -ForegroundColor Green
        $deviceKeys = $allKeys | Where-Object { $_.DeviceId -eq $device.DeviceId }

        if ($deviceKeys) {
            Write-Host "Found $($deviceKeys.Count) key(s) for device." -ForegroundColor Green
            foreach ($k in $deviceKeys) { Show-KeyDetail $k }
        } else {
            Write-Host "No BitLocker keys stored in Entra for this device." -ForegroundColor Red
            Write-Host "Device may have been re-imaged without key escrow, or encrypted outside Intune policy." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Device '$DeviceName' not found in active Entra directory." -ForegroundColor Red
        Write-Host "`nOptions:" -ForegroundColor Cyan
        Write-Host "  1. Check deleted devices: Get-MgDirectoryDeletedItemAsDevice" -ForegroundColor White
        Write-Host "  2. On hybrid-joined devices, check on-prem ADUC BitLocker Recovery tab" -ForegroundColor White
        Write-Host "  3. If no key exists, advise client: clean Windows reinstall via USB media" -ForegroundColor White

        Write-Host "`nChecking Entra recycle bin for '$DeviceName'..." -ForegroundColor Cyan
        $deleted = Get-MgDirectoryDeletedItemAsDevice -All -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $DeviceName }
        if ($deleted) {
            Write-Host "Found in deleted devices:" -ForegroundColor Yellow
            $deleted | Select-Object DisplayName, DeviceId, DeletedDateTime | Format-List
            Write-Host "Keys from a purged device are typically non-recoverable; escrow link is gone." -ForegroundColor Yellow
        } else {
            Write-Host "Not found in deleted devices recycle bin either." -ForegroundColor Red
        }
    }
} elseif (-not $KeyId) {
    Write-Host "Specify -KeyId, -DeviceName, or both." -ForegroundColor Yellow
}
