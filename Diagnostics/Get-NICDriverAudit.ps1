<#
.SYNOPSIS
    Audits NIC driver details across workstations — provider, version, and source (OEM vs generic).
.DESCRIPTION
    Gathers network adapter name, driver provider, version, date,
    and source (OEM vs Windows Update vs inbox) for physical Ethernet adapters.
    Targets physical Ethernet adapters only (skips virtual, WiFi, Bluetooth).

    OEM/Manufacturer drivers (oem*.inf) are preferred over Microsoft Generic
    drivers for stability. Use to verify fleet driver health after Win11 upgrade
    or when investigating NIC-related SMB/network drops.

    Also queries Windows Update history for recent network driver updates.
    Deploy via RMM for fleet-wide audit.
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
.KEYWORDS
    NIC, driver, Ethernet, OEM, generic, fleet, audit, network
#>

$ErrorActionPreference = "Stop"

try {
    $computerName = $env:COMPUTERNAME

    # Get physical Ethernet adapters only (skip virtual, WiFi, Bluetooth)
    $adapters = Get-NetAdapter -Physical | Where-Object {
        $_.MediaType -eq '802.3' -or $_.InterfaceDescription -match 'Ethernet|Realtek|Intel|Broadcom|Killer|Marvell|Aquantia'
    }

    if (-not $adapters) {
        $adapters = Get-NetAdapter -Physical
    }

    foreach ($adapter in $adapters) {
        # Get driver details from CIM
        $pnp = Get-CimInstance Win32_PnPSignedDriver | Where-Object {
            $_.DeviceID -eq $adapter.PnPDeviceID
        }

        # Determine driver source
        $driverSource = "Unknown"
        if ($pnp) {
            $infPath = $pnp.InfName
            if ($infPath) {
                # OEM-prefixed INF = third-party/manufacturer driver
                # Non-OEM = Windows inbox driver
                if ($infPath -match '^oem\d+\.inf$') {
                    $driverSource = "OEM/Manufacturer"
                } else {
                    $driverSource = "Windows Inbox/Generic"
                }
            }
            if ($pnp.DriverProviderName -eq "Microsoft") {
                $driverSource = "Microsoft Generic"
            }
        }

        Write-Output "=== NIC DRIVER AUDIT ==="
        Write-Output "Computer:        $computerName"
        Write-Output "Adapter:         $($adapter.InterfaceDescription)"
        Write-Output "Status:          $($adapter.Status)"
        Write-Output "Link Speed:      $($adapter.LinkSpeed)"
        Write-Output "MAC:             $($adapter.MacAddress)"
        Write-Output "Driver Provider: $(if ($pnp) { $pnp.DriverProviderName } else { 'N/A' })"
        Write-Output "Driver Version:  $(if ($pnp) { $pnp.DriverVersion } else { $adapter.DriverVersion })"
        Write-Output "Driver Date:     $(if ($pnp) { $pnp.DriverDate } else { 'N/A' })"
        Write-Output "INF File:        $(if ($pnp) { $pnp.InfName } else { 'N/A' })"
        Write-Output "Driver Source:   $driverSource"
        Write-Output "Hardware ID:     $(if ($pnp) { $pnp.HardwareID } else { 'N/A' })"
        Write-Output "========================"
    }

    # Windows Update history for recent network driver updates
    Write-Output ""
    Write-Output "=== RECENT DRIVER UPDATES (Windows Update) ==="
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min($count, 100))
            $driverUpdates = @($history | Where-Object {
                $_.Title -match 'network|ethernet|realtek|intel.*ethernet|broadcom|killer|NIC' -and
                $_.ResultCode -eq 2
            } | Select-Object -First 5)

            if ($driverUpdates.Count -gt 0) {
                foreach ($update in $driverUpdates) {
                    Write-Output "  $($update.Date.ToString('yyyy-MM-dd')): $($update.Title)"
                }
            } else {
                Write-Output "  No network driver updates found in recent Windows Update history"
            }
        }
    } catch {
        Write-Output "  Could not query Windows Update history: $($_.Exception.Message)"
    }
    Write-Output "========================"

    exit 0
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
