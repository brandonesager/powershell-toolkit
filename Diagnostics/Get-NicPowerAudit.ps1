<#
.SYNOPSIS
    Audits NIC power management and advanced power settings as a baseline.
.DESCRIPTION
    Read-only audit of all network adapters. Reports:
    - Current Windows power plan
    - All adapter status snapshot
    - Per physical adapter: PnPCapabilities registry value and power management status
    - Advanced adapter properties related to power (EEE, Green Ethernet, Power Saving, Wake)
    - All advanced properties for full baseline capture

    Deploy via RMM to capture baseline before applying per-endpoint changes.
    Useful for diagnosing intermittent mapped drive drops caused by NIC power events.
.EXAMPLE
    .\Get-NicPowerAudit.ps1
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
.KEYWORDS
    NIC, power management, EEE, energy efficient ethernet, green ethernet,
    adapter, SMB drops, mapped drives, baseline audit
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

try {
    $computerName = $env:COMPUTERNAME
    Write-Output "=== NIC POWER AUDIT: $computerName ==="
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    # Section 1: Current Power Plan
    Write-Output "--- POWER PLAN ---"
    try {
        $planOutput = powercfg -getactivescheme
        Write-Output "Active plan: $planOutput"
    } catch {
        Write-Output "Active plan: (could not query powercfg)"
    }
    Write-Output ""

    # Section 2: All adapters -- status snapshot
    Write-Output "--- ADAPTER STATUS SNAPSHOT ---"
    $allAdapters = Get-NetAdapter
    foreach ($a in $allAdapters) {
        Write-Output "  $($a.Name) | $($a.InterfaceDescription) | Status: $($a.Status) | LinkSpeed: $($a.LinkSpeed)"
    }
    Write-Output ""

    # Section 3: Per-adapter detail (physical only)
    $physAdapters = Get-NetAdapter -Physical | Where-Object {
        $_.MediaType -eq '802.3' -or
        $_.InterfaceDescription -match 'Ethernet|Realtek|Intel|Broadcom|Killer|Marvell|Aquantia'
    }
    if (-not $physAdapters) {
        $physAdapters = Get-NetAdapter -Physical
    }

    $powerKeywords = @(
        'energy',
        'green',
        'power',
        'eee',
        'wake',
        'shutdown',
        'speed.*down',
        'low power'
    )

    $nicClassPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"

    foreach ($adapter in $physAdapters) {
        Write-Output "=========================================="
        Write-Output "ADAPTER: $($adapter.InterfaceDescription)"
        Write-Output "  Name:        $($adapter.Name)"
        Write-Output "  Status:      $($adapter.Status)"
        Write-Output "  LinkSpeed:   $($adapter.LinkSpeed)"
        Write-Output "  PnPDeviceID: $($adapter.PnPDeviceID)"
        Write-Output ""

        # Power Management tab (registry PnPCapabilities)
        Write-Output "  [Power Management Tab]"
        $pnpCap = $null
        try {
            $subkeys = Get-ChildItem -Path $nicClassPath -ErrorAction SilentlyContinue |
                       Where-Object { $_.PSChildName -match "^\d{4}$" }
            foreach ($subkey in $subkeys) {
                $devDesc = (Get-ItemProperty -Path $subkey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
                if ($devDesc -and $adapter.InterfaceDescription -and
                    $devDesc.Trim() -eq $adapter.InterfaceDescription.Trim()) {
                    $pnpCap = (Get-ItemProperty -Path $subkey.PSPath -Name "PnPCapabilities" -ErrorAction SilentlyContinue).PnPCapabilities
                    break
                }
            }
        } catch {
            Write-Output "  Registry lookup error: $($_.Exception.Message)"
        }

        if ($null -eq $pnpCap) {
            Write-Output "  PnPCapabilities: (not set / key not found)"
            Write-Output "  Power mgmt status: DEFAULT (OS may allow power-down)"
        } else {
            Write-Output "  PnPCapabilities: $pnpCap (0x$([Convert]::ToString($pnpCap,16).ToUpper()))"
            if ($pnpCap -eq 0x18 -or $pnpCap -eq 0x118 -or $pnpCap -ge 24) {
                Write-Output "  Power mgmt status: DISABLED (PnPCapabilities >= 0x18)"
            } else {
                Write-Output "  Power mgmt status: ENABLED (Allow computer to turn off this device)"
            }
        }
        Write-Output ""

        # Advanced properties: power-related
        Write-Output "  [Advanced Power Properties]"
        try {
            $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($advProps) {
                $powerProps = $advProps | Where-Object {
                    $dn = $_.DisplayName.ToLower()
                    $powerKeywords | Where-Object { $dn -match $_ }
                }
                if ($powerProps) {
                    foreach ($prop in $powerProps) {
                        Write-Output "  $($prop.DisplayName): $($prop.DisplayValue)"
                    }
                } else {
                    Write-Output "  (no power-related advanced properties found)"
                }

                Write-Output ""
                Write-Output "  [All Advanced Properties]"
                foreach ($prop in $advProps) {
                    Write-Output "  $($prop.DisplayName): $($prop.DisplayValue)"
                }
            } else {
                Write-Output "  (no advanced properties available for this adapter)"
            }
        } catch {
            Write-Output "  Advanced property query error: $($_.Exception.Message)"
        }
        Write-Output ""
    }

    Write-Output "=== AUDIT COMPLETE ==="
    exit 0

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
