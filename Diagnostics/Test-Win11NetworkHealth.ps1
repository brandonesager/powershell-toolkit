<#
.SYNOPSIS
    Win11 24H2 network health check — KB presence, update history, NDIS filters, TCP/IP registry, network services.
.DESCRIPTION
    Fleet diagnostic for evaluating Win11 24H2 network regression factors. Checks:
    1. Specific KB presence and install date (configurable via $KBToCheck)
    2. Windows Update history since a configurable cutoff date
    3. Third-party NDIS filter driver bindings (non-ms_* components)
    4. TCP/IP interface registry health (DhcpIPAddress, DhcpSubnetMask)
    5. Network service startup types and status (NLA, netprofm, DHCP, DNS, Workstation)
    6. OS build for context

    Originally developed to investigate KB5044284 correlation with mapped drive drops
    on Win11 24H2 fleets. Generalizable to any KB-linked network regression.
.NOTES
    Context:  RMM (SYSTEM), PS 5.1, read-only diagnostic
    Platform: Windows 10/11
.KEYWORDS
    KB5044284, Win11, 24H2, network regression, NLA, NDIS, filter driver, network services
#>

param(
    # KB article to check (e.g., "KB5044284"). Leave empty to skip KB-specific check.
    [string]$KBToCheck = "KB5044284",
    # Only report updates installed on or after this date
    [datetime]$UpdateCutoff = "2026-01-01"
)

$ErrorActionPreference = "Stop"

try {
    $computer = $env:COMPUTERNAME
    Write-Output "=== WIN11 NETWORK HEALTH CHECK: $computer ==="
    Write-Output ""

    # 1. Specific KB via Get-HotFix
    if ($KBToCheck -ne "") {
        Write-Output "--- $KBToCheck Status ---"
        $kb = Get-HotFix -Id $KBToCheck -ErrorAction SilentlyContinue
        if ($kb) {
            Write-Output "INSTALLED: $KBToCheck"
            Write-Output "  InstalledOn: $($kb.InstalledOn)"
            Write-Output "  InstalledBy: $($kb.InstalledBy)"
            Write-Output "  Description: $($kb.Description)"
        }
        else {
            Write-Output "NOT FOUND via Get-HotFix: $KBToCheck"
        }
        Write-Output ""
    }

    # 2. Windows Update history (COM) — catches updates Get-HotFix misses
    Write-Output "--- Windows Update History (since $($UpdateCutoff.ToString('yyyy-MM-dd'))) ---"
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $history = $searcher.QueryHistory(0, $total)
            $relevant = $history | Where-Object {
                $_.Date -ge $UpdateCutoff -and $_.ResultCode -eq 2
            } | Sort-Object Date -Descending

            if ($relevant) {
                foreach ($entry in $relevant) {
                    $date = $entry.Date.ToString("yyyy-MM-dd HH:mm")
                    $title = $entry.Title
                    $flag = if ($KBToCheck -ne "" -and $title -match $KBToCheck) { " <<<" } else { "" }
                    Write-Output "  $date | $title$flag"
                }
            }
            else {
                Write-Output "  No updates found since $($UpdateCutoff.ToString('yyyy-MM-dd'))"
            }
        }
        else {
            Write-Output "  Update history empty"
        }
    }
    catch {
        Write-Output "  COM query failed: $($_.Exception.Message)"
        Write-Output "  Fallback: Get-HotFix (since $($UpdateCutoff.ToString('yyyy-MM-dd'))):"
        $allKb = Get-HotFix | Where-Object {
            $_.InstalledOn -ge $UpdateCutoff
        } | Sort-Object InstalledOn -Descending
        foreach ($h in $allKb) {
            Write-Output "    $($h.InstalledOn.ToString('yyyy-MM-dd')) | $($h.HotFixID) | $($h.Description)"
        }
    }
    Write-Output ""

    # 3. Third-party NDIS filter drivers
    Write-Output "--- Network Filter Driver Bindings ---"
    $bindings = Get-NetAdapterBinding -ComponentID "*" -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true -and $_.ComponentID -notmatch '^ms_' } |
        Select-Object Name, DisplayName, ComponentID
    if ($bindings) {
        foreach ($b in @($bindings)) {
            Write-Output "  $($b.Name) | $($b.DisplayName) | $($b.ComponentID)"
        }
    }
    else {
        Write-Output "  No third-party filter drivers enabled (ms_* only)"
    }
    Write-Output ""

    # 4. TCP/IP interface registry health
    Write-Output "--- TCP/IP Interface Registry ---"
    $ifPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    $activeNic = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }
    foreach ($nic in @($activeNic)) {
        $guid = $nic.InterfaceGuid
        $regKey = Join-Path $ifPath $guid
        if (Test-Path $regKey) {
            $props = Get-ItemProperty $regKey -ErrorAction SilentlyContinue
            $dhcpIP   = $props.DhcpIPAddress
            $dhcpMask = $props.DhcpSubnetMask
            $dhcpGw   = $props.DhcpDefaultGateway
            $dhcpDns  = $props.DhcpNameServer
            Write-Output "  NIC: $($nic.Name) ($($nic.InterfaceDescription))"
            Write-Output "    DhcpIPAddress:      $dhcpIP"
            Write-Output "    DhcpSubnetMask:     $dhcpMask"
            Write-Output "    DhcpDefaultGateway: $($dhcpGw -join ', ')"
            Write-Output "    DhcpNameServer:     $dhcpDns"
            if ([string]::IsNullOrEmpty($dhcpIP) -or [string]::IsNullOrEmpty($dhcpMask)) {
                Write-Output "    ** WARNING: Blank DHCP values — possible TCP/IP stack corruption **"
            }
        }
        else {
            Write-Output "  NIC: $($nic.Name) — registry key missing for GUID $guid"
        }
    }
    Write-Output ""

    # 5. Network services — startup type and status
    Write-Output "--- Network Services ---"
    $svcNames  = @("NlaSvc", "netprofm", "Dhcp", "Dnscache", "LanmanWorkstation")
    $svcLabels = @("Network Location Awareness (NLA)", "Network List Service", "DHCP Client", "DNS Client", "Workstation (SMB)")
    for ($i = 0; $i -lt $svcNames.Count; $i++) {
        $svc = Get-Service $svcNames[$i] -ErrorAction SilentlyContinue
        if ($svc) {
            $flag = if ($svc.Status -ne "Running") { " ** NOT RUNNING **" } else { "" }
            Write-Output "  $($svcLabels[$i]): $($svc.Status) ($($svc.StartType))$flag"
        }
        else {
            Write-Output "  $($svcLabels[$i]): SERVICE NOT FOUND"
        }
    }
    Write-Output ""

    # 6. OS build
    Write-Output "--- OS Build ---"
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Output "  $($os.Caption) Build $($os.BuildNumber)"
    if ($os.BuildNumber -ge 26100) {
        Write-Output "  NOTE: Win11 24H2 — check NLA StartType (should be Automatic, not Manual)"
    }

    Write-Output ""
    Write-Output "=== END: $computer ==="
    exit 0
}
catch {
    Write-Output "FATAL: $($_.Exception.Message)"
    Write-Output "  Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}
