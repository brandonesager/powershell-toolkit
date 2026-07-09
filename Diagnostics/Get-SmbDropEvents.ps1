<#
.SYNOPSIS
    Pulls SMB drop event correlation from a workstation — SMBClient/Connectivity, Operational, and network-layer events.

.DESCRIPTION
    Queries three event sources over a configurable lookback window:
      - Microsoft-Windows-SMBClient/Connectivity (30803, 30805, 30806, 30807, 30808)
      - Microsoft-Windows-SMBClient/Operational (31998, 31999 — signing/encryption audit)
      - System log Tcpip and NDIS providers (network-layer correlation)

    Use alongside Get-SmbClientAudit.ps1 and Get-SmbServerAudit.ps1 to diagnose
    intermittent SMB mapped drive drops on Win11 24H2/25H2.

    Event 30803 = session disconnected (timestamp matches user-reported drop)
    Event 30805 = failed to establish session
    Event 30806 = lost network connectivity to server
    Event 30808 = connection established (recovery marker)

.NOTES
    Run via RMM in SYSTEM context (PS 5.1) on affected workstations.
    Deploy to each machine reporting drops — results include machine name for fleet correlation.

#>

$ErrorActionPreference = 'Stop'
$DaysBack = 14

try {
    Write-Output "=== SMB Drop Events: $env:COMPUTERNAME ==="
    Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "Lookback: $DaysBack days"
    Write-Output ""

    $start = (Get-Date).AddDays(-$DaysBack)

    Write-Output "--- SMBClient/Connectivity (30803, 30805-30808) ---"
    $connEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-SMBClient/Connectivity'
        Id        = 30803, 30805, 30806, 30807, 30808
        StartTime = $start
    } -ErrorAction SilentlyContinue

    if ($connEvents) {
        Write-Output "Total: $($connEvents.Count) events"
        Write-Output ""
        $connEvents | Group-Object Id | Sort-Object Count -Descending |
            Format-Table @{N='EventID';E={$_.Name}}, Count -AutoSize | Out-String

        Write-Output "Timeline (newest first):"
        $connEvents | Sort-Object TimeCreated -Descending |
            Select-Object TimeCreated, Id,
                @{N='Summary';E={
                    $line = ($_.Message -split "`n")[0]
                    if ($line.Length -gt 120) { $line.Substring(0, 120) } else { $line }
                }} |
            Format-Table -AutoSize | Out-String -Width 200
    } else {
        Write-Output "No SMBClient/Connectivity events in last $DaysBack days"
    }

    Write-Output ""

    Write-Output "--- SMBClient/Operational (31998, 31999 — signing/encryption audit) ---"
    $opEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-SMBClient/Operational'
        Id        = 31998, 31999
        StartTime = $start
    } -ErrorAction SilentlyContinue

    if ($opEvents) {
        Write-Output "Total: $($opEvents.Count) events"
        $opEvents | Select-Object -First 10 TimeCreated, Id, Message |
            Format-Table -Wrap -AutoSize | Out-String -Width 200
    } else {
        Write-Output "No signing/encryption audit events"
    }

    Write-Output ""

    Write-Output "--- Network-Layer Events (Tcpip, NDIS) ---"
    $netEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($provider in @('Tcpip', 'NDIS')) {
        $ev = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = $provider
            StartTime    = $start
        } -ErrorAction SilentlyContinue
        if ($ev) { foreach ($e in $ev) { $netEvents.Add($e) } }
    }

    if ($netEvents.Count -gt 0) {
        Write-Output "Total: $($netEvents.Count) events"
        $netEvents | Group-Object ProviderName, Id | Sort-Object Count -Descending |
            Format-Table @{N='Provider_EventID';E={$_.Name}}, Count -AutoSize | Out-String
        Write-Output "Recent 15:"
        $netEvents | Sort-Object TimeCreated -Descending | Select-Object -First 15 TimeCreated,
            ProviderName, Id,
            @{N='Msg';E={
                $line = ($_.Message -split "`n")[0]
                if ($line.Length -gt 100) { $line.Substring(0, 100) } else { $line }
            }} |
            Format-Table -AutoSize | Out-String -Width 200
    } else {
        Write-Output "No Tcpip/NDIS events in last $DaysBack days"
    }

    exit 0
} catch {
    Write-Output "ERROR: $_"
    exit 1
}
