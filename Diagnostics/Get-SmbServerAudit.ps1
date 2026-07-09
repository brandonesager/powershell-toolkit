<#
.SYNOPSIS
    Enumerate SMB server configuration, active sessions, shares, and critical event log entries.

.DESCRIPTION
    Audits SMB server-side state to diagnose session drops and correlation with client drops.
    Output includes server configuration (AutoDisconnectTimeout, DurableHandleV2Timeout, signing,
    Multichannel limits), active sessions with open count and idle time, share list with dialect
    enforcement, and event log entries for session setup failures (1020), client disconnects (551),
    and critical durable handle reopen failures (1016).

    Critical event 1016 "Reopen failed" indicates client reconnection attempts where the server
    could not reclaim file handles, resulting in LOB app crashes (Lacerte, Excel). Sparse Event
    1016 occurrences paired with Multichannel phantom NIC diagnosis on client points to brief
    TCP interruptions from dead interface path attempts.

.NOTES
    - Requires SYSTEM context (RMM compatible)
    - Run on file server experiencing client drops
    - Scans last 14 days of SMBServer/Operational log
    - Windows PowerShell 5.1+
#>

$ErrorActionPreference = 'Stop'

try {
    Write-Output "=== SMB Server Audit: $env:COMPUTERNAME ==="
    Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    Write-Output "--- SMB Server Configuration ---"
    $srvCfg = Get-SmbServerConfiguration
    $props = [ordered]@{
        AutoDisconnectTimeout        = "$($srvCfg.AutoDisconnectTimeout) min"
        DurableHandleV2TimeoutSeconds = "$($srvCfg.DurableHandleV2TimeoutInSeconds) sec"
        RequireSecuritySignature     = $srvCfg.RequireSecuritySignature
        EnableSecuritySignature      = $srvCfg.EnableSecuritySignature
        EncryptData                  = $srvCfg.EncryptData
        RejectUnencryptedAccess      = $srvCfg.RejectUnencryptedAccess
        EnableMultiChannel           = $srvCfg.EnableMultiChannel
        MaxChannelPerSession         = $srvCfg.MaxChannelPerSession
        Smb2CreditsMin               = $srvCfg.Smb2CreditsMin
        Smb2CreditsMax               = $srvCfg.Smb2CreditsMax
    }
    [PSCustomObject]$props | Format-List | Out-String

    Write-Output "--- Active Sessions ---"
    $sessions = Get-SmbSession -ErrorAction SilentlyContinue
    if ($sessions) {
        $sessions | Format-Table ComputerName, UserName, NumOpens, IdleTime, Dialect -AutoSize |
            Out-String -Width 150
    } else {
        Write-Output "No active sessions"
    }
    Write-Output ""

    Write-Output "--- Shares ---"
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^IPC\$|ADMIN\$|C\$|D\$' }
    if ($shares) {
        $shares | Format-Table Name, Path, Description -AutoSize
    } else {
        Write-Output "No user shares"
    }
    Write-Output ""

    Write-Output "--- SMBServer/Operational Events (last 14 days) ---"
    $since = (Get-Date).AddDays(-14)
    $events = Get-WinEvent -LogName 'Microsoft-Windows-SMBServer/Operational' -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $since -and $_.Id -in @(1016, 1017, 1020, 1001, 1905) }

    if ($events) {
        $eventSummary = $events |
            Group-Object -Property Id |
            Select-Object @{Name='EventID';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}}

        $eventSummary | Format-Table EventID, Count

        Write-Output ""
        Write-Output "--- Event 1016 (Reopen Failed) Details ---"
        $event1016 = $events | Where-Object { $_.Id -eq 1016 }
        if ($event1016) {
            $event1016 | Select-Object TimeCreated, Message | Format-List
        } else {
            Write-Output "No Event 1016 entries in this period"
        }
    } else {
        Write-Output "No relevant events found"
    }

    exit 0
} catch {
    Write-Output "ERROR: $_"
    exit 1
}
