<#
.SYNOPSIS
    Enumerate SMB client configuration, active connections, Multichannel state, and network interfaces.

.DESCRIPTION
    Audits SMB client-side state to diagnose session drops, Multichannel phantom interfaces,
    KeepConn mismatch, and signing/encryption configuration. Output includes active connections,
    client network interface registry (LinkSpeed, RdmaCapable, RssCapable), Multichannel connections
    with SelectedForEstablished status, and SMB client config.

    Critical diagnostic: SelectedForEstablished = blank (abnormal; should be True/False when
    Multichannel enabled). Paired with LinkSpeed=0 + Inactive interfaces, indicates phantom
    dead NICs that may cause brief 5-20s drops.

.NOTES
    - Requires SYSTEM context (RMM compatible)
    - Windows PowerShell 5.1+
    - Must run on client experiencing SMB drops
    - Output width: 150 characters for table readability
#>

$ErrorActionPreference = 'Stop'

try {
    Write-Output "=== SMB Client Audit: $env:COMPUTERNAME ==="
    Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    Write-Output "--- Active SMB Connections ---"
    $conns = Get-SmbConnection -ErrorAction SilentlyContinue
    if ($conns) {
        $conns | Format-Table ServerName, ShareName, Dialect, Signed, Encrypted, NumOpens -AutoSize |
            Out-String -Width 150
    } else {
        Write-Output "No active SMB connections"
    }

    Write-Output "--- SMB Client Configuration ---"
    $cfg = Get-SmbClientConfiguration
    $props = [ordered]@{
        EnableMultiChannel              = $cfg.EnableMultiChannel
        SessionTimeout                  = $cfg.SessionTimeout
        ExtendedSessionTimeout          = $cfg.ExtendedSessionTimeout
        RequireSecuritySignature        = $cfg.RequireSecuritySignature
        EnableSecuritySignature         = $cfg.EnableSecuritySignature
        MaximumConnectionCountPerServer = $cfg.MaximumConnectionCountPerServer
        EnableBandwidthThrottling       = $cfg.EnableBandwidthThrottling
        EnableLargeMtu                  = $cfg.EnableLargeMtu
    }
    [PSCustomObject]$props | Format-List | Out-String

    Write-Output "--- KeepConn (Registry) ---"
    $kc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name KeepConn -ErrorAction SilentlyContinue
    if ($kc) {
        Write-Output "KeepConn: $($kc.KeepConn) seconds"
    } else {
        Write-Output "KeepConn: not set (default 600 seconds / 10 min)"
    }
    Write-Output ""

    Write-Output "--- Multichannel Connections ---"
    $mc = Get-SmbMultichannelConnection -ErrorAction SilentlyContinue
    if ($mc) {
        $mc | Format-Table ServerName, ClientInterfaceIndex, ClientIpAddress,
            ServerIpAddress, ClientInterfaceFriendlyName, SelectedForEstablished -AutoSize |
            Out-String -Width 150
    } else {
        Write-Output "No multichannel connections (single NIC or multichannel disabled)"
    }

    Write-Output "--- Client Network Interfaces ---"
    Write-Output "[Red flag: LinkSpeed=0 + Active=False on registered interfaces indicates phantom dead NICs]"
    Get-SmbClientNetworkInterface -ErrorAction SilentlyContinue |
        Select-Object InterfaceIndex, FriendlyName, LinkSpeed, @{Name='Active';Expression={$_.RdmaCapable -ne $false}}, RdmaCapable, RssCapable |
        Format-Table -AutoSize |
        Out-String -Width 150

    exit 0
} catch {
    Write-Output "ERROR: $_"
    exit 1
}
