<#
.SYNOPSIS
    DHCP/DNS fleet audit — verify DNS server assignments and resolution health.
.DESCRIPTION
    Diagnostic script for verifying DHCP scope changes propagated to endpoints.
    Reports DNS server assignments, DHCP lease info, file server DNS resolution,
    OS build (flags Win11 24H2 DHCP regression), and NIC driver versions.

    Deploy via RMM to affected workstations after DHCP scope cleanup.
    Read-only — no configuration changes.
.PARAMETER FileServer
    FQDN of the primary file server to test DNS resolution against.
    Default: prompts for detection from DHCP lease. Pass explicitly for RMM use.
.NOTES
    Context:  RMM (SYSTEM), PS 5.1, read-only diagnostic
    Platform: Windows 10/11
.KEYWORDS
    DNS, DHCP, fleet audit, stale DNS, network, SMB
#>

param(
    [string]$FileServer = ""
)

$ErrorActionPreference = "Stop"

try {
    $hostname = $env:COMPUTERNAME
    Write-Output "=== DHCP/DNS FLEET AUDIT: $hostname ==="
    Write-Output ""

    #-- 1. DNS server addresses (IPv4 only) --
    Write-Output "--- DNS Server Addresses ---"
    $dnsAddresses = Get-DnsClientServerAddress | Where-Object {
        $_.AddressFamily -eq 2 -and $_.ServerAddresses.Count -gt 0
    }
    foreach ($iface in $dnsAddresses) {
        $addrs = $iface.ServerAddresses -join ", "
        Write-Output "$($iface.InterfaceAlias): $addrs"
    }
    Write-Output ""

    #-- 2. DHCP lease info (confirm which server is assigning DNS) --
    Write-Output "--- DHCP Lease Info ---"
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration |
        Where-Object { $_.DHCPEnabled -eq $true -and $_.IPAddress }
    foreach ($a in $adapters) {
        Write-Output "Interface: $($a.Description)"
        Write-Output "  DHCP Server: $($a.DHCPServer)"
        Write-Output "  DNS Servers: $($a.DNSServerSearchOrder -join ', ')"
        Write-Output "  Lease Obtained: $($a.DHCPLeaseObtained)"
        Write-Output "  Lease Expires: $($a.DHCPLeaseExpires)"
    }
    Write-Output ""

    #-- 3. DNS resolution test for file server (if provided) --
    if ($FileServer -ne "") {
        Write-Output "--- DNS Resolution: $FileServer ---"
        try {
            $resolved = Resolve-DnsName $FileServer -Type A -ErrorAction Stop
            foreach ($r in $resolved) {
                Write-Output "Type: $($r.Type) | Name: $($r.Name) | IP: $($r.IPAddress) | TTL: $($r.TTL)"
            }
        } catch {
            Write-Output "FAILED: $($_.Exception.Message)"
        }
        Write-Output ""

        #-- 4. DNS cache entries for file server --
        Write-Output "--- DNS Cache ($FileServer entries) ---"
        $serverShort = ($FileServer -split '\.')[0]
        $cacheEntries = Get-DnsClientCache | Where-Object {
            $_.Entry -like "*$serverShort*"
        } | Select-Object Entry, Data, TimeToLive, Type
        if ($cacheEntries) {
            foreach ($c in $cacheEntries) {
                Write-Output "$($c.Entry) -> $($c.Data) (TTL: $($c.TimeToLive), Type: $($c.Type))"
            }
        } else {
            Write-Output "(no cached entries for $serverShort)"
        }
        Write-Output ""
    }

    #-- 5. OS build version --
    Write-Output "--- OS Build ---"
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [System.Environment]::OSVersion.Version
    Write-Output "$($os.Caption) | Build: $($build.Major).$($build.Minor).$($build.Build).$($build.Revision)"
    if ($build.Build -ge 26100) {
        Write-Output "WARNING: Win11 24H2 (build 26100+) -- known DHCP regression: stale DNS IPs may persist after lease renewal"
    }
    Write-Output ""

    #-- 6. NIC driver info --
    Write-Output "--- NIC Drivers ---"
    $nics = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
        Select-Object Name, InterfaceDescription, DriverVersion, DriverDate
    foreach ($nic in $nics) {
        $driverDate = if ($nic.DriverDate) { $nic.DriverDate.ToString("yyyy-MM-dd") } else { "unknown" }
        Write-Output "$($nic.Name): $($nic.InterfaceDescription) | Driver: $($nic.DriverVersion) | Date: $driverDate"
    }
    Write-Output ""

    Write-Output "=== END: $hostname ==="
    exit 0
}
catch {
    Write-Output "ERROR on $($env:COMPUTERNAME): $($_.Exception.Message)"
    exit 1
}
