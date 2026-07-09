#Requires -Version 5.1

<#
.SYNOPSIS
    Test-TcpPortConnection — PS 5.1 async TCP port test with RMM exit codes

.DESCRIPTION
    Tests TCP connectivity to one or more targets using System.Net.Sockets.TcpClient
    with async connect and configurable timeout. More reliable than Test-NetConnection
    in SYSTEM context and on older Windows versions.

    Accepts targets as an array of hashtables or simple "host:port" strings.

.PARAMETER Targets
    Array of targets to test. Accepts either:
    - Hashtables: @{ Name = 'Label'; Host = 'ip-or-hostname'; Port = 9100 }
    - Strings: 'ip-or-hostname:port'

.PARAMETER TimeoutMs
    Connection timeout in milliseconds. Default: 2000.

.EXAMPLE
    # Hashtable format with labels
    $targets = @(
        @{ Name = 'OFFICE-HP'; Host = '10.0.1.50'; Port = 9100 }
        @{ Name = 'WAREHOUSE'; Host = '10.0.1.51'; Port = 9100 }
    )
    .\Test-TcpPortConnection.ps1 -Targets $targets

.EXAMPLE
    # Simple string format
    .\Test-TcpPortConnection.ps1 -Targets @('10.0.1.50:9100', '10.0.1.51:445', 'fileserver:445')

.EXAMPLE
    # Single target quick test
    .\Test-TcpPortConnection.ps1 -Targets @('192.168.1.100:9100') -TimeoutMs 5000

.NOTES
    Category: Diagnostics
    Context: SYSTEM (RMM) or interactive
    PS Version: 5.1
    Exit Codes: 0=All passed, 1=All failed, 112=Partial success

.KEYWORDS
    TCP, port, connectivity, network, diagnostic, RMM
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [object[]]$Targets,

    [ValidateRange(100, 30000)]
    [int]$TimeoutMs = 2000
)

$ErrorActionPreference = "Stop"

#region Functions
function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 2000
    )

    $tcpClient = $null
    $result = $false

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle

        if ($waitHandle.WaitOne($TimeoutMs, $false)) {
            if ($tcpClient.Connected) {
                $tcpClient.EndConnect($asyncResult)
                $result = $true
            }
        }
    }
    catch {
        $result = $false
    }
    finally {
        if ($null -ne $tcpClient) {
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
    }

    return $result
}
#endregion

#region Parse Targets
$parsed = foreach ($target in $Targets) {
    if ($target -is [hashtable]) {
        [PSCustomObject]@{
            Name = if ($target.Name) { $target.Name } else { "$($target.Host):$($target.Port)" }
            Host = $target.Host
            Port = [int]$target.Port
        }
    }
    elseif ($target -is [string] -and $target -match '^(.+):(\d+)$') {
        [PSCustomObject]@{
            Name = $target
            Host = $Matches[1]
            Port = [int]$Matches[2]
        }
    }
    else {
        Write-Output "[SKIP] Invalid target format: $target (use 'host:port' or hashtable)"
    }
}

if (-not $parsed -or $parsed.Count -eq 0) {
    Write-Output "ERROR: No valid targets specified."
    exit 1
}
#endregion

#region Main
Write-Output "=== TCP Port Connectivity Test ==="
Write-Output "Server: $env:COMPUTERNAME"
Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Timeout: ${TimeoutMs}ms"
Write-Output "Targets: $($parsed.Count)"
Write-Output "==================================="
Write-Output ""

$passCount = 0
$failCount = 0

foreach ($t in $parsed) {
    $connected = Test-TcpPort -ComputerName $t.Host -Port $t.Port -TimeoutMs $TimeoutMs

    if ($connected) {
        Write-Output "[PASS] $($t.Name) ($($t.Host):$($t.Port))"
        $passCount++
    }
    else {
        Write-Output "[FAIL] $($t.Name) ($($t.Host):$($t.Port))"
        $failCount++
    }
}

Write-Output ""
Write-Output "==================================="
Write-Output "RESULTS: $passCount/$($parsed.Count) reachable"
Write-Output "==================================="
#endregion

#region Exit
if ($failCount -eq 0) {
    Write-Output "All targets reachable."
    exit 0
}
elseif ($passCount -gt 0) {
    Write-Output "Partial success. $failCount target(s) unreachable."
    exit 112
}
else {
    Write-Output "All targets unreachable."
    exit 1
}
#endregion
