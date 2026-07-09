<#
.SYNOPSIS
    Disables SMB Multichannel on the local workstation.
.DESCRIPTION
    Checks whether SMB Multichannel is currently enabled on the SMB client.
    If enabled, disables it and reports success. If already disabled, exits
    without making changes (idempotent).

    Use to resolve mapped drive drops caused by phantom dead network interfaces
    causing SMB Multichannel to route over an unusable path.
    No reboot required -- takes effect immediately.
.EXAMPLE
    .\Disable-SmbMultichannel.ps1
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=Success or already disabled, 1=Failed to disable
    PS 5.1 compatible.
.KEYWORDS
    SMB, multichannel, network, mapped drives, drops, NIC
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

try {
    $config = Get-SmbClientConfiguration

    if (-not $config.EnableMultichannel) {
        Write-Output "SKIP: SMB Multichannel already disabled on $env:COMPUTERNAME"
        exit 0
    }

    Set-SmbClientConfiguration -EnableMultichannel $false -Force

    $verify = Get-SmbClientConfiguration
    if (-not $verify.EnableMultichannel) {
        Write-Output "SUCCESS: SMB Multichannel disabled on $env:COMPUTERNAME"
        exit 0
    } else {
        Write-Output "FAILED: SMB Multichannel still enabled on $env:COMPUTERNAME"
        exit 1
    }
} catch {
    Write-Output "ERROR on ${env:COMPUTERNAME}: $($_.Exception.Message)"
    exit 1
}
