<#
.SYNOPSIS
    Audits local Administrators group membership across Contoso workstations.

.DESCRIPTION
    Queries the local Administrators group and reports current members.
    Used to verify target user has local admin on each machine
    before running Add-LocalAdmin-Remediation.ps1.

    Designed for RMM bulk deployment: filter by site naming prefix,
    multi-select devices, run script, review Script History results.

.PARAMETER TargetUser
    Username to check for specifically. Default: "jdoe"

.NOTES
    Created: 2025-12
    PS Version: 5.1+ (RMM compatible)
#>

param(
    [string]$TargetUser = "jdoe"
)

$members = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
$hasTarget = $members | Where-Object { $_ -match $TargetUser }

[PSCustomObject]@{
    ComputerName  = $env:COMPUTERNAME
    AllAdmins     = ($members -join "; ")
    TargetUser    = $TargetUser
    TargetPresent = if ($hasTarget) { "YES" } else { "NO" }
}
