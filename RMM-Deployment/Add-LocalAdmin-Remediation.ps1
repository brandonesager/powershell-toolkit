<#
.SYNOPSIS
    Adds a user to the local Administrators group on targeted workstations.

.DESCRIPTION
    Adds a specified domain or local user to the local Administrators group.
    Idempotent — exits cleanly if the user is already a member.

    Designed for RMM bulk deployment: filter by site naming prefix,
    multi-select devices, run script, review Script History results.

    Authorization: approved by management.
    Policy: each site designates its own local-admin user (some sites none).

.PARAMETER Username
    Domain\Username or local username to add. Default: "CONTOSO\jdoe"

.NOTES
    Created: 2025-12
    PS Version: 5.1+ (RMM compatible)
#>

param(
    [string]$Username = "CONTOSO\jdoe"
)

$group = "Administrators"

# Check current membership
$members = Get-LocalGroupMember -Group $group | Select-Object -ExpandProperty Name
if ($members -match [regex]::Escape($Username)) {
    Write-Output "ALREADY_MEMBER: $Username is already in $group on $env:COMPUTERNAME"
    exit 0
}

try {
    Add-LocalGroupMember -Group $group -Member $Username -ErrorAction Stop
    Write-Output "SUCCESS: Added $Username to $group on $env:COMPUTERNAME"
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}

# Verify
$updated = Get-LocalGroupMember -Group $group | Select-Object -ExpandProperty Name
if ($updated -match [regex]::Escape($Username)) {
    Write-Output "VERIFIED: $Username confirmed in $group"
} else {
    Write-Output "VERIFY_FAILED: $Username not found after add — check manually"
    exit 1
}
