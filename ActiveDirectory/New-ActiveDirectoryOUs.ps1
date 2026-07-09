#Requires -Version 5.1

<#
.SYNOPSIS
    New-ActiveDirectoryOUs — Creates standard OU hierarchy for multi-site organizations

.DESCRIPTION
    Creates a "Managed Objects" base OU with location-based sub-OUs for
    each location. Each location gets child OUs
    for Contacts, Disabled Objects, Managed Computers, Managed Groups,
    Managed Servers, Managed Users, and related sub-categories.
    Not idempotent — will error if OUs already exist.

.EXAMPLE
    .\New-ActiveDirectoryOUs.ps1

.NOTES
    Category: ActiveDirectory
.KEYWORDS
    AD, provision, OU, hierarchy, template
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$baseOU = "Managed Objects"

$locations = @("Location1", "Location2", "Location3", "Location4")

$subOUs = @(
    "Contacts",
    "Disabled Objects",
    "Managed Computers",
    "Active",
    "Retired",
    "Managed Groups",
    "Distribution Groups",
    "Security Groups",
    "Managed Servers",
    "Active",
    "Retired",
    "Managed Users",
    "Regular",
    "Admins",
    "Retain",
    "Service Accounts"
)

# Dynamically resolve domain DN at runtime
$DomainDN = (Get-ADDomain).DistinguishedName

foreach ($location in $locations) {

    $locationOU = "$location"
    New-ADOrganizationalUnit -Name $locationOU -Path "OU=$baseOU,$DomainDN" -ProtectedFromAccidentalDeletion $false

    foreach ($subOU in $subOUs) {
        $subOUNaming = $subOU -replace " ", "" # Remove spaces for naming
        $subOUNaming = "$subOUNaming-$location" # Append location to the name
        New-ADOrganizationalUnit -Name $subOUNaming -Path "OU=$locationOU,OU=$baseOU,$DomainDN" -ProtectedFromAccidentalDeletion $false
    }
}
