<#
.SYNOPSIS
    Assign an Entra directory role and an Intune RBAC built-in role to a user, with pre/post audit.

.DESCRIPTION
    1. Pre-assignment audit: lists current Entra directory roles, group memberships, and licenses.
    2. Assigns the specified Entra directory role (activates from template if not yet active).
       Uses New-MgDirectoryRoleMemberByRef (Graph SDK v2+ naming; direct OData bind).
    3. Assigns the specified Intune built-in role via deviceManagement/roleAssignments POST.
    4. Post-assignment verification for both assignments.

    Idempotent: skips if the assignment already exists.

    Run from an already-connected Microsoft Graph PowerShell session with scopes:
    RoleManagement.ReadWrite.Directory, DeviceManagementRBAC.ReadWrite.All, User.Read.All.

.PARAMETER UserUPN
    UPN of the target user.

.PARAMETER EntraRoleName
    Display name of the Entra directory role to assign (e.g., 'Cloud Application Administrator').

.PARAMETER IntuneRoleName
    Display name of the Intune built-in role to assign (e.g., 'Help Desk Operator').

.PARAMETER AssignmentDisplayName
    Label for the Intune role assignment record. Defaults to "{UserUPN} {IntuneRoleName}".

.EXAMPLE
    .\Set-EntraIntuneRoleAssignments.ps1 `
        -UserUPN 'jdoe@contoso.example.com' `
        -EntraRoleName 'Cloud Application Administrator' `
        -IntuneRoleName 'Help Desk Operator'

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: Cloud

    SDK note: New-MgDirectoryRoleMember was renamed to New-MgDirectoryRoleMemberByRef
    in Graph PowerShell SDK v2. The OData bind body format is required.

.KEYWORDS
    Entra, Intune, RBAC, directory role, role assignment, Cloud Application Administrator, Help Desk Operator
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$UserUPN,

    [Parameter(Mandatory)]
    [string]$EntraRoleName,

    [Parameter(Mandatory)]
    [string]$IntuneRoleName,

    [string]$AssignmentDisplayName = ''
)

$ErrorActionPreference = 'Stop'

# Locate user
$user = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction Stop
if (-not $user) {
    Write-Error "User '$UserUPN' not found."
    return
}
Write-Host "`nUser: $($user.DisplayName) | ID: $($user.Id)" -ForegroundColor Cyan

if (-not $AssignmentDisplayName) {
    $AssignmentDisplayName = "$UserUPN $IntuneRoleName"
}

# ============================================================
# PRE-ASSIGNMENT AUDIT
# ============================================================
Write-Host "`n=== PRE-ASSIGNMENT AUDIT ===" -ForegroundColor Yellow

$memberOf = Get-MgUserMemberOf -UserId $user.Id -All
$dirRoles = $memberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
$groups   = $memberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

if ($dirRoles) {
    Write-Host "Entra directory roles:"
    $dirRoles | ForEach-Object { Write-Host "  - $($_.AdditionalProperties.displayName)" }
} else {
    Write-Host "Entra directory roles: none" -ForegroundColor DarkGray
}

if ($groups) {
    Write-Host "Group memberships:"
    $groups | ForEach-Object { Write-Host "  - $($_.AdditionalProperties.displayName)" }
} else {
    Write-Host "Group memberships: none" -ForegroundColor DarkGray
}

$licenses = Get-MgUserLicenseDetail -UserId $user.Id
if ($licenses) {
    Write-Host "Licenses:"
    $licenses | ForEach-Object { Write-Host "  - $($_.SkuPartNumber)" }
}

# ============================================================
# ENTRA DIRECTORY ROLE
# ============================================================
Write-Host "`n=== ENTRA ROLE: $EntraRoleName ===" -ForegroundColor Yellow

$role = Get-MgDirectoryRole -Filter "displayName eq '$EntraRoleName'" -ErrorAction SilentlyContinue

if (-not $role) {
    Write-Host "Activating role from template..." -ForegroundColor Yellow
    $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $EntraRoleName }
    if (-not $template) {
        Write-Error "Role template '$EntraRoleName' not found in directory."
        return
    }
    $role = New-MgDirectoryRole -BodyParameter @{ roleTemplateId = $template.Id }
    Write-Host "Role activated." -ForegroundColor Green
}

$existing = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
if ($existing | Where-Object { $_.Id -eq $user.Id }) {
    Write-Host "Already assigned. Skipping." -ForegroundColor Green
} else {
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
    }
    Write-Host "$EntraRoleName assigned to $($user.DisplayName)." -ForegroundColor Green
}

# ============================================================
# INTUNE RBAC ROLE
# ============================================================
Write-Host "`n=== INTUNE ROLE: $IntuneRoleName ===" -ForegroundColor Yellow

$roleDefResp = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions' -OutputType PSObject
$roleDefn = $roleDefResp.value | Where-Object { $_.displayName -eq $IntuneRoleName -and $_.isBuiltIn -eq $true }

if (-not $roleDefn) {
    Write-Error "Intune built-in role '$IntuneRoleName' not found."
    return
}
Write-Host "Role definition: $($roleDefn.displayName) | ID: $($roleDefn.id)"

$existingAssignResp = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments' -OutputType PSObject
$alreadyAssigned = $existingAssignResp.value | Where-Object {
    $_.members -contains $user.Id -and
    $_.roleDefinition.id -eq $roleDefn.id
}

if ($alreadyAssigned) {
    Write-Host "User already has this Intune role assignment. Skipping." -ForegroundColor Green
} else {
    $body = @{
        '@odata.type'    = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
        displayName      = $AssignmentDisplayName
        description      = "Intune $IntuneRoleName for $UserUPN. Assigned via Set-EntraIntuneRoleAssignments.ps1."
        members          = @($user.Id)
        resourceScopes   = @('00000000-0000-0000-0000-000000000000')
        'roleDefinition@odata.bind' = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions('$($roleDefn.id)')"
    }
    Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments' `
        -Body ($body | ConvertTo-Json -Depth 5) `
        -ContentType 'application/json' -OutputType PSObject | Out-Null
    Write-Host "Intune $IntuneRoleName assigned to $($user.DisplayName)." -ForegroundColor Green
}

# ============================================================
# POST-ASSIGNMENT VERIFICATION
# ============================================================
Write-Host "`n=== POST-ASSIGNMENT VERIFICATION ===" -ForegroundColor Yellow

$updatedRoles = Get-MgUserMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
Write-Host "Entra directory roles:"
$updatedRoles | ForEach-Object { Write-Host "  - $($_.AdditionalProperties.displayName)" }

$updatedAssignResp = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments' -OutputType PSObject
$userAssigns = $updatedAssignResp.value | Where-Object { $_.members -contains $user.Id }
if ($userAssigns) {
    Write-Host "Intune role assignments:"
    $userAssigns | ForEach-Object { Write-Host "  - $($_.displayName)" }
} else {
    Write-Host "Intune role assignments: pending replication (check in 2-5 min)" -ForegroundColor Yellow
}

Write-Host "`nDone. Replication may take 5-10 minutes. Have user sign out and back in to refresh token claims." -ForegroundColor Cyan
