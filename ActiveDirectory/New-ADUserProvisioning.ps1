<#
.SYNOPSIS
    New-ADUserProvisioning — Provisions a new AD user for Contoso

.DESCRIPTION
    Creates an AD user in the target OU, sets standard attributes (title,
    department, manager, phone), copies group memberships from an optional
    mirror user, adds mandatory security groups, and triggers Entra Connect
    delta sync.

    Client: Contoso (contoso.example.com)
    Domain: contoso.local
    Email schema: first initial + last name (e.g., jsmith)

.PARAMETER FirstName
    User's first name. Required.

.PARAMETER LastName
    User's last name. Required.

.PARAMETER Department
    Department name. Required.

.PARAMETER JobTitle
    Job title. Required.

.PARAMETER MirrorUser
    Existing AD username to copy group memberships from. Optional.

.PARAMETER Manager
    Manager's AD username. Required.

.PARAMETER CellPhone
    Cell phone — digits with country code (e.g., 15101234567). Optional.

.PARAMETER OfficePhone
    Office phone — digits with country code. Optional.

.PARAMETER Password
    Temporary password as SecureString. Prompts if not provided.

.NOTES
    Category: Environment-Specific
    Environment: Contoso hybrid AD (contoso.local on-prem, contoso.example.com UPN)
    PowerShell: 5.1, requires RSAT or run on DC

.KEYWORDS
    Contoso, AD, provision, user, onboard
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FirstName,

    [Parameter(Mandatory)]
    [string]$LastName,

    [Parameter(Mandatory)]
    [string]$Department,

    [Parameter(Mandatory)]
    [string]$JobTitle,

    [Parameter()]
    [string]$MirrorUser,

    [Parameter(Mandatory)]
    [string]$Manager,

    [Parameter()]
    [string]$CellPhone,

    [Parameter()]
    [string]$OfficePhone,

    [Parameter()]
    [SecureString]$Password
)

#region Configuration — EDIT THESE FOR Contoso
$company      = "Contoso"
$upnSuffix    = "@contoso.example.com"
$emailDomain  = "contoso.example.com"

# OU paths — update DNs to match Contoso's AD structure
$ouChoices = @{
    # TODO: Replace with actual OU DNs from Contoso's AD
    # "1" = @{ Path = "OU=Users,OU=Managed Objects,DC=contoso,DC=local"; Label = "Main Office" }
    # "2" = @{ Path = "OU=Remote,OU=Managed Objects,DC=contoso,DC=local"; Label = "Remote" }
}

# Mandatory groups — every new user gets these
$mandatoryGroups = @(
    # TODO: Populate from Contoso's standard group list
    # "Intune Enrolled Users"
    # "DuoSecurity"
)

# Entra Connect sync server — set $null if cloud-only
$syncServer = "{ENTRA_CONNECT_SERVER}"
#endregion

#region Module Import
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Error "Failed to import ActiveDirectory module. Ensure RSAT is installed."
        return
    }
}
#endregion

#region Username Generation
# First initial + last name (e.g., John Smith = jsmith)
$cleanFirst = ($FirstName -replace '[^a-zA-Z]','').ToLower()
$cleanLast  = ($LastName  -replace '[^a-zA-Z]','').ToLower()
$username   = $cleanFirst.Substring(0,1) + $cleanLast

if ($username.Length -gt 20) {
    $username = $username.Substring(0, 20)
}

# Conflict check
$existing = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Error "Username '$username' already exists ($($existing.DisplayName)). Provide alternate."
    return
}
Write-Host "Username: $username" -ForegroundColor Green
#endregion

#region Validate Dependencies
try {
    $managerDN = (Get-ADUser -Identity $Manager -ErrorAction Stop).DistinguishedName
    Write-Host "Manager validated: $Manager" -ForegroundColor Green
} catch {
    Write-Error "Manager '$Manager' not found in AD."
    return
}

$mirrorUserObj = $null
if (-not [string]::IsNullOrWhiteSpace($MirrorUser)) {
    try {
        $mirrorUserObj = Get-ADUser -Identity $MirrorUser -Properties MemberOf -ErrorAction Stop
        Write-Host "Mirror user validated: $MirrorUser ($($mirrorUserObj.MemberOf.Count) groups)" -ForegroundColor Green
    } catch {
        Write-Error "Mirror user '$MirrorUser' not found in AD."
        return
    }
}
#endregion

#region OU Selection
if ($ouChoices.Count -eq 0) {
    Write-Error "No OU paths configured. Edit the Configuration region of this script."
    return
}

Write-Host "`n--- Select OU ---" -ForegroundColor Yellow
foreach ($key in ($ouChoices.Keys | Sort-Object)) {
    Write-Host "${key}: $($ouChoices[$key].Label)"
}
do {
    $ouPick = Read-Host "Select OU"
} while (-not $ouChoices.ContainsKey($ouPick))

$targetOU = $ouChoices[$ouPick].Path

try {
    Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null
    Write-Host "OU validated: $($ouChoices[$ouPick].Label)" -ForegroundColor Green
} catch {
    Write-Error "OU not found: $targetOU"
    return
}
#endregion

#region Password
if ($null -eq $Password) {
    $Password = Read-Host -AsSecureString "Enter temporary password for $username"
}
#endregion

#region Create AD User
$newUserParams = @{
    SamAccountName        = $username
    UserPrincipalName     = $username + $upnSuffix
    Name                  = "$FirstName $LastName"
    GivenName             = $FirstName
    Surname               = $LastName
    Enabled               = $true
    DisplayName           = "$FirstName $LastName"
    Title                 = $JobTitle
    Description           = $JobTitle
    Department            = $Department
    Company               = $company
    Manager               = $managerDN
    AccountPassword       = $Password
    ChangePasswordAtLogon = $false
    PasswordNeverExpires  = $false
    EmailAddress          = "$username@$emailDomain"
    Path                  = $targetOU
}

# Optional phone fields
$formattedCell   = $CellPhone   -replace '[^\d]'
$formattedOffice = $OfficePhone -replace '[^\d]'
if ($formattedCell)   { $newUserParams.MobilePhone = $formattedCell }
if ($formattedOffice) { $newUserParams.OfficePhone = $formattedOffice }

try {
    New-ADUser @newUserParams -ErrorAction Stop
    Write-Host "`nAD user '$username' created." -ForegroundColor Green
    Start-Sleep -Seconds 5
} catch {
    Write-Error "Failed to create user: $($_.Exception.Message)"
    return
}
#endregion

#region Group Memberships
$groupsAdded  = @()
$groupsFailed = @()

function Add-SafeGroupMember {
    param([string]$GroupName, [string]$User, [string]$Source)
    if ($script:groupsAdded -contains $GroupName) { return }
    $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($grp) {
        try {
            Add-ADGroupMember -Identity $grp -Members $User -ErrorAction Stop
            Write-Host "  + $GroupName ($Source)" -ForegroundColor Green
            $script:groupsAdded += $GroupName
        } catch {
            if ($_.Exception.Message -match 'already a member') {
                Write-Host "  ~ $GroupName (already member)" -ForegroundColor Gray
            } else {
                Write-Warning "  Failed: $GroupName — $($_.Exception.Message)"
                $script:groupsFailed += $GroupName
            }
        }
    } else {
        Write-Warning "  Group not found: $GroupName"
        $script:groupsFailed += $GroupName
    }
}

# Mandatory groups
if ($mandatoryGroups.Count -gt 0) {
    Write-Host "`n--- Mandatory Groups ---" -ForegroundColor Yellow
    foreach ($g in $mandatoryGroups) {
        Add-SafeGroupMember -GroupName $g -User $username -Source "mandatory"
    }
}

# Mirror user groups
if ($null -ne $mirrorUserObj -and $mirrorUserObj.MemberOf.Count -gt 0) {
    Write-Host "`n--- Mirroring groups from $MirrorUser ---" -ForegroundColor Yellow
    foreach ($dn in $mirrorUserObj.MemberOf) {
        $gName = if ($dn -match '^CN=([^,]+)') { $matches[1] } else { $dn }
        Add-SafeGroupMember -GroupName $gName -User $username -Source "mirror"
    }
}
#endregion

#region Entra Connect Sync
Write-Host "`n--- Entra Connect Sync ---" -ForegroundColor Yellow
$syncTriggered = $false
if (Get-Module -Name ADSync -ListAvailable -ErrorAction SilentlyContinue) {
    try {
        Import-Module ADSync -ErrorAction Stop
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
        Write-Host "Delta sync triggered." -ForegroundColor Green
        $syncTriggered = $true
    } catch {
        Write-Warning "Sync failed: $($_.Exception.Message)"
    }
}
if (-not $syncTriggered) {
    Write-Host "ADSync module not available. Run on sync server:" -ForegroundColor Yellow
    Write-Host "  Start-ADSyncSyncCycle -PolicyType Delta" -ForegroundColor White
}
#endregion

#region Summary
Write-Host "`n==============================" -ForegroundColor Cyan
Write-Host "  USER CREATION COMPLETE" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Username:     $username"
Write-Host "Email:        $username@$emailDomain"
Write-Host "Display Name: $FirstName $LastName"
Write-Host "Groups Added: $($groupsAdded.Count)"
if ($groupsFailed.Count -gt 0) {
    Write-Host "Groups Failed: $($groupsFailed.Count)" -ForegroundColor Yellow
    $groupsFailed | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Yellow }
}

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Verify Entra sync completed (check M365 admin portal)"
Write-Host "  2. Assign M365 license"
Write-Host "  3. Configure shared mailbox access if needed"
Write-Host "  4. Send credentials to stakeholder"
Write-Host "==============================" -ForegroundColor Cyan
#endregion
