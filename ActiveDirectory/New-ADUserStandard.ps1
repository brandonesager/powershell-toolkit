<#
.SYNOPSIS
    New-ADUserStandard — Provisions a new AD user for Contoso with standard configuration and group memberships

.DESCRIPTION
    Full onboarding workflow for Contoso.
    Creates an AD user in the appropriate OU (Main Office or Remote Sites),
    sets standard attributes (job title, department, phone formatting, manager),
    applies group memberships via mirror user, job title mapping, explicit groups,
    or portfolios, adds mandatory security groups (DUO, Intune, etc.), and triggers
    Azure AD Connect delta sync.

    Group Membership Sources (applied in this order):
    1. Mirror user (optional) - copies all groups from existing user
    2. Job title mapping - automatic groups based on role
    3. Portfolio parameter - adds portfolio groups
    4. Explicit groups - adds any groups specified via -Groups
    5. Interactive prompt - when no mirror user and no explicit groups

    Supports fully interactive, command-line, or mixed usage modes.
    Client: Contoso (contoso.com / contoso.com)

.PARAMETER FirstName
    User's first name. Required (will prompt if not provided).

.PARAMETER LastName
    User's last name. Required (will prompt if not provided).

.PARAMETER Department
    Department name (e.g., "Operations", "Member Services"). Required.

.PARAMETER JobTitle
    Job title - expand abbreviations (e.g., "Assistant Manager" not "APM"). Required.
    Determines automatic role-based group assignments.

.PARAMETER EmploymentType
    Employment type: "FullTime" or "Temp". Required.

.PARAMETER MirrorUser
    Username to copy group memberships from (e.g., "user1"). Optional.

.PARAMETER Manager
    Manager's AD username (e.g., "jsmith"). Required.

.PARAMETER Groups
    String array of explicit group names to add. Optional.

.PARAMETER Portfolio
    String array of portfolio names. Automatically prefixed with "Portfolio ". Optional.

.PARAMETER Properties
    String array of property names for physicalDeliveryOfficeName attribute. Optional.

.PARAMETER SkipGroupPrompt
    Switch to skip interactive group prompts when no mirror user provided.

.PARAMETER CellPhone
    User's cell phone - digits with country code (e.g., "15101234567"). Optional.
    WARNING: DUO enrollment fails without mobile number.

.PARAMETER OfficePhone
    Office phone - digits with country code. Optional.

.PARAMETER StreetAddress
    Street address. Optional.

.PARAMETER City
    City. Optional.

.PARAMETER State
    State abbreviation. Defaults to "CA".

.PARAMETER ZipCode
    Zip code. Optional.

.PARAMETER Office
    Office name (e.g., "Suite 100"). Optional.

.PARAMETER Password
    Temporary password as SecureString. If not provided, will prompt securely.

.NOTES
    Category: Environment-Specific
    Environment: Contoso hybrid AD (contoso.com on-prem, contoso.com UPN)
    PowerShell: 5.1, requires RSAT on management workstation or DC

.KEYWORDS
    Contoso, AD, provision, user, onboard, group, sync

.EXAMPLE
    .\New-ADUserStandard.ps1
    Runs fully interactive - prompts for all fields including groups.

.EXAMPLE
    .\New-ADUserStandard.ps1 -FirstName "Jane" -LastName "Doe" -Department "Operations" -JobTitle "Assistant Manager" -EmploymentType FullTime -Manager "jsmith" -Portfolio "West"
    Uses job title for groups, adds portfolio. Prompts for additional groups unless -SkipGroupPrompt.

.EXAMPLE
    .\New-ADUserStandard.ps1 -FirstName "Jane" -LastName "Doe" -Department "Operations" -JobTitle "Assistant Manager" -EmploymentType Temp -MirrorUser "user1" -Manager "jsmith"
    Copies groups from mirror user.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FirstName = "",

    [Parameter(Mandatory = $false)]
    [string]$LastName = "",

    [Parameter(Mandatory = $false)]
    [string]$Department = "",

    [Parameter(Mandatory = $false)]
    [string]$JobTitle = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("FullTime", "Temp", "")]
    [string]$EmploymentType = "",

    [Parameter(Mandatory = $false)]
    [string]$MirrorUser = "",

    [Parameter(Mandatory = $false)]
    [string]$Manager = "",

    [Parameter(Mandatory = $false)]
    [string[]]$Groups = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$Portfolio = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$Properties = @(),

    [Parameter(Mandatory = $false)]
    [switch]$SkipGroupPrompt,

    [Parameter(Mandatory = $false)]
    [string]$CellPhone = "",

    [Parameter(Mandatory = $false)]
    [string]$OfficePhone = "",

    [Parameter(Mandatory = $false)]
    [string]$StreetAddress = "",

    [Parameter(Mandatory = $false)]
    [string]$City = "",

    [Parameter(Mandatory = $false)]
    [string]$State = "CA",

    [Parameter(Mandatory = $false)]
    [string]$ZipCode = "",

    [Parameter(Mandatory = $false)]
    [string]$Office = "",

    [Parameter(Mandatory = $false)]
    [SecureString]$Password = $null
)

#region Transcript Logging
$transcriptPath = Join-Path $env:TEMP "Contoso-NewUser_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try {
    Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop | Out-Null
    Write-Host "Transcript logging to: $transcriptPath" -ForegroundColor Gray
} catch {
    Write-Warning "Failed to start transcript logging: $($_.Exception.Message)"
    Write-Warning "Session will not be logged to file."
    $transcriptPath = $null
}
#endregion

#region Module Import
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Error "Failed to import ActiveDirectory module. Ensure RSAT is installed."
        Stop-Transcript
        return
    }
}
#endregion

#region Helper Functions
function Read-RequiredInput {
    param (
        [string]$Prompt,
        [string]$CurrentValue
    )
    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        do {
            $userInput = Read-Host $Prompt
            if ([string]::IsNullOrWhiteSpace($userInput)) {
                Write-Host "  This field is required." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($userInput))
        return $userInput
    }
    return $CurrentValue
}

function Read-OptionalInput {
    param (
        [string]$Prompt,
        [string]$CurrentValue,
        [string]$Default = ""
    )
    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        $userInput = Read-Host "$Prompt (optional, press Enter to skip)"
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            return $Default
        }
        return $userInput
    }
    return $CurrentValue
}
#endregion

#region Validation Functions
function Convert-ToASCII {
    param([string]$InputString)
    $normalized = $InputString.Normalize([Text.NormalizationForm]::FormD)
    $ascii = New-Object Text.StringBuilder
    $normalized.ToCharArray() | ForEach-Object {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$ascii.Append($_)
        }
    }
    return $ascii.ToString().Normalize([Text.NormalizationForm]::FormC)
}

function Test-ValidUsername {
    param([string]$Username)
    # AD username: 1-20 chars, alphanumeric plus ._-@, must start with letter or digit
    if ($Username.Length -lt 1 -or $Username.Length -gt 20) { return $false }
    if ($Username -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$') { return $false }
    return $true
}

function Test-PasswordComplexity {
    param([SecureString]$Password)
    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $plainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    $valid = ($plainText.Length -ge 12) -and
             ($plainText -match '[A-Z]') -and
             ($plainText -match '[a-z]') -and
             ($plainText -match '\d') -and
             ($plainText -match '[^a-zA-Z0-9]')

    $plainText = $null
    return $valid
}

function Test-PhoneFormat {
    param([string]$Phone)
    # E.164 format: 11 digits starting with 1 (US/Canada)
    if ([string]::IsNullOrWhiteSpace($Phone)) { return $true } # Optional field
    if ($Phone -notmatch '^\d{11}$') { return $false }
    if ($Phone[0] -ne '1') { return $false }
    return $true
}

function Get-GroupNameFromDN {
    param([string]$DN)
    # Extract CN= value from DN (e.g., "CN=GroupName,OU=..." -> "GroupName")
    if ($DN -match '^CN=([^,]+)') {
        return $matches[1]
    }
    return $DN
}
#endregion

#region Job Title Group Mappings
$jobTitleGroups = @{
    "Assistant Manager" = @(
        "All Assistant Managers",
        "AllAssistantManagersENG"
    )
    "Assistant Manager (alt)" = @(
        "All Assistant Managers",
        "AllAssistantManagersENG"
    )
    "Operations Supervisor" = @(
        "All Operations Supervisors",
        "AllOperationsSupervisorsENG",
        "Core Team",
        "CoreTeamENG"
    )
    "Operations Manager" = @(
        "All Operations Managers",
        "AllOperationsManagersENG",
        "Core Team",
        "CoreTeamENG"
    )
    "Services Coordinator" = @(
        "All Member Services",
        "AllMemberServicesENG"
    )
    "Services Manager" = @(
        "All Member Services",
        "AllMemberServicesENG",
        "Services Team",
        "ServicesTeamENG"
    )
}
#endregion

#region Interactive Prompts
Write-Host "`n=== Contoso New User Creation ===" -ForegroundColor Cyan
Write-Host "Fill in required fields. Optional fields can be skipped.`n" -ForegroundColor Gray

# --- User Info ---
Write-Host "--- User Information ---" -ForegroundColor Yellow
$FirstName = Read-RequiredInput -Prompt "First Name" -CurrentValue $FirstName
$LastName = Read-RequiredInput -Prompt "Last Name" -CurrentValue $LastName
$Department = Read-RequiredInput -Prompt "Department" -CurrentValue $Department
$JobTitle = Read-RequiredInput -Prompt "Job Title (expand abbreviations)" -CurrentValue $JobTitle

# --- Employment Type ---
Write-Host "`n--- Employment Type ---" -ForegroundColor Yellow
if ([string]::IsNullOrWhiteSpace($EmploymentType)) {
    Write-Host "1: Full-Time"
    Write-Host "2: Temporary"
    do {
        $empChoice = Read-Host "Select employment type (1 or 2)"
        switch ($empChoice) {
            "1" { $EmploymentType = "FullTime" }
            "2" { $EmploymentType = "Temp" }
            default { Write-Host "  Invalid selection. Enter 1 or 2." -ForegroundColor Red }
        }
    } while ([string]::IsNullOrWhiteSpace($EmploymentType))
} else {
    Write-Host "Employment Type: $EmploymentType (from parameter)" -ForegroundColor Gray
}

# --- Maintenance Role ---
Write-Host "`n--- Maintenance Role ---" -ForegroundColor Yellow
Write-Host "1: Not maintenance staff (default)"
Write-Host "2: Maintenance Technician"
Write-Host "3: Maintenance Supervisor"
$maintChoice = Read-Host "Select maintenance role (1, 2, or 3 - press Enter for default)"
$MaintenanceRole = switch ($maintChoice) {
    "2" { "Technician" }
    "3" { "Supervisor" }
    default { "None" }
}
if ($MaintenanceRole -ne "None") {
    Write-Host "  Maintenance Role: $MaintenanceRole" -ForegroundColor Green
} else {
    Write-Host "  Not maintenance staff" -ForegroundColor Gray
}

# --- Account Relationships ---
Write-Host "`n--- Account Relationships ---" -ForegroundColor Yellow
$MirrorUser = Read-OptionalInput -Prompt "Mirror User (username to copy groups from)" -CurrentValue $MirrorUser
$Manager = Read-RequiredInput -Prompt "Manager (username)" -CurrentValue $Manager

# --- Contact Info (Optional) ---
Write-Host "`n--- Contact Information (Optional) ---" -ForegroundColor Yellow
Write-Host "Phone format: digits with country code, e.g., 15101234567" -ForegroundColor Gray
$CellPhone = Read-OptionalInput -Prompt "Cell Phone" -CurrentValue $CellPhone
$OfficePhone = Read-OptionalInput -Prompt "Office Phone" -CurrentValue $OfficePhone

# --- Location Info (Optional) ---
Write-Host "`n--- Location Information (Optional) ---" -ForegroundColor Yellow
$Office = Read-OptionalInput -Prompt "Property/Office Name" -CurrentValue $Office
$StreetAddress = Read-OptionalInput -Prompt "Street Address" -CurrentValue $StreetAddress
$City = Read-OptionalInput -Prompt "City" -CurrentValue $City
$ZipCode = Read-OptionalInput -Prompt "Zip Code" -CurrentValue $ZipCode
#endregion

#region OU Selection
# Contoso uses two primary OUs based on work location
$ouOption1 = "OU=MainOffice,OU=Egnyte,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com"
$ouOption2 = "OU=RemoteSites,OU=Egnyte,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com"

Write-Host "`n--- Organizational Unit ---" -ForegroundColor Yellow
Write-Host "1: Main Office"
Write-Host "2: Remote Sites (site-based staff)"
do {
    $ouChoice = Read-Host "Select OU (1 or 2)"
    switch ($ouChoice) {
        "1" { $ou = $ouOption1; $locationDesc = "Main Office" }
        "2" { $ou = $ouOption2; $locationDesc = "Remote Sites" }
        default { 
            Write-Host "  Invalid selection. Enter 1 or 2." -ForegroundColor Red
            $ou = $null
        }
    }
} while ($null -eq $ou)

# Validate OU exists
try {
    $ouExists = Get-ADOrganizationalUnit -Identity $ou -ErrorAction Stop
    Write-Host "  OU validated: $locationDesc" -ForegroundColor Green
} catch {
    Write-Error "Selected OU does not exist or is inaccessible: $ou"
    Stop-Transcript
    return
}
#endregion

#region Username Generation
# Contoso username convention: firstinitiallastname (e.g., Bob Axe = baxe)
# Fallback if taken in Egnyte: firstname.lastname (e.g., bob.axe)

# Sanitize and transliterate names
$cleanFirstName = Convert-ToASCII -InputString $FirstName
$cleanLastName = Convert-ToASCII -InputString $LastName

# Remove non-alphanumeric characters (except dots, which we'll handle separately)
$cleanFirstName = [regex]::Replace($cleanFirstName, '[^a-zA-Z]', '')
$cleanLastName = [regex]::Replace($cleanLastName, '[^a-zA-Z]', '')

# Validate we have usable names after sanitization
if ([string]::IsNullOrWhiteSpace($cleanFirstName) -or [string]::IsNullOrWhiteSpace($cleanLastName)) {
    Write-Error "Names contain only special characters or are invalid after sanitization. Original: '$FirstName $LastName'"
    Stop-Transcript
    return
}

# Generate username
$username = ($cleanFirstName.Substring(0, 1) + $cleanLastName).ToLower()
$upnSuffix = "@contoso.com"
$company = "Contoso"

# Validate generated username
if (-not (Test-ValidUsername -Username $username)) {
    Write-Error "Generated username '$username' is invalid for Active Directory. Use alternate username."
    $username = ""
}

Write-Host "`n--- Generated Username ---" -ForegroundColor Yellow
if ($username) {
    Write-Host "Username: $username" -ForegroundColor White
} else {
    Write-Host "Auto-generation failed. Please provide username manually." -ForegroundColor Yellow
}
Write-Host "NOTE: Verify this username is available in Egnyte before proceeding." -ForegroundColor Yellow

do {
    $usernameConfirm = Read-Host "Press Enter to accept '$username', or type alternate username"
    if (-not [string]::IsNullOrWhiteSpace($usernameConfirm)) {
        $username = $usernameConfirm.ToLower()
        if (-not (Test-ValidUsername -Username $username)) {
            Write-Host "  Invalid username format. Must be 1-20 chars, alphanumeric with ._- allowed." -ForegroundColor Red
            $username = ""
        } else {
            Write-Host "Using alternate username: $username" -ForegroundColor Green
        }
    } elseif ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "  Username is required." -ForegroundColor Red
    }
} while ([string]::IsNullOrWhiteSpace($username))
#endregion

#region Validation
Write-Host "`n--- Validating ---" -ForegroundColor Yellow

# Validate manager exists in AD
try {
    $managerDN = (Get-ADUser -Identity $Manager -ErrorAction Stop).DistinguishedName
    Write-Host "  Manager validated: $Manager" -ForegroundColor Green
} catch {
    Write-Error "Manager with username '$Manager' does not exist in AD."
    Stop-Transcript
    return
}

# Validate mirror user exists in AD (if provided)
$mirrorUserObj = $null
if (-not [string]::IsNullOrWhiteSpace($MirrorUser)) {
    try {
        $mirrorUserObj = Get-ADUser -Identity $MirrorUser -Properties MemberOf -ErrorAction Stop
        Write-Host "  Mirror user validated: $MirrorUser" -ForegroundColor Green
    } catch {
        Write-Error "Mirror user with username '$MirrorUser' does not exist in AD."
        Stop-Transcript
        return
    }
} else {
    Write-Host "  No mirror user specified (will use job-based groups)" -ForegroundColor Gray
}

# Check if target username already exists
$userExists = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
if ($userExists) {
    Write-Error "User with sAMAccountName '$username' already exists. Use firstname.lastname format or verify correct user."
    Stop-Transcript
    return
}
Write-Host "  Username available: $username" -ForegroundColor Green
#endregion

#region Phone Formatting
# Contoso requires phone numbers without dashes/parentheses, with country code
# Format: 19252770690 (not (925) 277-0690)
$formattedCell = $CellPhone -replace "[^\d]"
$formattedOffice = $OfficePhone -replace "[^\d]"

# Validate phone number formats
if (-not (Test-PhoneFormat -Phone $formattedCell)) {
    Write-Warning "Cell phone format invalid. Expected: 11 digits starting with 1 (e.g., 15101234567). Provided: '$formattedCell'"
    $formattedCell = ""
}
if (-not (Test-PhoneFormat -Phone $formattedOffice)) {
    Write-Warning "Office phone format invalid. Expected: 11 digits starting with 1 (e.g., 19252770690). Provided: '$formattedOffice'"
    $formattedOffice = ""
}

# Flag missing optional fields
$missingOptional = @()
if ([string]::IsNullOrWhiteSpace($formattedCell)) { $missingOptional += "Cell Phone" }
if ([string]::IsNullOrWhiteSpace($formattedOffice)) { $missingOptional += "Office Phone" }
if ([string]::IsNullOrWhiteSpace($Office)) { $missingOptional += "Property/Office Name" }
if ([string]::IsNullOrWhiteSpace($StreetAddress)) { $missingOptional += "Street Address" }

if ($missingOptional.Count -gt 0) {
    Write-Host "`nOptional fields not provided (can be updated later):" -ForegroundColor Yellow
    $missingOptional | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
}
#endregion

#region Password Handling
Write-Host "`n--- Password ---" -ForegroundColor Yellow
Write-Host "Requirements: 12+ chars, special chars, capitals, numbers" -ForegroundColor Gray

do {
    if ($null -eq $Password) {
        $securePassword = Read-Host -AsSecureString "Enter temporary password for $username"
    } else {
        $securePassword = $Password
        Write-Host "Password provided via parameter." -ForegroundColor Gray
    }

    if (-not (Test-PasswordComplexity -Password $securePassword)) {
        Write-Host "  Password does not meet complexity requirements:" -ForegroundColor Red
        Write-Host "  - Minimum 12 characters" -ForegroundColor Red
        Write-Host "  - At least one uppercase letter" -ForegroundColor Red
        Write-Host "  - At least one lowercase letter" -ForegroundColor Red
        Write-Host "  - At least one number" -ForegroundColor Red
        Write-Host "  - At least one special character" -ForegroundColor Red
        $Password = $null
        $securePassword = $null
    }
} while ($null -eq $securePassword -or -not (Test-PasswordComplexity -Password $securePassword))

Write-Host "  Password meets complexity requirements." -ForegroundColor Green
#endregion

#region Confirmation Summary
$employmentGroup = switch ($EmploymentType) {
    "FullTime" { "Full-Time Employees" }
    "Temp"     { "Temp Employees" }
    default    { "Full-Time Employees" }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "        CONFIRM USER CREATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Username:       $username"
Write-Host "Display Name:   $FirstName $LastName"
Write-Host "Email:          $username@contoso.com"
Write-Host "Job Title:      $JobTitle"
Write-Host "Department:     $Department"
Write-Host "Manager:        $Manager"
if ([string]::IsNullOrWhiteSpace($MirrorUser)) {
    Write-Host "Mirror User:    (none - using job-based groups)" -ForegroundColor Gray
} else {
    Write-Host "Mirror User:    $MirrorUser"
}
Write-Host "Location:       $locationDesc"
Write-Host "Employment:     $employmentGroup"
if (-not [string]::IsNullOrWhiteSpace($Office)) {
    Write-Host "Office:         $Office"
}
if ($Properties.Count -gt 0) {
    Write-Host "Properties:     $($Properties -join ', ')"
}
if ($Portfolio.Count -gt 0) {
    Write-Host "Portfolio:      $($Portfolio -join ', ')"
}
if ($Groups.Count -gt 0) {
    Write-Host "Explicit Groups: $($Groups -join ', ')"
}
Write-Host "========================================" -ForegroundColor Cyan

$confirm = Read-Host "`nProceed with user creation? (Y/N)"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "User creation cancelled." -ForegroundColor Yellow
    Stop-Transcript
    return
}
#endregion

#region Create AD User
Write-Host "`n--- Creating AD User ---" -ForegroundColor Yellow

# Build the user object with all required attributes
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
    AccountPassword       = $securePassword
    ChangePasswordAtLogon = $false
    PasswordNeverExpires  = $false
    EmailAddress          = "$username@contoso.com"
    Path                  = $ou
}

# Add optional fields if provided
# Phone handling differs for remote site temps per Contoso documentation
$isRemoteSiteTemp = ($EmploymentType -eq "Temp") -and ($locationDesc -eq "Remote Sites")

if (-not [string]::IsNullOrWhiteSpace($formattedCell)) {
    $newUserParams.MobilePhone = $formattedCell
    if (-not $isRemoteSiteTemp) {
        $newUserParams.HomePhone = $formattedCell
    }
}
if (-not [string]::IsNullOrWhiteSpace($formattedOffice)) {
    if ($isRemoteSiteTemp) {
        $newUserParams.HomePhone = $formattedOffice
    } else {
        $newUserParams.OfficePhone = $formattedOffice
    }
}
if (-not [string]::IsNullOrWhiteSpace($StreetAddress)) {
    $newUserParams.StreetAddress = $StreetAddress
}
if (-not [string]::IsNullOrWhiteSpace($City)) {
    $newUserParams.City = $City
}
if (-not [string]::IsNullOrWhiteSpace($State)) {
    $newUserParams.State = $State
}
if (-not [string]::IsNullOrWhiteSpace($ZipCode)) {
    $newUserParams.PostalCode = $ZipCode
}
if (-not [string]::IsNullOrWhiteSpace($Office)) {
    $newUserParams.Office = $Office
}

# Additional attributes (physicalDeliveryOfficeName, telephoneNumber)
$otherAttributes = @{}
if ((-not [string]::IsNullOrWhiteSpace($formattedOffice)) -and (-not $isRemoteSiteTemp)) {
    $otherAttributes.otherTelephone = $formattedOffice
}
if ($Properties.Count -gt 0) {
    $otherAttributes.physicalDeliveryOfficeName = $Properties -join "; "
}

try {
    if ($otherAttributes.Count -gt 0) {
        New-ADUser @newUserParams -OtherAttributes $otherAttributes -ErrorAction Stop
    } else {
        New-ADUser @newUserParams -ErrorAction Stop
    }
    Write-Host "  AD User '$username' created successfully." -ForegroundColor Green
    
    # Brief pause for replication
    Write-Host "  Waiting for replication..." -ForegroundColor Gray
    Start-Sleep -Seconds 5
} catch {
    Write-Error "Error creating AD User: $($_.Exception.Message)"
    Stop-Transcript
    return
}
#endregion

#region Group Memberships
$groupsAdded = @()
$groupsFailed = @()
$pendingItems = @()

function Add-UserToGroup {
    param(
        [string]$GroupName,
        [string]$Username,
        [string]$Source
    )
    if ($groupsAdded -contains $GroupName) {
        Write-Host "  ~ $GroupName (already added via $Source)" -ForegroundColor Gray
        return
    }
    $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($group) {
        try {
            Add-ADGroupMember -Identity $group -Members $Username -ErrorAction Stop
            Write-Host "  + $GroupName" -ForegroundColor Green
            $script:groupsAdded += $GroupName
        } catch {
            if ($_.Exception.Message -match "already a member|object already exists") {
                Write-Host "  ~ $GroupName (already member)" -ForegroundColor Gray
            } else {
                Write-Warning "  Could not add to '$GroupName': $($_.Exception.Message)"
                $script:groupsFailed += $GroupName
            }
        }
    } else {
        Write-Warning "  Group '$GroupName' not found in AD."
        $script:groupsFailed += $GroupName
    }
}

# --- 1. Copy group memberships from mirror user (if provided) ---
if ($null -ne $mirrorUserObj) {
    $mirrorGroups = $mirrorUserObj.MemberOf
    if ($mirrorGroups) {
        Write-Host "`n--- Copying groups from mirror user '$MirrorUser' ---" -ForegroundColor Yellow
        foreach ($groupDN in $mirrorGroups) {
            try {
                Add-ADGroupMember -Identity $groupDN -Members $username -ErrorAction Stop
                $groupName = Get-GroupNameFromDN -DN $groupDN
                Write-Host "  + $groupName" -ForegroundColor Green
                $groupsAdded += $groupName
            } catch {
                $groupName = Get-GroupNameFromDN -DN $groupDN
                if ($_.Exception.Message -match "already a member|object already exists") {
                    Write-Host "  ~ $groupName (already member)" -ForegroundColor Gray
                } else {
                    Write-Warning "  Could not add to '$groupName': $($_.Exception.Message)"
                    $groupsFailed += $groupName
                }
            }
        }
    }
}

# --- 2. Add job-title based groups ---
if ($jobTitleGroups.ContainsKey($JobTitle)) {
    Write-Host "`n--- Adding job title groups for '$JobTitle' ---" -ForegroundColor Yellow
    foreach ($groupName in $jobTitleGroups[$JobTitle]) {
        Add-UserToGroup -GroupName $groupName -Username $username -Source "job title"
    }
} else {
    Write-Host "`n--- No automatic groups for job title '$JobTitle' ---" -ForegroundColor Yellow
    $pendingItems += "Verify role-based groups with supervisor (job title '$JobTitle' has no automatic mappings)"
}

# --- 3. Add portfolio groups (translate "West" to "Portfolio West") ---
if ($Portfolio.Count -gt 0) {
    Write-Host "`n--- Adding portfolio groups ---" -ForegroundColor Yellow
    foreach ($portfolioName in $Portfolio) {
        $portfolioGroupName = if ($portfolioName -match "^Portfolio ") { $portfolioName } else { "Portfolio $portfolioName" }
        Add-UserToGroup -GroupName $portfolioGroupName -Username $username -Source "portfolio parameter"
    }
}

# --- 4. Add explicit groups from -Groups parameter ---
if ($Groups.Count -gt 0) {
    Write-Host "`n--- Adding explicit groups ---" -ForegroundColor Yellow
    foreach ($groupName in $Groups) {
        Add-UserToGroup -GroupName $groupName -Username $username -Source "explicit parameter"
    }
}

# --- 5. Interactive group prompt (when no mirror user and no explicit groups) ---
if ($null -eq $mirrorUserObj -and $Groups.Count -eq 0 -and -not $SkipGroupPrompt) {
    Write-Host "`n--- Additional Groups ---" -ForegroundColor Yellow
    Write-Host "No mirror user or explicit groups provided." -ForegroundColor Gray
    Write-Host "Common optional groups: Portfolio [Name], Regional Program" -ForegroundColor Gray
    $additionalGroups = Read-Host "Enter additional group names (comma-separated, or press Enter to skip)"
    if (-not [string]::IsNullOrWhiteSpace($additionalGroups)) {
        $additionalGroupList = $additionalGroups -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($groupName in $additionalGroupList) {
            Add-UserToGroup -GroupName $groupName -Username $username -Source "interactive"
        }
    }
    $pendingItems += "Confirm with supervisor: additional portfolios, program groups, shared mailboxes"
}

# --- 6. Mandatory groups for ALL Contoso users ---
$mandatoryGroups = @(
    "Intune Enrolled Users",
    "DuoSecurity",
    "Phin Onboarding",
    "Wireless Users",
    "Second Fine-Grained Password Policy",
    "Self-Service Password Reset"
)

# Add Contoso-Main Printers for Main Office users
if ($locationDesc -eq "Main Office") {
    $mandatoryGroups += "Contoso-Main Printers"
}

# Add maintenance-specific groups based on role
if ($MaintenanceRole -eq "Technician" -or $MaintenanceRole -eq "Supervisor") {
    $mandatoryGroups += @(
        "All Maintenance",
        "AllMaintenanceENG",
        "AllStaff",
        "AllStaffENG"
    )
}
if ($MaintenanceRole -eq "Supervisor") {
    $mandatoryGroups += @(
        "Facilities Supervisors",
        "Facilities Leadership Team",
        "FacilitiesLeadershipTeamENG"
    )
}

# Combine mandatory + employment type groups
$allRequiredGroups = $mandatoryGroups + $employmentGroup

Write-Host "`n--- Adding mandatory groups ---" -ForegroundColor Yellow
foreach ($groupName in $allRequiredGroups) {
    Add-UserToGroup -GroupName $groupName -Username $username -Source "mandatory"
}
#endregion

#region Azure AD Sync
Write-Host "`n--- Azure AD Connect Sync ---" -ForegroundColor Yellow

$syncTriggered = $false
if (Get-Module -Name ADSync -ListAvailable -ErrorAction SilentlyContinue) {
    try {
        Import-Module ADSync -ErrorAction Stop
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
        Write-Host "  Delta sync triggered successfully." -ForegroundColor Green
        $syncTriggered = $true
    } catch {
        Write-Warning "  Error triggering sync: $($_.Exception.Message)"
    }
}

if (-not $syncTriggered) {
    Write-Host "  ADSync module not available on this machine." -ForegroundColor Yellow
    Write-Host "  Run this command on the AAD Connect server:" -ForegroundColor Yellow
    Write-Host "    Start-ADSyncSyncCycle -PolicyType Delta" -ForegroundColor White
}
#endregion

#region Pre-Output Checks
if ([string]::IsNullOrWhiteSpace($formattedCell)) {
    $pendingItems += "DUO BLOCKER: Mobile phone required for MFA enrollment"
}
#endregion

#region Output Object
$result = [PSCustomObject]@{
    Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Username        = $username
    Email           = "$username@contoso.com"
    DisplayName     = "$FirstName $LastName"
    JobTitle        = $JobTitle
    Department      = $Department
    Manager         = $Manager
    MirrorUser      = if ([string]::IsNullOrWhiteSpace($MirrorUser)) { "(none)" } else { $MirrorUser }
    Location        = $locationDesc
    EmploymentType  = $employmentGroup
    Properties      = if ($Properties.Count -gt 0) { $Properties -join "; " } else { "(none)" }
    OU              = $ou
    GroupsAdded     = ($groupsAdded | Select-Object -Unique) -join "; "
    GroupsFailed    = $groupsFailed -join "; "
    PendingItems    = $pendingItems -join "; "
    SyncTriggered   = $syncTriggered
    TranscriptPath  = $transcriptPath
}
#endregion

#region Final Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "        USER CREATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Username:      $username"
Write-Host "Email:         $username@contoso.com"
Write-Host "Groups Added:  $($groupsAdded.Count)"
if ($groupsFailed.Count -gt 0) {
    Write-Host "Groups Failed: $($groupsFailed.Count)" -ForegroundColor Yellow
    Write-Host "`nWARNING: The following groups failed to add:" -ForegroundColor Yellow
    $groupsFailed | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Yellow }

    # Check if critical security groups are missing
    $criticalGroups = @("DuoSecurity", "Intune Enrolled Users", "Second Fine-Grained Password Policy")
    $missingCritical = $groupsFailed | Where-Object { $criticalGroups -contains $_ }

    if ($missingCritical) {
        Write-Host "`nCRITICAL: User is missing essential security groups!" -ForegroundColor Red
        $missingCritical | ForEach-Object { Write-Host "  !! $_" -ForegroundColor Red }
        Write-Host "REQUIRED ACTION: Manually add these groups immediately." -ForegroundColor Red
    }
}

# DUO Mobile Warning
if ([string]::IsNullOrWhiteSpace($formattedCell)) {
    Write-Host "`nWARNING: No mobile phone provided!" -ForegroundColor Red
    Write-Host "  DUO enrollment will FAIL without a mobile number." -ForegroundColor Red
    Write-Host "  ACTION: Obtain mobile from supervisor and update user before first login." -ForegroundColor Red
}

# Pending Items
if ($pendingItems.Count -gt 0) {
    Write-Host "`nPENDING ITEMS (requires supervisor confirmation):" -ForegroundColor Yellow
    $pendingItems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

# Shared Mailbox Suggestions (if properties specified)
if ($Properties.Count -gt 0) {
    Write-Host "`nProperty Mailbox Recommendations:" -ForegroundColor Cyan
    Write-Host "  Properties assigned: $($Properties -join ', ')"
    Write-Host "  Verify shared mailbox access needed for these properties with supervisor."
}

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Verify AD sync completed (check Azure AD / M365 admin)"
Write-Host "  2. Assign M365 license via Partner Center (Business Premium default, Business Basic for contractors/service accounts)"
Write-Host "  3. Configure shared mailbox access if PM/APM/MT Staff role"
Write-Host "  4. Add to Egnyte (verify username: $username)"
Write-Host "  5. Send encrypted credentials to stakeholders"
if ([string]::IsNullOrWhiteSpace($formattedCell)) {
    Write-Host "  6. UPDATE MOBILE PHONE before user's first day (DUO requirement)" -ForegroundColor Red
}

if ($transcriptPath) {
    Write-Host "`nTranscript saved to: $transcriptPath" -ForegroundColor Gray
}
Write-Host "========================================" -ForegroundColor Cyan

if ($transcriptPath) {
    Stop-Transcript | Out-Null
} else {
    Write-Verbose "No transcript to stop (logging was disabled)"
}

# Return result object for pipeline use
$result
#endregion