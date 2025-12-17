<#
.SYNOPSIS
    Active Directory User Onboarding with Group Mirroring

.DESCRIPTION
    Automates the creation of new Active Directory user accounts with comprehensive
    provisioning features including:
    - Automatic username generation (first initial + last name)
    - Role-based group assignment
    - Permission mirroring from existing users
    - Azure AD Connect sync triggering for hybrid environments
    - Detailed audit logging

    Designed for MSP/enterprise environments with standardized onboarding workflows.

.PARAMETER FirstName
    User's first name (default: template value - CHANGE THIS)

.PARAMETER LastName
    User's last name (default: template value - CHANGE THIS)

.PARAMETER Department
    Department name (e.g., "Property Management", "IT", "Facilities")

.PARAMETER JobTitle
    Job title (determines role-specific group assignments)

.PARAMETER Company
    Specifies the company.

.PARAMETER OfficeNumber
    Specifies the office number.

.PARAMETER Mobile
    Specifies the mobile.

.PARAMETER StreetAddress
    Specifies the street address.

.PARAMETER City
    Specifies the city.

.PARAMETER State
    Specifies the state.

.PARAMETER ZipCode
    Specifies the zip code.

.PARAMETER Country
    Specifies the country.

.PARAMETER Office
    Specifies the office.

.PARAMETER MirrorUser
    Existing AD username to copy group memberships from

.PARAMETER Manager
    Manager's AD username for supervisor assignment

.PARAMETER OULocation
    'AlcatrazOffice' or 'RemoteSites' - determines OU placement

.PARAMETER EmploymentType
    'Regular' for full-time, 'Temp' for temporary employees

.PARAMETER UserRole
    Specifies the user role.

.PARAMETER DefaultPassword
    Specifies the default password.

.PARAMETER UpnSuffix
    Specifies the upn suffix.

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Initialize-ADUserOnboarding.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Initialize-ADUserOnboarding.ps1' -FirstName 'Value' -LastName 'Value' -Department 'Value'

.NOTES
    Author: Brandon Sager
    Version: 1.0

    Requirements:
    - PowerShell 5.1+
    - Active Directory module (RSAT)
    - Domain Admin or delegated OU permissions
    - Azure AD Connect (for hybrid sync)

    Logging: Creates detailed logs at C:\Temp\OnboardAD_timestamp.log
#>

[CmdletBinding()]
param(
    # === TEMPLATE VALUES - CUSTOMIZE FOR EACH NEW USER ===
    
    [Parameter(HelpMessage = "User's first name")]
    [string]$FirstName = "FIRSTNAME_PLACEHOLDER",              # CHANGE THIS: New user's first name
    
    [Parameter(HelpMessage = "User's last name")]
    [string]$LastName = "LASTNAME_PLACEHOLDER",                # CHANGE THIS: New user's last name
    
    [Parameter(HelpMessage = "Department name")]
    [string]$Department = "Property Management",               # CHANGE THIS: User's department
    
    [Parameter(HelpMessage = "Job title")]
    [string]$JobTitle = "Assistant Property Manager",          # CHANGE THIS: User's job title
    
    # === ORGANIZATIONAL DEFAULTS (Usually don't change) ===
    
    [Parameter(HelpMessage = "Company name")]
    [string]$Company = "Contoso",                              # Standard: Company name
    
    # === CONTACT INFORMATION - CUSTOMIZE FOR EACH USER ===
    
    [Parameter(HelpMessage = "Office phone number (digits only)")]
    [string]$OfficeNumber = "OFFICE_PHONE_PLACEHOLDER",        # CHANGE THIS: Office phone (format: 1234567890)
    
    [Parameter(HelpMessage = "Mobile phone number (digits only)")]
    [string]$Mobile = "MOBILE_PHONE_PLACEHOLDER",              # CHANGE THIS: Mobile phone (format: 1234567890)
    
    # === ADDRESS INFORMATION - CUSTOMIZE FOR EACH USER ===
    
    [Parameter(HelpMessage = "Street address with property details")]
    [string]$StreetAddress = "STREET_ADDRESS_PLACEHOLDER",     # CHANGE THIS: Full address with property name
    
    [Parameter(HelpMessage = "City name")]
    [string]$City = "CITY_PLACEHOLDER",                        # CHANGE THIS: City name
    
    [Parameter(HelpMessage = "State abbreviation")]
    [string]$State = "CA",                                     # Default state
    
    [Parameter(HelpMessage = "ZIP code")]
    [string]$ZipCode = "ZIP_CODE_PLACEHOLDER",                 # CHANGE THIS: Property ZIP code
    
    [Parameter(HelpMessage = "Country code")]
    [string]$Country = "US",                                   # Standard: United States
    
    [Parameter(HelpMessage = "Office/Property name")]
    [string]$Office = "PROPERTY_NAME_PLACEHOLDER",             # CHANGE THIS: Property/office name
    
    # === ORGANIZATIONAL RELATIONSHIPS - CUSTOMIZE FOR EACH USER ===
    
    [Parameter(HelpMessage = "Username of user to copy permissions from")]
    [string]$MirrorUser = "USERNAME_TO_MIRROR",                # CHANGE THIS: Existing user to copy groups from
    
    [Parameter(HelpMessage = "Manager's username")]
    [string]$Manager = "MANAGER_USERNAME",                     # CHANGE THIS: Manager's AD username
    
    [Parameter()]
    [ValidateSet('Headquarters', 'RemoteSites')]
    [string]$OULocation = 'RemoteSites',
    
    [Parameter()]
    [ValidateSet('Regular', 'Temp')]
    [string]$EmploymentType = 'Temp',
    
    [Parameter()]
    [ValidateSet('Standard', 'MaintenanceTechnician', 'MaintenanceSupervisor')]
    [string]$UserRole = 'Standard',
    
    [Parameter()]
    [string]$DefaultPassword = '',
    
    # === DOMAIN CONFIGURATION (Usually don't change) ===
    
    [Parameter(HelpMessage = "UPN suffix for domain")]
    [string]$UpnSuffix = "@contoso.com"                            # Domain suffix for UPN
)

#==============================================================================
# INITIALIZATION AND LOGGING SETUP
#==============================================================================

# Create temp directory for logging (required for system context execution)
if (!(Test-Path -LiteralPath 'C:\Temp')) { 
    New-Item -ItemType Directory -Path 'C:\Temp' | Out-Null 
}

# Configure comprehensive logging for audit trail and troubleshooting
$Log = ('C:\Temp\{0}_{1}.log' -f 'OnboardAD', (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Logging function - writes to both console (for RMM visibility) and file
function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $ts = (Get-Date).ToString('s')
    "$ts`t$Message" | Tee-Object -FilePath $Log -Append
}

#==============================================================================
# MAIN ONBOARDING PROCESS
#==============================================================================

Write-Log "=== Starting AD Onboarding for User: $FirstName $LastName ==="
Write-Log "Parameters: Department=$Department, JobTitle=$JobTitle, EmploymentType=$EmploymentType, UserRole=$UserRole"

try {
    #--------------------------------------------------------------------------
    # STEP 1: ACTIVE DIRECTORY MODULE INITIALIZATION
    # Required for all AD operations - handles both PS5.1 and PS7 compatibility
    #--------------------------------------------------------------------------
    
    Write-Log "Importing Active Directory module..."
    if (-not (Get-Module -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Log "Active Directory module imported successfully"
        } catch {
            Write-Log "PowerShell 7 fallback for ActiveDirectory module"
            Import-Module ActiveDirectory -UseWindowsPowerShell -ErrorAction Stop
            Write-Log "Active Directory module imported successfully (Windows PowerShell compatibility)"
        }
    } else {
        Write-Log "Active Directory module already loaded"
    }
    
    #--------------------------------------------------------------------------
    # STEP 2: USERNAME GENERATION AND CONFLICT DETECTION
    # Naming convention: first initial + last name (lowercase)
    # Must check for conflicts before proceeding with account creation
    #--------------------------------------------------------------------------
    
    # Generate username following standard format
    $Username = ($FirstName.Substring(0, 1) + $LastName).ToLower()
    Write-Log "Generated username: $Username"
    
    # Critical safety check - prevent duplicate accounts
    Write-Log "=== Step 1: User Conflict Checking ==="
    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
    if ($ExistingUser) {
        Write-Log "FATAL ERROR: User with SamAccountName '$Username' already exists"
        Write-Log "Existing user: $($ExistingUser.DisplayName) ($($ExistingUser.DistinguishedName))"
        throw "User conflict detected - aborting onboarding process"
    }
    Write-Log "Username '$Username' is available"
    
    # Validate manager and mirror user
    Write-Log "=== Step 2: Validate Dependencies ==="
    try {
        $ManagerDN = (Get-ADUser -Identity $Manager -ErrorAction Stop).DistinguishedName
        Write-Log "Manager validated: $Manager"
    } catch {
        Write-Log "FATAL ERROR: Manager with username '$Manager' does not exist in AD"
        throw "Manager validation failed"
    }
    
    try {
        $MirrorUserObj = Get-ADUser -Identity $MirrorUser -Properties MemberOf -ErrorAction Stop
        Write-Log "Mirror user validated: $MirrorUser"
        Write-Log "Mirror user has $($MirrorUserObj.MemberOf.Count) group memberships"
    } catch {
        Write-Log "FATAL ERROR: Mirror user with username '$MirrorUser' does not exist in AD"
        throw "Mirror user validation failed"
    }
    
    # OU Selection
    Write-Log "=== Step 3: Organizational Unit Selection ==="
    $ouOption1 = "OU=AlcatrazOffice,OU=Egnyte,OU=Managed Users,OU=Managed Objects,DC=sathomes,DC=org"
    $ouOption2 = "OU=RemoteSites,OU=Egnyte,OU=Managed Users,OU=Managed Objects,DC=sathomes,DC=org"
    
    if ([string]::IsNullOrWhiteSpace($OULocation)) {
        Write-Log "No OU parameter provided - prompting for selection"
        Write-Host "Select the OU for the new user:"
        Write-Host "1: Alcatraz Office"
        Write-Host "2: Remote Sites"
        do {
            $ouChoice = Read-Host "Enter your choice (1 or 2)"
        } while ($ouChoice -notin @("1", "2"))
        
        switch ($ouChoice) {
            "1" { 
                $TargetOU = $ouOption1
                $OULocation = "AlcatrazOffice"
            }
            "2" { 
                $TargetOU = $ouOption2 
                $OULocation = "RemoteSites"
            }
        }
    } else {
        switch ($OULocation) {
            "AlcatrazOffice" { $TargetOU = $ouOption1 }
            "RemoteSites" { $TargetOU = $ouOption2 }
        }
    }
    Write-Log "Selected OU: $OULocation"
    Write-Log "Target DN: $TargetOU"
    
    # Password handling
    Write-Log "=== Step 4: Password Configuration ==="
    if ([string]::IsNullOrWhiteSpace($DefaultPassword)) {
        $SecurePassword = Read-Host -AsSecureString "Enter a temporary password for $Username"
        Write-Log "Password provided interactively"
    } else {
        $SecurePassword = ConvertTo-SecureString -String $DefaultPassword -AsPlainText -Force
        Write-Log "Password provided via parameter"
    }
    
    # Format phone numbers
    $FormattedMobile = $Mobile -replace "[^\d]"
    $FormattedOfficeNumber = $OfficeNumber -replace "[^\d]"
    Write-Log "Formatted mobile: $FormattedMobile"
    Write-Log "Formatted office: $FormattedOfficeNumber"
    
    # Create user account
    Write-Log "=== Step 5: Create User Account ==="
    $NewUserDetails = @{
        SamAccountName        = $Username
        UserPrincipalName     = $Username + $UpnSuffix
        Name                  = "$FirstName $LastName"
        GivenName             = $FirstName
        Surname               = $LastName
        Enabled               = $true
        DisplayName           = "$FirstName $LastName"
        Title                 = $JobTitle
        Description           = $JobTitle
        Department            = $Department
        Company               = $Company
        StreetAddress         = $StreetAddress
        City                  = $City
        State                 = $State
        PostalCode            = $ZipCode
        Country               = $Country
        Office                = $Office
        Manager               = $ManagerDN
        AccountPassword       = $SecurePassword
        ChangePasswordAtLogon = $false
        PasswordNeverExpires  = $false
        EmailAddress          = "$Username$UpnSuffix"
        MobilePhone           = $FormattedMobile
        HomePhone             = $FormattedMobile
        OfficePhone           = $FormattedMobile
    }
    
    $OtherAttributes = @{
        otherTelephone = $FormattedOfficeNumber
    }
    
    New-ADUser @NewUserDetails -Path $TargetOU -OtherAttributes $OtherAttributes -ErrorAction Stop
    Write-Log "AD User '$Username' created successfully"
    Write-Log "User DN: $(Get-ADUser -Identity $Username | Select-Object -ExpandProperty DistinguishedName)"
    
    Start-Sleep -Seconds 5
    Write-Log "Waited 5 seconds for AD replication"
    
    # Group assignment logic
    Write-Log "=== Step 6: Mandatory Group Assignment ==="
    
    # Base mandatory groups (always applied)
    $MandatoryGroups = @(
        "Intune Enrolled Users",
        "DuoSecurity",
        "Phin Onboarding",
        "Wireless Users"
    )
    
    # Employment type groups
    switch ($EmploymentType) {
        'Regular' { 
            $MandatoryGroups += "Full-Time Employee"
            Write-Log "Adding Full-Time Employee group (Regular employment)"
        }
        'Temp' { 
            $MandatoryGroups += "Temp Employees"
            Write-Log "Adding Temp Employee group (Temporary employment)"
        }
    }
    
    # Location-specific groups
    if ($OULocation -eq "Headquarters") {
        $MandatoryGroups += "HQ-Printers"
        Write-Log "Adding HQ-Printers group (Headquarters location)"
    }
    
    # Role-specific groups
    switch ($UserRole) {
        'MaintenanceTechnician' {
            $MandatoryGroups += @("All Maintenance", "All MaintenanceENG", "Property", "PropertyENG")
            Write-Log "Adding Maintenance Technician groups"
        }
        'MaintenanceSupervisor' {
            $MandatoryGroups += @("All Maintenance", "All MaintenanceENG", "Property", "PropertyENG", 
                "Facilities Supervisors", "Facilities Leadership Team", "FacilitiesLeadershipTeamENG")
            Write-Log "Adding Maintenance Supervisor groups"
        }
        'Standard' {
            Write-Log "Standard user role - no additional role-specific groups"
        }
    }
    
    # Add mandatory groups
    $AddedGroupsCount = 0
    $FailedGroupsCount = 0
    
    foreach ($GroupName in $MandatoryGroups) {
        $Group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
        if ($Group) {
            try {
                Add-ADGroupMember -Identity $Group -Members $Username -ErrorAction Stop
                Write-Log "Added to mandatory group: $GroupName"
                $AddedGroupsCount++
            } catch {
                Write-Log "WARNING: Could not add to mandatory group '$GroupName': $($_.Exception.Message)"
                $FailedGroupsCount++
            }
        } else {
            Write-Log "WARNING: Mandatory group '$GroupName' not found in AD"
            $FailedGroupsCount++
        }
    }
    
    Write-Log "Mandatory groups summary: $AddedGroupsCount added, $FailedGroupsCount failed"
    
    # Mirror groups from specified user
    Write-Log "=== Step 7: Mirror Group Memberships ==="
    if ($MirrorUserObj.MemberOf) {
        Write-Log "Copying $($MirrorUserObj.MemberOf.Count) group memberships from $MirrorUser"
        $MirroredGroupsCount = 0
        $SkippedGroupsCount = 0
        $FailedMirrorCount = 0
        
        foreach ($GroupDN in $MirrorUserObj.MemberOf) {
            try {
                $Group = Get-ADGroup -Identity $GroupDN -ErrorAction Stop
                
                # Skip if user is already a member (from mandatory groups)
                $CurrentMembership = Get-ADUser -Identity $Username -Properties MemberOf
                if ($CurrentMembership.MemberOf -contains $GroupDN) {
                    Write-Log "Skipping group (already member): $($Group.Name)"
                    $SkippedGroupsCount++
                    continue
                }
                
                Add-ADGroupMember -Identity $GroupDN -Members $Username -ErrorAction Stop
                Write-Log "Mirrored group: $($Group.Name)"
                $MirroredGroupsCount++
            } catch {
                Write-Log "WARNING: Could not mirror group $($Group.Name): $($_.Exception.Message)"
                $FailedMirrorCount++
            }
        }
        
        Write-Log "Group mirroring summary: $MirroredGroupsCount mirrored, $SkippedGroupsCount skipped, $FailedMirrorCount failed"
    } else {
        Write-Log "Mirror user has no group memberships to copy"
    }
    
    # Trigger Azure AD Connect Synchronization
    Write-Log "=== Step 8: Azure AD Connect Synchronization ==="
    try {
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
        Write-Log "Azure AD Connect synchronization triggered (Delta sync)"
    } catch {
        Write-Log "WARNING: Failed to trigger Azure AD Connect synchronization: $($_.Exception.Message)"
        Write-Log "You may need to manually run: Start-ADSyncSyncCycle -PolicyType Delta"
    }
    
    # Verification and summary
    Write-Log "=== Step 9: Final Verification and Summary ==="
    $NewUser = Get-ADUser -Identity $Username -Properties MemberOf, Manager, DisplayName, Enabled, Department, Title, EmailAddress, MobilePhone, Office
    
    Write-Log "User: $($NewUser.DisplayName) ($($NewUser.SamAccountName))"
    Write-Log "Account Status: Enabled = $($NewUser.Enabled)"
    Write-Log "Email Address: $($NewUser.EmailAddress)"
    Write-Log "Department: $($NewUser.Department)"
    Write-Log "Job Title: $($NewUser.Title)"
    Write-Log "Mobile Phone: $($NewUser.MobilePhone)"
    Write-Log "Office: $($NewUser.Office)"
    if ($NewUser.Manager) { 
        $ManagerName = (Get-ADUser -Identity $NewUser.Manager).DisplayName
        Write-Log "Manager: $ManagerName"
    }
    Write-Log "Current OU: $($NewUser.DistinguishedName.Split(',')[1..99] -join ',')"
    
    # Show current group memberships
    Write-Log "Current Group Memberships: $($NewUser.MemberOf.Count) groups"
    if ($NewUser.MemberOf.Count -gt 0) {
        foreach ($GroupDN in $NewUser.MemberOf) {
            try {
                $GroupName = (Get-ADGroup -Identity $GroupDN).Name
                Write-Log "  -> Member of: $GroupName"
            } catch {
                Write-Log "  -> Member of: $GroupDN (name lookup failed)"
            }
        }
    }
    
    # Summary of actions completed
    Write-Log "=== ACTIONS COMPLETED ==="
    Write-Log "User account created: $($NewUser.DisplayName)"
    Write-Log "Placed in OU: $OULocation"
    Write-Log "Mandatory groups added: $AddedGroupsCount"
    if ($MirroredGroupsCount -gt 0) { Write-Log "Groups mirrored from ${MirrorUser}: $MirroredGroupsCount" }
    Write-Log "Manager assigned: $Manager"
    Write-Log "Azure AD Connect sync triggered"
    
    if ($FailedGroupsCount -gt 0 -or $FailedMirrorCount -gt 0) {
        Write-Log "WARNINGS: $($FailedGroupsCount + $FailedMirrorCount) group assignment failures - review log for details"
    }
    
    Write-Log "=== AD Onboarding completed successfully for $Username ==="
} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)"
    throw
}
