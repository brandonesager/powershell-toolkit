<#
.SYNOPSIS
    Microsoft 365 User Onboarding with Auto-Discovery

.DESCRIPTION
    Automates Microsoft 365 onboarding tasks for new employees including license assignment,
    shared mailbox permissions, and usage location configuration. Features automatic shared mailbox
    discovery based on user's office location and role.

    Key Features:
    - Auto-discovers shared mailboxes based on Office Location attribute
    - Role-based shared mailbox assignment (Property Managers, Maintenance, etc.)
    - License availability validation before assignment
    - Comprehensive logging for audit trails
    - Idempotent operations (safe to re-run)

.PARAMETER UserUPN
    User Principal Name (e.g., "jsmith@contoso.com") - REQUIRED

.PARAMETER DisplayName
    Specifies the display name.

.PARAMETER Department
    Department name - used for shared mailbox role detection

.PARAMETER JobTitle
    Job title - determines shared mailbox access requirements

.PARAMETER LicenseType
    'BusinessPremium' (default) or 'BusinessBasic' for contractors

.PARAMETER SkipSharedMailboxes
    Skip all shared mailbox assignments

.PARAMETER SharedMailboxNames
    Manual shared mailbox specification (overrides auto-discovery)

.PARAMETER SkipLicenseCheck
    Skip license availability validation

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Initialize-Microsoft365UserOnboarding.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Initialize-Microsoft365UserOnboarding.ps1' -UserUPN 'Value' -DisplayName 'Value' -Department 'Value'

.NOTES
    Author: Brandon Sager
    Version: 1.0

    Requirements:
    - PowerShell 7.0+ (for Microsoft Graph compatibility)
    - ExchangeOnlineManagement module
    - Microsoft.Graph.Authentication module
    - Microsoft.Graph.Users module
    - Exchange Administrator permissions
    - User Administrator permissions

    Logging: Creates detailed logs at C:\Temp\OnboardO365_timestamp.log

    The script automatically connects to Exchange Online and Microsoft Graph,
    and discovers shared mailboxes based on user's Office Location attribute (from AD sync).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter user UPN (e.g., jsmith@contoso.com)")]
    [string]$UserUPN,
    
    # === TEMPLATE VALUES - CUSTOMIZE FOR EACH USER ===
    
    [Parameter(HelpMessage = "Display name override (leave blank to use AD display name)")]
    [string]$DisplayName = "",                                     # Usually blank - uses AD sync value
    
    [Parameter(HelpMessage = "Department (e.g., Property Management, IT, Facilities)")]
    [string]$Department = "DEPARTMENT_PLACEHOLDER",                # CHANGE THIS: User's department
    
    [Parameter(HelpMessage = "Job title (e.g., Assistant Property Manager, Maintenance Technician)")]
    [string]$JobTitle = "JOB_TITLE_PLACEHOLDER",                   # CHANGE THIS: User's job title (determines shared mailbox access)
    
    [Parameter()]
    [ValidateSet('BusinessPremium', 'BusinessBasic')]
    [string]$LicenseType = 'BusinessPremium',
    
    [Parameter(HelpMessage = "Skip shared mailbox assignments")]
    [switch]$SkipSharedMailboxes,
    
    [Parameter(HelpMessage = "Shared mailbox names to assign permissions (e.g., 'Building-A','Property-Management')")]
    [string[]]$SharedMailboxNames = @(),
    
    # === SCRIPT OPTIONS (Usually don't change) ===
    
    [Parameter(HelpMessage = "Skip license availability checking")]
    [switch]$SkipLicenseCheck                                      # Advanced: Skip license validation
)

#==============================================================================
# INITIALIZATION AND LOGGING SETUP
#==============================================================================

# Create temp directory for logging and audit trail
if (!(Test-Path -LiteralPath 'C:\Temp')) { 
    New-Item -ItemType Directory -Path 'C:\Temp' | Out-Null 
}

# Configure comprehensive logging for audit and troubleshooting
$Log = ('C:\Temp\{0}_{1}.log' -f 'OnboardO365', (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Logging function - writes to both console and file for complete visibility
function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $ts = (Get-Date).ToString('s')
    "$ts`t$Message" | Tee-Object -FilePath $Log -Append
}

#==============================================================================
# MAIN OFFICE 365 ONBOARDING PROCESS
#==============================================================================

Write-Log "=== Starting Office 365 Onboarding for User: $UserUPN ==="
Write-Log "Parameters: Department=$Department, JobTitle=$JobTitle, LicenseType=$LicenseType"
Write-Log "Options: SkipLicenseCheck=$SkipLicenseCheck, SkipSharedMailboxes=$SkipSharedMailboxes"

try {
    #--------------------------------------------------------------------------
    # STEP 1: POWERSHELL MODULE INITIALIZATION
    # Required for Microsoft 365 operations - Exchange Online and Graph API
    #--------------------------------------------------------------------------
    
    Write-Log "=== Step 1: Import Required Modules ==="
    Write-Log "Importing ExchangeOnlineManagement module..."
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Log "ExchangeOnlineManagement module imported successfully"
    
    Write-Log "Importing Microsoft.Graph modules..."
    Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -ErrorAction Stop
    Write-Log "Microsoft.Graph modules imported successfully"
    
    #--------------------------------------------------------------------------
    # STEP 2: CLOUD SERVICES AUTHENTICATION
    # Auto-connects to Exchange Online and Microsoft Graph with proper scopes
    # Handles existing connections gracefully to avoid duplicate auth prompts
    #--------------------------------------------------------------------------
    
    Write-Log "=== Step 2: Connect to Cloud Services ==="
    
    # Connect to Exchange Online
    Write-Log "Connecting to Exchange Online..."
    try {
        $ExoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($ExoConnection -and $ExoConnection.State -eq "Connected") {
            Write-Log "-> Already connected to Exchange Online: $($ExoConnection.UserPrincipalName)"
        } else {
            Write-Log "Establishing connection to Exchange Online..."
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            $ExoConnection = Get-ConnectionInformation
            Write-Log "Connected to Exchange Online successfully: $($ExoConnection.UserPrincipalName)"
        }
    } catch {
        Write-Log "ERROR: Failed to connect to Exchange Online: $($_.Exception.Message)"
        throw "Exchange Online connection failed"
    }
    
    # Connect to Microsoft Graph
    Write-Log "Connecting to Microsoft Graph..."
    try {
        $MgContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($MgContext -and $MgContext.Account) {
            $RequiredScopes = @("User.ReadWrite.All", "Directory.ReadWrite.All")
            $MissingScopes = $RequiredScopes | Where-Object { $MgContext.Scopes -notcontains $_ }
            
            if ($MissingScopes.Count -eq 0) {
                Write-Log "-> Already connected to Microsoft Graph: $($MgContext.Account) with required scopes"
            } else {
                Write-Log "Connected to Graph but missing scopes. Reconnecting with required scopes..."
                Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All" -ErrorAction Stop
                $MgContext = Get-MgContext
                Write-Log "Connected to Microsoft Graph successfully: $($MgContext.Account) with required scopes"
            }
        } else {
            Write-Log "Establishing connection to Microsoft Graph..."
            Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All" -ErrorAction Stop
            $MgContext = Get-MgContext
            Write-Log "Connected to Microsoft Graph successfully: $($MgContext.Account)"
        }
    } catch {
        Write-Log "ERROR: Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        throw "Microsoft Graph connection failed"
    }
    
    # Verify user exists and get details
    Write-Log "=== Step 3: User Verification ==="
    Write-Log "Verifying user exists: $UserUPN"
    try {
        $MgUser = Get-MgUser -UserId $UserUPN -Property DisplayName, Department, JobTitle, AssignedLicenses, UsageLocation, OfficeLocation -ErrorAction Stop
        Write-Log "User found: $($MgUser.DisplayName)"
        
        if ([string]::IsNullOrWhiteSpace($DisplayName)) {
            $DisplayName = $MgUser.DisplayName
        }
        
        Write-Log "User Details:"
        Write-Log "  Display Name: $($MgUser.DisplayName)"
        Write-Log "  Department: $($MgUser.Department)"
        Write-Log "  Job Title: $($MgUser.JobTitle)"
        Write-Log "  Office Location: $($MgUser.OfficeLocation)"
        Write-Log "  Usage Location: $($MgUser.UsageLocation)"
        Write-Log "  Current Licenses: $($MgUser.AssignedLicenses.Count) SKUs assigned"
        
        if ($MgUser.AssignedLicenses.Count -gt 0) {
            Write-Log "WARNING: User already has $($MgUser.AssignedLicenses.Count) licenses assigned"
            foreach ($License in $MgUser.AssignedLicenses) {
                Write-Log "  -> Existing License SKU: $($License.SkuId)"
            }
        }
    } catch {
        Write-Log "FATAL ERROR: User not found or error retrieving user: $($_.Exception.Message)"
        throw "User verification failed"
    }
    
    # Set Usage Location if missing
    Write-Log "=== Step 4: Usage Location Configuration ==="
    if ([string]::IsNullOrWhiteSpace($MgUser.UsageLocation)) {
        Write-Log "Usage Location is not set - setting to 'US' for license assignment"
        try {
            Update-MgUser -UserId $UserUPN -UsageLocation "US" -ErrorAction Stop
            Write-Log "Usage Location set to 'US' successfully"
            # Refresh user object with updated UsageLocation
            $MgUser = Get-MgUser -UserId $UserUPN -Property DisplayName, Department, JobTitle, AssignedLicenses, UsageLocation, OfficeLocation -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to set Usage Location: $($_.Exception.Message)"
            throw "Usage Location configuration failed"
        }
    } else {
        Write-Log "Usage Location already set: $($MgUser.UsageLocation)"
    }
    
    # Auto-discover shared mailboxes based on office location and role
    Write-Log "=== Step 5: Auto-Discover Shared Mailboxes ==="
    $AutoDiscoveredMailboxes = @()
    
    # Check if user role requires shared mailbox access
    $SharedMailboxRoles = @(
        'Property Manager', 'Assistant Property Manager', 'Property Supervisor',
        'Maintenance Technician', 'Maintenance Supervisor', 'MT Staff',
        'Facilities', 'Maintenance'
    )
    
    $RequiresSharedMailboxes = $SharedMailboxRoles | Where-Object { 
        $JobTitle -like "*$_*" -or $Department -like "*$_*" 
    }
    
    if ($RequiresSharedMailboxes -and -not [string]::IsNullOrWhiteSpace($MgUser.OfficeLocation)) {
        Write-Log "User role '$JobTitle' requires shared mailbox access"
        Write-Log "Office Location: '$($MgUser.OfficeLocation)'"
        Write-Log "Searching for shared mailboxes matching office location..."
        
        try {
            # Get all shared mailboxes
            $AllSharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
            Write-Log "Found $($AllSharedMailboxes.Count) total shared mailboxes in tenant"
            
            # Create search patterns from office location
            $OfficeLocation = $MgUser.OfficeLocation
            $SearchPatterns = @()
            
            # Remove common property suffixes and create variations
            $CleanLocation = $OfficeLocation -replace '\s+(Manor|Apartments?|Village|Court|Place|Way|Drive|Street|Ave|Avenue|Blvd|Boulevard)(\s|$)', ''
            $CleanLocation = $CleanLocation.Trim()
            
            # Create search patterns
            $SearchPatterns += $OfficeLocation                    # Original: "Oak Plaza"
            $SearchPatterns += $CleanLocation                     # Cleaned: "Oak"
            $SearchPatterns += ($OfficeLocation -replace '\s', '-')     # Hyphenated: "Oak-Plaza"
            $SearchPatterns += ($OfficeLocation -replace '\s', '')      # No spaces: "OakPlaza"
            $SearchPatterns += ($CleanLocation -replace '\s', '-')      # Clean+Hyphen: "Oak"
            $SearchPatterns += ($CleanLocation -replace '\s', '')       # Clean+NoSpace: "Oak"
            
            # Remove duplicates and empty patterns
            $SearchPatterns = $SearchPatterns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            
            Write-Log "Search patterns: $($SearchPatterns -join ', ')"
            
            # Search for matching shared mailboxes
            foreach ($Pattern in $SearchPatterns) {
                $MatchingMailboxes = $AllSharedMailboxes | Where-Object { 
                    $_.DisplayName -like "*$Pattern*" -or 
                    $_.Alias -like "*$Pattern*" -or
                    $_.PrimarySmtpAddress -like "*$Pattern*"
                }
                
                foreach ($Mailbox in $MatchingMailboxes) {
                    if ($AutoDiscoveredMailboxes -notcontains $Mailbox.PrimarySmtpAddress) {
                        $AutoDiscoveredMailboxes += $Mailbox.PrimarySmtpAddress
                        Write-Log "-> Found matching shared mailbox: $($Mailbox.DisplayName) ($($Mailbox.PrimarySmtpAddress))"
                    }
                }
            }
            
            if ($AutoDiscoveredMailboxes.Count -gt 0) {
                Write-Log "Auto-discovered $($AutoDiscoveredMailboxes.Count) shared mailboxes for user"
                # Override the SharedMailboxNames parameter with auto-discovered ones
                if ($SharedMailboxNames.Count -eq 0) {
                    $SharedMailboxNames = $AutoDiscoveredMailboxes
                    Write-Log "Using auto-discovered shared mailboxes: $($SharedMailboxNames -join ', ')"
                } else {
                    Write-Log "User provided SharedMailboxNames parameter - using those instead of auto-discovered"
                }
            } else {
                Write-Log "No shared mailboxes found matching office location patterns"
            }
            
        } catch {
            Write-Log "WARNING: Failed to auto-discover shared mailboxes: $($_.Exception.Message)"
            Write-Log "Proceeding with manual SharedMailboxNames if provided"
        }
    } elseif (-not $RequiresSharedMailboxes) {
        Write-Log "User role '$JobTitle' does not require shared mailbox access - skipping auto-discovery"
    } elseif ([string]::IsNullOrWhiteSpace($MgUser.OfficeLocation)) {
        Write-Log "Office Location not set - cannot auto-discover shared mailboxes"
        Write-Log "Use -SharedMailboxNames parameter to manually specify shared mailboxes"
    }
    
    # Check license availability  
    Write-Log "=== Step 6: License Availability Check ==="
    Write-Host ""  # Ensure clean console output
    if (-not $SkipLicenseCheck) {
        Write-Log "Checking license availability for type: $LicenseType"
        
        try {
            $TenantSkus = Get-MgSubscribedSku -ErrorAction Stop
            Write-Log "Found $($TenantSkus.Count) available SKU types in tenant"
            
            # Map license types to SKU part numbers
            $LicenseSkuMapping = @{
                'BusinessPremium' = @('SPB', 'O365_BUSINESS_PREMIUM')
                'BusinessBasic' = @('SPE_F1', 'O365_BUSINESS_ESSENTIALS', 'SPB_GOV', 'DESKLESSPACK')
            }
            
            $TargetSkus = $TenantSkus | Where-Object { 
                $_.SkuPartNumber -in $LicenseSkuMapping[$LicenseType] 
            }
            
            if ($TargetSkus.Count -eq 0) {
                Write-Log "FATAL ERROR: No matching SKUs found for license type '$LicenseType'"
                Write-Log "Available SKUs in tenant:"
                foreach ($Sku in $TenantSkus) {
                    Write-Log "  -> $($Sku.SkuPartNumber) | $($Sku.SkuId)"
                }
                throw "License type not available in tenant"
            }
            
            # Check availability of target licenses
            $AvailableLicenses = $false
            foreach ($Sku in $TargetSkus) {
                $Available = $Sku.PrepaidUnits.Enabled - $Sku.ConsumedUnits
                Write-Log "License check: $($Sku.SkuPartNumber) - $Available available (Enabled: $($Sku.PrepaidUnits.Enabled), Consumed: $($Sku.ConsumedUnits))"
                
                if ($Available -gt 0) {
                    $SelectedSku = $Sku
                    $AvailableLicenses = $true
                    Write-Log "Selected SKU: $($Sku.SkuPartNumber) | $($Sku.SkuId)"
                    break
                }
            }
            
            if (-not $AvailableLicenses) {
                Write-Log "FATAL ERROR: No available licenses for type '$LicenseType'"
                Write-Log "All matching SKUs are fully consumed. Please purchase additional licenses."
                throw "Insufficient licenses available"
            }
        } catch {
            Write-Log "ERROR: License availability check failed: $($_.Exception.Message)"
            throw "License availability check failed"
        }
    } else {
        Write-Log "License availability check skipped by parameter - proceeding with assignment attempt"
    }
    
    # Assign license
    Write-Log "=== Step 7: License Assignment ==="
    Write-Host ""  # Ensure clean console output
    if ($MgUser.AssignedLicenses.Count -eq 0) {
        Write-Log "Assigning $LicenseType license to user..."
        try {
            $LicenseToAdd = @{
                SkuId = $SelectedSku.SkuId
            }
            
            Set-MgUserLicense -UserId $UserUPN -AddLicenses @($LicenseToAdd) -RemoveLicenses @() -ErrorAction Stop
            Write-Log "License assigned successfully: $($SelectedSku.SkuPartNumber)"
            
            # Wait for license propagation
            Write-Log "Waiting 10 seconds for license propagation..."
            Start-Sleep -Seconds 10
        } catch {
            Write-Log "ERROR: License assignment failed: $($_.Exception.Message)"
            throw "License assignment failed"
        }
    } else {
        Write-Log "-> User already has licenses assigned - skipping license assignment"
    }
    
    # Shared mailbox assignments
    Write-Log "=== Step 8: Shared Mailbox Assignments ==="
    if (-not $SkipSharedMailboxes) {
        # Determine if user should get shared mailbox access based on job title
        $SharedMailboxRoles = @(
            'Property Manager', 'Assistant Property Manager', 'Property Supervisor',
            'Maintenance Technician', 'Maintenance Supervisor', 'MT Staff',
            'Facilities', 'Maintenance'
        )
        
        $RequiresSharedMailboxes = $SharedMailboxRoles | Where-Object { 
            $JobTitle -like "*$_*" -or $Department -like "*$_*" 
        }
        
        if ($RequiresSharedMailboxes -or $SharedMailboxNames.Count -gt 0) {
            Write-Log "User role indicates shared mailbox access required"
            Write-Log "Job Title: $JobTitle | Department: $Department"
            
            if ($SharedMailboxNames.Count -gt 0) {
                Write-Log "Processing specified shared mailboxes: $($SharedMailboxNames -join ', ')"
                $ProcessedMailboxes = 0
                $SuccessfulAssignments = 0
                $FailedAssignments = 0
                
                foreach ($MailboxName in $SharedMailboxNames) {
                    $ProcessedMailboxes++
                    Write-Log "Processing shared mailbox: $MailboxName"
                    
                    try {
                        # Find the shared mailbox
                        $SharedMailbox = Get-EXOMailbox -Identity $MailboxName -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                        Write-Log "-> Found shared mailbox: $($SharedMailbox.DisplayName) ($($SharedMailbox.PrimarySmtpAddress))"
                        
                        # Add FullAccess permission
                        try {
                            Add-MailboxPermission -Identity $SharedMailbox.PrimarySmtpAddress -User $UserUPN -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop
                            Write-Log "Added FullAccess permission for: $($SharedMailbox.DisplayName)"
                        } catch {
                            if ($_.Exception.Message -like "*already exists*") {
                                Write-Log "-> FullAccess permission already exists for: $($SharedMailbox.DisplayName)"
                            } else {
                                Write-Log "WARNING: Failed to add FullAccess permission: $($_.Exception.Message)"
                            }
                        }
                        
                        # Add SendAs permission
                        try {
                            Add-RecipientPermission -Identity $SharedMailbox.PrimarySmtpAddress -Trustee $UserUPN -AccessRights SendAs -Confirm:$false -ErrorAction Stop
                            Write-Log "Added SendAs permission for: $($SharedMailbox.DisplayName)"
                        } catch {
                            if ($_.Exception.Message -like "*already exists*") {
                                Write-Log "-> SendAs permission already exists for: $($SharedMailbox.DisplayName)"
                            } else {
                                Write-Log "WARNING: Failed to add SendAs permission: $($_.Exception.Message)"
                            }
                        }
                        
                        $SuccessfulAssignments++
                        Write-Log "Shared mailbox assignment completed: $($SharedMailbox.DisplayName)"
                        
                    } catch {
                        Write-Log "ERROR: Failed to process shared mailbox '$MailboxName': $($_.Exception.Message)"
                        $FailedAssignments++
                    }
                }
                
                Write-Log "Shared mailbox assignment summary: $ProcessedMailboxes processed, $SuccessfulAssignments successful, $FailedAssignments failed"
            } else {
                Write-Log "WARNING: User appears to require shared mailbox access, but no mailboxes specified"
                Write-Log "-> Use -SharedMailboxNames parameter to specify which shared mailboxes to assign"
                Write-Log "-> Or manually assign shared mailbox permissions after script completion"
            }
        } else {
            Write-Log "-> User role does not require shared mailbox access - skipping"
        }
    } else {
        Write-Log "-> Shared mailbox assignment skipped by parameter"
    }
    
    # Verification and summary
    Write-Log "=== Step 9: Final Verification and Summary ==="
    
    # Verify license assignment
    Write-Log "Verifying license assignment..."
    try {
        $UpdatedUser = Get-MgUser -UserId $UserUPN -Property AssignedLicenses -ErrorAction Stop
        Write-Log "Current License Count: $($UpdatedUser.AssignedLicenses.Count) SKUs"
        
        if ($UpdatedUser.AssignedLicenses.Count -gt 0) {
            # Get detailed license information
            $TenantSkus = Get-MgSubscribedSku
            foreach ($License in $UpdatedUser.AssignedLicenses) {
                $SkuInfo = $TenantSkus | Where-Object { $_.SkuId -eq $License.SkuId }
                if ($SkuInfo) {
                    Write-Log "  -> Assigned: $($SkuInfo.SkuPartNumber) | $($License.SkuId)"
                } else {
                    Write-Log "  -> Assigned: Unknown SKU | $($License.SkuId)"
                }
            }
        } else {
            Write-Log "WARNING: No licenses found - license assignment may have failed"
        }
    } catch {
        Write-Log "WARNING: Could not verify license assignment: $($_.Exception.Message)"
    }
    
    # Verify shared mailbox permissions if any were assigned
    if (-not $SkipSharedMailboxes -and $SharedMailboxNames.Count -gt 0) {
        Write-Log "Verifying shared mailbox permissions..."
        foreach ($MailboxName in $SharedMailboxNames) {
            try {
                $SharedMailbox = Get-EXOMailbox -Identity $MailboxName -RecipientTypeDetails SharedMailbox -ErrorAction SilentlyContinue
                if ($SharedMailbox) {
                    # Check FullAccess
                    $FullAccessPerms = Get-MailboxPermission -Identity $SharedMailbox.PrimarySmtpAddress | Where-Object { $_.User -like "*$UserUPN*" }
                    if ($FullAccessPerms) {
                        Write-Log "FullAccess confirmed: $($SharedMailbox.DisplayName)"
                    }
                    
                    # Check SendAs
                    $SendAsPerms = Get-RecipientPermission -Identity $SharedMailbox.PrimarySmtpAddress | Where-Object { $_.Trustee -like "*$UserUPN*" }
                    if ($SendAsPerms) {
                        Write-Log "SendAs confirmed: $($SharedMailbox.DisplayName)"
                    }
                }
            } catch {
                Write-Log "WARNING: Could not verify permissions for ${MailboxName}: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Log "=== Office 365 onboarding completed successfully for $UserUPN ==="
    
    # Summary of actions
    Write-Log "=== SUMMARY OF ACTIONS ==="
    Write-Log "User verified in Microsoft 365"
    if (-not $SkipLicenseCheck) { Write-Log "License availability confirmed" }
    if ($MgUser.AssignedLicenses.Count -eq 0) { Write-Log "$LicenseType license assigned" }
    if ($SuccessfulAssignments -gt 0) { Write-Log "Shared mailbox permissions assigned: $SuccessfulAssignments mailboxes" }
    
    Write-Host ""
    Write-Host "=== Next Steps ===" -ForegroundColor Green
    Write-Host "1. Verify user can access Microsoft 365 services" -ForegroundColor White
    Write-Host "2. Confirm mailbox creation and email flow" -ForegroundColor White
    if ($SharedMailboxNames.Count -gt 0) {
        Write-Host "3. Test shared mailbox access in Outlook" -ForegroundColor White
        Write-Host "4. Complete any remaining manual tasks (Adobe licensing, etc.)" -ForegroundColor White
    } else {
        Write-Host "3. Complete any remaining manual tasks (Adobe licensing, etc.)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Note: Services remain connected for additional operations. Disconnect manually when complete." -ForegroundColor Yellow
    
} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)"
    throw
}
