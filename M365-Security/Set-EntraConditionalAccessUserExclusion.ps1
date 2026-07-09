#Requires -Version 5.1

<#
.SYNOPSIS
    Set-EntraConditionalAccessUserExclusion — Excludes a user from CA MFA policies

.DESCRIPTION
    Connects to Microsoft Graph, identifies Conditional Access policies requiring MFA,
    checks current exclusions, determines which policies apply to the target user,
    and generates WhatIf commands to add the user to the exclusion list. Outputs
    copy-paste-ready commands for the actual update after review.
.PARAMETER TargetUserPrincipalName
    The User Principal Name (email address) of the user to be excluded.

.PARAMETER AdminUserPrincipalName
    The User Principal Name (email address) of the administrator account used to connect.

.EXAMPLE
    .\Set-EntraConditionalAccessUserExclusion.ps1 -TargetUserPrincipalName "user1@contoso.example.com" -AdminUserPrincipalName "admin@contoso.example.com"

.NOTES
    Category: Environment-Specific
    Date: 2025-04-09
    Requires Global Administrator, Conditional Access Administrator, or Security Administrator role.
    Requires the Microsoft.Graph.Identity.SignIns module.

.KEYWORDS
    Entra, MFA, conditional-access, exclusion, Contoso
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetUserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$AdminUserPrincipalName
)

Write-Host "Step 1: Checking and Installing necessary Microsoft Graph module..." -ForegroundColor Yellow

$requiredModule = "Microsoft.Graph.Identity.SignIns"
$installedModule = Get-InstalledModule -Name $requiredModule -ErrorAction SilentlyContinue
if (-not $installedModule) {
    Write-Host "Module '$requiredModule' not found. Attempting installation..."
    try {
        Install-Module $requiredModule -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        Write-Host "Module '$requiredModule' installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install module '$requiredModule': $_"
        exit 1
    }
} else {
    Write-Host "Module '$requiredModule' is already installed."
}

Import-Module $requiredModule
Import-Module Microsoft.Graph.Authentication # Ensure auth module is loaded

Write-Host "Step 2: Connecting to Microsoft Graph..." -ForegroundColor Yellow
Write-Host "Please authenticate as '$AdminUserPrincipalName' in the browser window."

Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "User.Read.All", "Group.Read.All", "Directory.Read.All" -ErrorAction Stop
$context = Get-MgContext
Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
Write-Host " TenantId: $($context.TenantId)"
Write-Host " Account: $($context.Account)"

if ($context.Account -ne $AdminUserPrincipalName) {
     Write-Warning "Connected as '$($context.Account)', which differs from the specified AdminUserPrincipalName '$AdminUserPrincipalName'. Please ensure you logged in with the correct account."
}

Write-Host "`nStep 3: Getting Object ID for target user '$TargetUserPrincipalName'..." -ForegroundColor Yellow
$targetUser = Get-MgUser -Filter "userPrincipalName eq '$TargetUserPrincipalName'" -ErrorAction Stop
if ($targetUser) {
    $targetUserId = $targetUser.Id
    Write-Host "Found user '$TargetUserPrincipalName' with Object ID: $targetUserId" -ForegroundColor Green
} else {
    Write-Error "User '$TargetUserPrincipalName' not found."
    return
}

Write-Host "`nStep 4: Retrieving all Conditional Access Policies and checking current exclusions..." -ForegroundColor Yellow

$policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
if (-not $policies) {
    Write-Warning "No Conditional Access policies found in the tenant."
    return
}

Write-Host "Found $($policies.Count) policies. Analyzing inclusions and exclusions:"

$policies | ForEach-Object {
    $policy = $_
    Write-Host "--------------------------------------------------"
    $policyDetails = [PSCustomObject]@{
        PolicyName     = $policy.DisplayName
        PolicyID       = $policy.Id
        State          = $policy.State
        IncludedUsers  = if ($policy.Conditions.Users.IncludeAllUsers) { 'All Users' } else { ($policy.Conditions.Users.IncludeUsers -join ', ') }
        IncludedGroups = $policy.Conditions.Users.IncludeGroups -join ', '
        IncludedRoles  = $policy.Conditions.Users.IncludeRoles -join ', '
        ExcludedUsers  = $policy.Conditions.Users.ExcludeUsers -join ', '
        ExcludedGroups = $policy.Conditions.Users.ExcludeGroups -join ', '
        ExcludedRoles  = $policy.Conditions.Users.ExcludeRoles -join ', '
        GrantControlMFA = $policy.GrantControls.BuiltInControls -contains "mfa"
        GrantControlCustom = if ($policy.GrantControls.CustomAuthenticationFactors) { $true } else { $false }
        GrantOperator  = $policy.GrantControls.Operator
    }
    $policyDetails | Format-List
    Write-Host "--------------------------------------------------"
}

Write-Host "`nStep 5: Identifying policies applying to '$TargetUserPrincipalName' that require MFA and preparing exclusion commands..." -ForegroundColor Yellow

$policiesToModify = @()

foreach ($policy in $policies) {

    if ($policy.State -ne "enabled") { continue }

    $policyRequiresMfa = $false
    if ($policy.GrantControls) {
        if (($policy.GrantControls.BuiltInControls -contains "mfa") -or ($policy.GrantControls.CustomAuthenticationFactors)) {
            $policyRequiresMfa = $true
        }
    }
    if (-not $policyRequiresMfa) { continue } # Skip if it doesn't require MFA

    $userIsPotentiallyIncluded = $false
    if ($policy.Conditions.Users.IncludeAllUsers) { $userIsPotentiallyIncluded = $true }
    if ($policy.Conditions.Users.IncludeUsers -contains $targetUserId) { $userIsPotentiallyIncluded = $true }
    if ($policy.Conditions.Users.IncludeUsers -contains 'All') { $userIsPotentiallyIncluded = $true }

    $directMemberGroups = $null

    if (-not $userIsPotentiallyIncluded -and $policy.Conditions.Users.IncludeGroups) {
        Write-Host "Checking included group memberships for policy '$($policy.DisplayName)'..." -ForegroundColor DarkGray
        $directMemberGroups = Get-MgUserMemberOf -UserId $targetUserId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
            if ($null -ne $directMemberGroups) {
                foreach ($groupId in $policy.Conditions.Users.IncludeGroups) {
                    if ($directMemberGroups -contains $groupId) {
                        $userIsPotentiallyIncluded = $true
                        Write-Host " User '$TargetUserPrincipalName' is potentially included in policy '$($policy.DisplayName)' via group membership (Group ID: $groupId)." -ForegroundColor Gray
                        break # Found inclusion via group
                    }
                }
            }
    }

    if (-not $userIsPotentiallyIncluded) { continue } # Skip if user isn't included

    $userIsAlreadyExcluded = $false
    if ($policy.Conditions.Users.ExcludeUsers -contains $targetUserId) {
        $userIsAlreadyExcluded = $true
        Write-Host "Policy '$($policy.DisplayName)': User '$TargetUserPrincipalName' is ALREADY explicitly excluded." -ForegroundColor Cyan
    }

     if (-not $userIsAlreadyExcluded -and $policy.Conditions.Users.ExcludeGroups) {
        Write-Host "Checking excluded group memberships for policy '$($policy.DisplayName)'..." -ForegroundColor DarkGray
        if ($null -eq $directMemberGroups) {
                 $directMemberGroups = Get-MgUserMemberOf -UserId $targetUserId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
            }
             if ($null -ne $directMemberGroups) {
                 foreach ($groupId in $policy.Conditions.Users.ExcludeGroups) {
                     if ($directMemberGroups -contains $groupId) {
                        $userIsAlreadyExcluded = $true
                        Write-Host " User '$TargetUserPrincipalName' is ALREADY excluded from policy '$($policy.DisplayName)' via group membership (Group ID: $groupId)." -ForegroundColor Cyan
                        break
                    }
                 }
             }
    }

    if ($userIsAlreadyExcluded) {
        continue # Move to the next policy
    }

    Write-Host "Policy '$($policy.DisplayName)' (ID: $($policy.Id)): IDENTIFIED for modification. Requires MFA and applies to user." -ForegroundColor Magenta
    $policiesToModify += $policy
}

if ($policiesToModify.Count -eq 0) {
    Write-Host "`nNo enabled policies found that require MFA and currently apply to '$TargetUserPrincipalName' without excluding them." -ForegroundColor Green
} else {
    Write-Host "`nStep 6: Generating -WhatIf commands to exclude '$TargetUserPrincipalName' (ID: $targetUserId)..." -ForegroundColor Yellow

    foreach ($policy in $policiesToModify) {
        Write-Host "--------------------------------------------------"
        Write-Host "Preparing exclusion for Policy: '$($policy.DisplayName)' (ID: $($policy.Id))"

        $currentUserExclusions = @($policy.Conditions.Users.ExcludeUsers)

        $newUserExclusions = $currentUserExclusions + $targetUserId

        $newConditions = $policy.Conditions.PSObject.Copy() # Create a copy to modify
        $newConditions.Users.ExcludeUsers = $newUserExclusions # Update the exclusion list in the copy

        $updateParams = @{
            ConditionalAccessPolicyId = $policy.Id
            Conditions                = $newConditions # Pass the modified copy

            DisplayName               = $policy.DisplayName
            GrantControls             = $policy.GrantControls
            SessionControls           = $policy.SessionControls
            State                     = $policy.State
        }

        Write-Host "Executing WhatIf for policy '$($policy.DisplayName)'..." -ForegroundColor Cyan
        Update-MgIdentityConditionalAccessPolicy @updateParams -WhatIf -ErrorAction Stop

        Write-Host "To apply this change, you can try running the following command:" -ForegroundColor Yellow
        Write-Host @"

    `$targetUserIdForUpdate = '$targetUserId'

    Write-Host "Getting policy '$($policy.DisplayName)' ($($policy.Id)) before update..."
    `$policyToUpdate = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId '$($policy.Id)' -ErrorAction Stop
    if (`$policyToUpdate) {
        Write-Host "Current ExcludeUsers: @(`$policyToUpdate.Conditions.Users.ExcludeUsers)"
        `$currentExclusions = @(`$policyToUpdate.Conditions.Users.ExcludeUsers)

        if (`$currentExclusions -notcontains `$targetUserIdForUpdate) {
            `$updatedExclusions = `$currentExclusions + `$targetUserIdForUpdate
            Write-Host "New ExcludeUsers: @(`$updatedExclusions)"

            `$updatedConditions = `$policyToUpdate.Conditions.PSObject.Copy()
            `$updatedConditions.Users.ExcludeUsers = `$updatedExclusions

            `$updateParamsReal = @{
                ConditionalAccessPolicyId = `$policyToUpdate.Id
                Conditions                = `$updatedConditions
                DisplayName               = `$policyToUpdate.DisplayName
                GrantControls             = `$policyToUpdate.GrantControls
                SessionControls           = `$policyToUpdate.SessionControls
                State                     = `$policyToUpdate.State
            }

            Write-Host "Review the following parameters before execution:"
            `$updateParamsReal | Out-String | Write-Host

            Write-Host "Command to run: Update-MgIdentityConditionalAccessPolicy @updateParamsReal"
        } else {
            Write-Warning "User ID '`$targetUserIdForUpdate' already found in ExcludeUsers for policy '$($policy.DisplayName)'. No update needed for this policy."
        }
    } else {
        Write-Error "Failed to retrieve policy '$($policy.DisplayName)' before attempting update."
    }

"@
        Write-Warning "IMPORTANT: Review the parameters (`$updateParamsReal) carefully before uncommenting and running the Update-MgIdentityConditionalAccessPolicy command. Ensure all necessary conditions and controls are correctly included."
        Write-Host "--------------------------------------------------"

    }
}

Write-Host "`nScript finished. Review the output and -WhatIf previews above carefully." -ForegroundColor Green
Write-Host "Remember to run the actual Update-MgIdentityConditionalAccessPolicy commands without -WhatIf if the preview is correct."
Write-Host "Consider using an Azure AD Group for exclusions as a best practice."
