<#
.SYNOPSIS
    Conditional Access Policy Analysis and User Exclusion Tool

.DESCRIPTION
    Analyzes Entra ID Conditional Access policies to identify which require MFA for a target user,
    then generates commands to add exclusions using the minimal update approach.

    Features:
    - Lists all CA policies with MFA requirements
    - Identifies policies affecting the target user
    - Generates safe -WhatIf commands for review
    - Produces ready-to-execute exclusion commands
    - Recommends group-based exclusion best practices

.NOTES
    Author: Brandon Sager
    Version: 1.0

    Requirements:
    - PowerShell 7.0+
    - Microsoft.Graph.Identity.SignIns module
    - Conditional Access Administrator or Global Administrator role
#>

#Requires -Version 5.1



[CmdletBinding(SupportsShouldProcess)]
param()

# Execution Policy Setup
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}
}

$TranscriptPath = "C:\Temp"
if (-not (Test-Path $TranscriptPath)) { New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null }
$ScriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$TranscriptFile = Join-Path $TranscriptPath "PS-Transcript_$($env:COMPUTERNAME)_$ScriptBaseName`_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($PID).log"
Start-Transcript -Path $TranscriptFile -Force

try {
    Write-Host "Starting $ScriptBaseName (Other)..." -ForegroundColor Green
    Write-Verbose "Transcript logging to: $TranscriptFile"

    # CORE SCRIPT LOGIC - REFACTORED FROM ORIGINAL
    <#
    .SYNOPSIS
    Analyzes and prepares commands to exclude a specific user from Microsoft 365 Conditional Access MFA requirements.

    .DESCRIPTION
    This script connects to Microsoft Graph, identifies Conditional Access policies, checks current exclusions,
    determines which policies apply to the target user and require MFA, and generates the commands (using -WhatIf)
    to add the user to the exclusion list of those policies. It also generates a sample command block to apply the changes
    using the recommended 'minimal update' method if policies are identified for modification.

    .PARAMETER TargetUserPrincipalName
    The User Principal Name (email address) of the user to be excluded.

    .PARAMETER AdminUserPrincipalName
    The User Principal Name (email address) of the administrator account used to connect. This script will prompt
    for this user's credentials during the connection phase.

    .EXAMPLE
    .\Exclude-UserFromMfaPolicy.ps1 -TargetUserPrincipalName "user.to.exclude@example.com" -AdminUserPrincipalName "admin.user@example.com"

    .NOTES
    Author: Brandon Sager
    Version: 1.0
    Requires Global Administrator, Conditional Access Administrator, or Security Administrator role.
    Requires the Microsoft.Graph.Identity.SignIns module.
    Ensure you review the output of the -WhatIf commands carefully before running the update commands without -WhatIf.
    The script generates sample 'apply change' commands using the minimal update approach (passing only -Conditions). Review these carefully before execution.
    Best practice recommendation: Consider creating an Azure AD group for MFA exclusions and adding users to that group,
    then excluding the group from the policy instead of individual users.
    This script focuses on direct user exclusion as requested.
    Reference: Get-MgIdentityConditionalAccessPolicy - https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/get-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0 (Uses -All for pagination)
    Reference: Update-MgIdentityConditionalAccessPolicy - https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0
    Reference: Conditional Access Conditions - https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0
    #>

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
            throw
        }
    } else {
        Write-Host "Module '$requiredModule' is already installed."
    }

    Import-Module $requiredModule -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop # Ensure auth module is loaded

    Write-Host "Step 2: Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "Please authenticate as '$AdminUserPrincipalName' in the browser window."

    $scopes = @("Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "User.Read.All", "Group.Read.All", "Directory.Read.All")
    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
    $context = Get-MgContext
    Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
    Write-Host " TenantId: $($context.TenantId)"
    Write-Host " Account: $($context.Account)"

    if ($context.Account -ne $AdminUserPrincipalName) {
        Write-Warning "Connected as '$($context.Account)', which differs from the specified AdminUserPrincipalName '$AdminUserPrincipalName'. Please ensure you logged in with the correct account."
    }

    Write-Host "`nStep 3: Getting Object ID for target user '$TargetUserPrincipalName'..." -ForegroundColor Yellow
    $targetUserId = $null
    $targetUser = Get-MgUser -Filter "userPrincipalName eq '$TargetUserPrincipalName'" -Select Id -ErrorAction Stop
    if ($targetUser) {
        $targetUserId = $targetUser.Id
        Write-Host "Found user '$TargetUserPrincipalName' with Object ID: $targetUserId" -ForegroundColor Green
    } else {
        Write-Error "User '$TargetUserPrincipalName' not found."
        return
    }

    Write-Host "`nStep 4: Retrieving all Conditional Access Policies and checking current configurations..." -ForegroundColor Yellow
    $policies = $null
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    if (-not $policies) {
        Write-Warning "No Conditional Access policies found in the tenant."
        return
    }

    Write-Host "Found $($policies.Count) policies. Analyzing inclusions, exclusions, and grant controls:"

    $policies | ForEach-Object {
        $policy = $_
        Write-Host "--------------------------------------------------"

        $policyDetails = [PSCustomObject]@{
            PolicyName         = $policy.DisplayName
            PolicyID           = $policy.Id
            State              = $policy.State
            IncludedUsers      = if ($policy.Conditions.Users.IncludeAllUsers) { 'All Users' } else { ($policy.Conditions.Users.IncludeUsers -join ', ') }
            IncludedGroups     = $policy.Conditions.Users.IncludeGroups -join ', '
            IncludedRoles      = $policy.Conditions.Users.IncludeRoles -join ', '
            ExcludedUsers      = $policy.Conditions.Users.ExcludeUsers -join ', '
            ExcludedGroups     = $policy.Conditions.Users.ExcludeGroups -join ', '
            ExcludedRoles      = $policy.Conditions.Users.ExcludeRoles -join ', '
            GrantControlMFA    = if ($policy.GrantControls) { $policy.GrantControls.BuiltInControls -contains "mfa" } else { $false }
            GrantControlCustom = if ($policy.GrantControls) { $null -ne $policy.GrantControls.CustomAuthenticationFactors -and $policy.GrantControls.CustomAuthenticationFactors.Count -gt 0 } else { $false }
            GrantOperator      = if ($policy.GrantControls) { $policy.GrantControls.Operator } else { $null }
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
            if (($policy.GrantControls.BuiltInControls -contains "mfa") -or ($null -ne $policy.GrantControls.CustomAuthenticationFactors -and $policy.GrantControls.CustomAuthenticationFactors.Count -gt 0)) {
                $policyRequiresMfa = $true
            }
        }
        if (-not $policyRequiresMfa) { continue } # Skip if it doesn't require MFA

        $userIsPotentiallyIncluded = $false

        if ($policy.Conditions.Users.IncludeAllUsers) { $userIsPotentiallyIncluded = $true }
        if (-not $userIsPotentiallyIncluded -and $policy.Conditions.Users.IncludeUsers -contains $targetUserId) { $userIsPotentiallyIncluded = $true }
        if (-not $userIsPotentiallyIncluded -and $policy.Conditions.Users.IncludeUsers -contains 'All') { $userIsPotentiallyIncluded = $true } # Handle 'All' string if used

        $directMemberGroups = $null
        if (-not $userIsPotentiallyIncluded -and $policy.Conditions.Users.IncludeGroups) {
            Write-Host "Checking included group memberships for policy '$($policy.DisplayName)'..." -ForegroundColor DarkGray
            $directMemberGroups = Get-MgUserMemberOf -UserId $targetUserId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
            if ($null -ne $directMemberGroups) {
                $commonGroups = $directMemberGroups | Where-Object {$policy.Conditions.Users.IncludeGroups -contains $_}
                if ($commonGroups) {
                    $userIsPotentiallyIncluded = $true
                    Write-Host " User '$TargetUserPrincipalName' is potentially included in policy '$($policy.DisplayName)' via group membership (Group ID(s): $($commonGroups -join ', '))." -ForegroundColor Gray
                }
            }
        }

        if (-not $userIsPotentiallyIncluded) { continue }

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
                $commonExcludedGroups = $directMemberGroups | Where-Object {$policy.Conditions.Users.ExcludeGroups -contains $_}
                if ($commonExcludedGroups) {
                    $userIsAlreadyExcluded = $true
                    Write-Host " User '$TargetUserPrincipalName' is ALREADY excluded from policy '$($policy.DisplayName)' via group membership (Group ID(s): $($commonExcludedGroups -join ', '))." -ForegroundColor Cyan
                }
            }
        }

        if ($userIsAlreadyExcluded) { continue }

        Write-Host "Policy '$($policy.DisplayName)' (ID: $($policy.Id)): IDENTIFIED for modification. Requires MFA and applies to user." -ForegroundColor Magenta
        $policiesToModify += $policy
    }

    if ($policiesToModify.Count -eq 0) {
        Write-Host "`nStep 6: No enabled policies found that require MFA and currently apply to '$TargetUserPrincipalName' without excluding them." -ForegroundColor Green
    } else {
        Write-Host "`nStep 6: Generating commands to exclude '$TargetUserPrincipalName' (ID: $targetUserId)..." -ForegroundColor Yellow
        Write-Host "The following command blocks can be used to apply the necessary changes." -ForegroundColor Yellow
        Write-Host "It is recommended to use the 'Minimal Update Attempt' block." -ForegroundColor Yellow

        foreach ($policy in $policiesToModify) {
            Write-Host "--------------------------------------------------"
            Write-Host "Commands for Policy: '$($policy.DisplayName)' (ID: $($policy.Id))"

            Write-Host @"

`$targetUserIdForUpdate = '$targetUserId'
`$policyIdToUpdate = '$($policy.Id)'
`$policyNameToUpdate = '$($policy.DisplayName)'

Write-Host "Getting policy '`$policyNameToUpdate' (`$policyIdToUpdate) before update..."
`$policyToUpdate = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId `$policyIdToUpdate -ErrorAction Stop
if (`$policyToUpdate) {
    Write-Host "Current ExcludeUsers: @(`$policyToUpdate.Conditions.Users.ExcludeUsers)"
    `$currentExclusions = @(`$policyToUpdate.Conditions.Users.ExcludeUsers)

    if (`$currentExclusions -notcontains `$targetUserIdForUpdate) {
        `$updatedExclusions = `$currentExclusions + `$targetUserIdForUpdate
        Write-Host "New ExcludeUsers: @(`$updatedExclusions)"

        `$updatedConditions = `$policyToUpdate.Conditions.PSObject.Copy()
        `$updatedConditions.Users.ExcludeUsers = `$updatedExclusions

        Write-Host "Review the planned MINIMAL update parameters before execution:"
        Write-Host "- ConditionalAccessPolicyId: `$(`$policyToUpdate.Id)"
        Write-Host "- Conditions (ONLY this object will be passed): `$(`$updatedConditions | ConvertTo-Json -Depth 4)"

        Write-Host "Command to run (uncomment above): Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId `$policyToUpdate.Id -Conditions `$updatedConditions"

    } else {
        Write-Warning "User ID '`$targetUserIdForUpdate' already found in ExcludeUsers for policy '`$policyNameToUpdate'. No update needed for this policy."
    }
} else {
    Write-Error "Failed to retrieve policy '`$policyNameToUpdate' before attempting update."
}
"@
            Write-Warning "IMPORTANT: Review the generated command block carefully before uncommenting and running the Update-MgIdentityConditionalAccessPolicy command."
            Write-Host "--------------------------------------------------"

        }
    }

    Write-Host "`nScript finished. Review the analysis output above." -ForegroundColor Green
    Write-Host "If policies were identified for modification, copy, review, and run the generated command block(s) to apply the exclusion(s)."
    Write-Host "Consider using an Azure AD Group for exclusions as a best practice for easier management."

    Write-Host "=… $ScriptBaseName completed successfully" -ForegroundColor Green

} catch {
    Write-Error "= $ScriptBaseName failed: $_"
    exit 1
} finally {
    Stop-Transcript
}

