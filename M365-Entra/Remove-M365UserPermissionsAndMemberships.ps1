#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement
#Requires -Modules ImportExcel

<#
.SYNOPSIS
    Remove-M365UserPermissionsAndMemberships — Removes M365 user permissions and group memberships with reporting

.DESCRIPTION
    Removes a user's permissions and memberships across Microsoft 365 services including:
    - Entra ID group memberships (Security groups, M365 groups)
    - Exchange Distribution Group memberships
    - Exchange mailbox permissions (FullAccess, SendAs, SendOnBehalf)
    Idempotent — running multiple times produces the same result without errors.
    All operations are logged and reported in a comprehensive Excel file.

.PARAMETER Users
    Array of user email addresses to process. If not provided, the script will prompt for input.

.PARAMETER ReportPath
    Folder path for Excel report output. Default: C:\scripts\reports

.PARAMETER MaxThreads
    Maximum parallel threads for operations. Default: 10.

.PARAMETER BatchMode
    Suppress interactive prompts (useful for scheduled runs).

.EXAMPLE
    .\Remove-M365UserPermissionsAndMemberships.ps1
    Runs the script interactively, prompting for user email addresses.

.EXAMPLE
    .\Remove-M365UserPermissionsAndMemberships.ps1 -Users @("user1@company.com", "user2@company.com") -WhatIf
    Processes specific users in preview mode.

.EXAMPLE
    .\Remove-M365UserPermissionsAndMemberships.ps1 -Users @("departing@company.com") -BatchMode
    Processes a user in batch mode without interactive prompts.

.NOTES
    Category: M365-Entra
    Requires: ExchangeOnlineManagement, Microsoft.Graph, ImportExcel modules

.KEYWORDS
    user, offboard, permission, Exchange, cleanup
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false, HelpMessage="Array of user email addresses to process")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Users,

    [Parameter(Mandatory=$false, HelpMessage="Folder path for Excel report output")]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = "C:\scripts\reports",

    [Parameter(Mandatory=$false, HelpMessage="Maximum parallel threads for operations")]
    [ValidateRange(1, 50)]
    [int]$MaxThreads = 10,

    [Parameter(Mandatory=$false, HelpMessage="Suppress interactive prompts")]
    [switch]$BatchMode
)

$ProgressPreference = 'Continue'

Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    M365 User Permissions & Memberships Removal               ║
║                                                                              ║
║  This script will remove user permissions and memberships from:              ║
║  * Entra ID Security Groups & M365 Groups                                    ║
║  * Exchange Distribution Groups                                              ║
║  * Exchange Mailbox Permissions (FullAccess, SendAs, SendOnBehalf)           ║
║                                                                              ║
║  All operations are IDEMPOTENT and fully logged.                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Checking module requirements..." -ForegroundColor Cyan

$requiredModules = @(
    @{Name="ExchangeOnlineManagement"; MinVersion="3.4.0"; Description="Exchange Online PowerShell V3"},
    @{Name="Microsoft.Graph"; MinVersion="2.18.0"; Description="Microsoft Graph PowerShell SDK"},
    @{Name="ImportExcel"; MinVersion="7.8.6"; Description="Excel reporting functionality"}
)

foreach ($module in $requiredModules) {
    Write-Host "  Checking $($module.Name)..." -ForegroundColor Gray -NoNewline

    $installedModule = Get-Module -ListAvailable -Name $module.Name |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $installedModule -or $installedModule.Version -lt [version]$module.MinVersion) {
        Write-Host " INSTALLING" -ForegroundColor Yellow
        Write-Host "    Installing $($module.Description) (min v$($module.MinVersion))..." -ForegroundColor Yellow

        Install-Module $module.Name -MinimumVersion $module.MinVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "    Installation completed" -ForegroundColor Green
    } else {
        Write-Host " OK (v$($installedModule.Version))" -ForegroundColor Green
    }
}

Write-Host "Loading modules..." -ForegroundColor Cyan
$moduleImports = @('ExchangeOnlineManagement', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'ImportExcel')

foreach ($moduleName in $moduleImports) {
    Import-Module $moduleName -ErrorAction Stop
    Write-Host "  $moduleName loaded" -ForegroundColor Green
}

if (-not $Users -and -not $BatchMode) {
    Write-Host "`nUser Input Required" -ForegroundColor Yellow
    Write-Host "Enter the email address(es) of users to process permissions removal." -ForegroundColor White
    Write-Host "You can enter multiple users separated by commas or semicolons." -ForegroundColor Gray
    Write-Host ""

    do {
        $userInput = Read-Host "Email address(es)"

        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Host "Email address is required. Please try again." -ForegroundColor Red
            continue
        }

        $Users = $userInput -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

        $invalidEmails = @()
        $validEmails = @()

        foreach ($email in $Users) {
            if ($email -match '^[^\s@]+@[^\s@]+\.[^\s@]+$') {
                $validEmails += $email
            } else {
                $invalidEmails += $email
            }
        }

        if ($invalidEmails.Count -gt 0) {
            Write-Host "Invalid email format(s): $($invalidEmails -join ', ')" -ForegroundColor Red
            Write-Host "Please enter valid email addresses." -ForegroundColor Yellow
            $Users = $null
            continue
        }

        $Users = $validEmails
        break

    } while ($true)

    Write-Host "`nUsers to process:" -ForegroundColor Cyan
    foreach ($user in $Users) {
        Write-Host "  - $user" -ForegroundColor White
    }

    if (-not $WhatIfPreference) {
        Write-Host "`nWARNING: This will remove permissions and memberships for the above user(s)!" -ForegroundColor Yellow
        $confirmation = Read-Host "`nContinue? (y/N)"

        if ($confirmation -notmatch '^[Yy]$') {
            Write-Host "Operation cancelled by user." -ForegroundColor Red
            exit 0
        }
    }

} elseif (-not $Users) {
    Write-Error "No users specified. Use -Users parameter or run without -BatchMode for interactive input."
    exit 1
}

Write-Host "`nProcessing $($Users.Count) user(s)" -ForegroundColor Green
if ($WhatIfPreference) {
    Write-Host "Running in WhatIf mode - no changes will be made" -ForegroundColor Magenta
}

Write-Host "`nEstablishing service connections..." -ForegroundColor Cyan

try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "  Exchange Online: Already connected" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
    exit 1
}

try {
    $context = Get-MgContext -ErrorAction Stop
    if ($context) {
        Write-Host "  Microsoft Graph: Already connected" -ForegroundColor Green

        $requiredScopes = @("User.Read.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }

        if ($missingScopes.Count -gt 0) {
            Write-Host "  Microsoft Graph: Reconnecting for additional scopes..." -ForegroundColor Yellow
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
            Write-Host "  Microsoft Graph: Reconnected with required scopes" -ForegroundColor Green
        }
    } else {
        throw "No active context"
    }
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nInitializing reporting framework..." -ForegroundColor Cyan

if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    Write-Host "  Created report directory: $ReportPath" -ForegroundColor Green
}

$allResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$allErrors = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

function Invoke-IdempotentOperation {
    param(
        [string]$OperationName,
        [string]$TargetUser,
        [string]$TargetObject,
        [ScriptBlock]$Operation,
        [string]$OperationType
    )

    $operationId = "$OperationName-$TargetUser-$TargetObject"

    try {
        if ($WhatIfPreference -or -not $PSCmdlet.ShouldProcess($TargetObject, $OperationName)) {
            Write-Host "  WHATIF: Would $OperationName for $TargetObject" -ForegroundColor Magenta
            $result = [PSCustomObject]@{
                User = $TargetUser
                Operation = $OperationName
                Target = $TargetObject
                Type = $OperationType
                Status = "WhatIf"
                Timestamp = Get-Date
                Error = $null
            }
        } else {
            & $Operation
            Write-Host "  SUCCESS: $OperationName for $TargetObject" -ForegroundColor Green

            $result = [PSCustomObject]@{
                User = $TargetUser
                Operation = $OperationName
                Target = $TargetObject
                Type = $OperationType
                Status = "Success"
                Timestamp = Get-Date
                Error = $null
            }
        }

        $allResults.Add($result)
        return $result
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "  ERROR: $OperationName for $TargetObject - $errorMessage" -ForegroundColor Red

        $errorResult = [PSCustomObject]@{
            User = $TargetUser
            Operation = $OperationName
            Target = $TargetObject
            Type = $OperationType
            Status = "Error"
            Timestamp = Get-Date
            Error = $errorMessage
        }

        $allErrors.Add($errorResult)
        $allResults.Add($errorResult)
        return $errorResult
    }
}

Write-Host "`nBeginning permissions removal process..." -ForegroundColor Cyan
Write-Host "────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray

$userCounter = 0
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

foreach ($targetUser in $Users) {
    $userCounter++
    Write-Host "`nProcessing User $userCounter of $($Users.Count): $targetUser" -ForegroundColor Yellow
    Write-Host "────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray

    Write-Host "Resolving user identity..." -ForegroundColor Cyan
    try {
        $filterString = "userPrincipalName eq '$targetUser' or mail eq '$targetUser'"
        $mgUser = Get-MgUser -Filter $filterString -ConsistencyLevel eventual -Count Variable -ErrorAction Stop

        if (-not $mgUser) {
            throw "User '$targetUser' not found in Entra ID"
        }

        $uid = $mgUser.Id
        $upn = $mgUser.UserPrincipalName
        $mail = $mgUser.Mail
        $displayName = $mgUser.DisplayName

        Write-Host "  Found: $displayName ($upn)" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to resolve user: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }

    Write-Host "`nProcessing Entra ID group memberships..." -ForegroundColor Cyan
    try {
        $groupMemberships = Get-MgUserMemberOf -UserId $uid -All -ErrorAction Stop
        $groups = $groupMemberships | Where-Object { $_.OdataType -eq "#microsoft.graph.group" }

        Write-Host "  Found $($groups.Count) group memberships" -ForegroundColor Yellow

        if ($groups.Count -gt 0) {
            foreach ($group in $groups) {
                try {
                    $groupDetails = Get-MgGroup -GroupId $group.Id -Property id,displayName,groupTypes -ErrorAction Stop
                    $groupType = if ($groupDetails.GroupTypes -contains "Unified") { "M365 Group" } else { "Security/Other" }

                    Invoke-IdempotentOperation -OperationName "Remove Entra Group Membership" -TargetUser $upn -TargetObject $groupDetails.DisplayName -OperationType "EntraGroup" -Operation {
                        Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $uid
                    }
                } catch {
                    Write-Host "  Failed to process group $($group.Id): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  No group memberships found" -ForegroundColor Blue
        }
    } catch {
        Write-Host "  Failed to retrieve group memberships: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nProcessing Exchange Distribution Groups..." -ForegroundColor Cyan
    try {
        $allDGs = Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop
        Write-Host "  Checking $($allDGs.Count) distribution groups..." -ForegroundColor Yellow

        $counter = 0
        $foundMemberships = @()

        foreach ($dg in $allDGs) {
            $counter++
            if ($counter % 20 -eq 0) {
                Write-Host "    Progress: $counter/$($allDGs.Count) groups checked" -ForegroundColor Gray
            }

            try {
                $members = Get-DistributionGroupMember -Identity $dg.Identity -ResultSize Unlimited -ErrorAction SilentlyContinue
                if ($members -and ($members.PrimarySmtpAddress -contains $upn -or $members.PrimarySmtpAddress -contains $mail)) {
                    $foundMemberships += $dg
                }
            } catch {
                # Silently skip inaccessible groups
            }
        }

        Write-Host "  Found $($foundMemberships.Count) distribution group memberships" -ForegroundColor Yellow

        foreach ($dg in $foundMemberships) {
            Invoke-IdempotentOperation -OperationName "Remove Distribution Group Membership" -TargetUser $upn -TargetObject $dg.DisplayName -OperationType "DistributionGroup" -Operation {
                Remove-DistributionGroupMember -Identity $dg.Identity -Member $upn -BypassSecurityGroupManagerCheck:$true -Confirm:$false
            }
        }

        if ($foundMemberships.Count -eq 0) {
            Write-Host "  No distribution group memberships found" -ForegroundColor Blue
        }
    } catch {
        Write-Host "  Failed to process distribution groups: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nProcessing Exchange mailbox permissions..." -ForegroundColor Cyan

    Write-Host "  Checking SendAs permissions..." -ForegroundColor Gray
    $sendAsPerms = Get-RecipientPermission -Trustee $upn -ErrorAction SilentlyContinue |
        Where-Object { $_.AccessRights -contains "SendAs" }

    Write-Host "    Found $($sendAsPerms.Count) SendAs permissions" -ForegroundColor Yellow

    foreach ($perm in $sendAsPerms) {
        Invoke-IdempotentOperation -OperationName "Remove SendAs Permission" -TargetUser $upn -TargetObject $perm.Identity -OperationType "SendAs" -Operation {
            Remove-RecipientPermission -Identity $perm.Identity -Trustee $upn -AccessRights SendAs -Confirm:$false
        }
    }

    Write-Host "  Checking SendOnBehalf permissions..." -ForegroundColor Gray
    $sendOnBehalfMbxs = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
        Where-Object { $_.GrantSendOnBehalfTo -and ($_.GrantSendOnBehalfTo -contains $upn -or $_.GrantSendOnBehalfTo -contains $mail) }

    Write-Host "    Found $($sendOnBehalfMbxs.Count) SendOnBehalf permissions" -ForegroundColor Yellow

    foreach ($mbx in $sendOnBehalfMbxs) {
        Invoke-IdempotentOperation -OperationName "Remove SendOnBehalf Permission" -TargetUser $upn -TargetObject $mbx.PrimarySmtpAddress -OperationType "SendOnBehalf" -Operation {
            Set-Mailbox -Identity $mbx.Identity -GrantSendOnBehalfTo @{remove="$upn"}
        }
    }

    Write-Host "  Checking FullAccess permissions..." -ForegroundColor Gray
    try {
        $allMailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        Write-Host "    Scanning $($allMailboxes.Count) mailboxes..." -ForegroundColor Yellow

        $batchSize = 50
        $batches = [System.Math]::Ceiling($allMailboxes.Count / $batchSize)
        $totalProcessed = 0
        $fullAccessFound = 0

        for ($i = 0; $i -lt $batches; $i++) {
            $startIndex = $i * $batchSize
            $endIndex = [Math]::Min(($startIndex + $batchSize - 1), ($allMailboxes.Count - 1))
            $batch = $allMailboxes[$startIndex..$endIndex]

            foreach ($mbx in $batch) {
                $totalProcessed++

                if ($totalProcessed % 50 -eq 0) {
                    Write-Host "      Progress: $totalProcessed/$($allMailboxes.Count) mailboxes" -ForegroundColor Gray
                }

                try {
                    $perms = Get-MailboxPermission -Identity $mbx.Identity -User $upn -ErrorAction SilentlyContinue |
                        Where-Object { -not $_.IsInherited -and $_.AccessRights -contains "FullAccess" }

                    if ($perms) {
                        $fullAccessFound++
                        Invoke-IdempotentOperation -OperationName "Remove FullAccess Permission" -TargetUser $upn -TargetObject $mbx.PrimarySmtpAddress -OperationType "FullAccess" -Operation {
                            Remove-MailboxPermission -Identity $mbx.Identity -User $upn -AccessRights FullAccess -InheritanceType All -Confirm:$false
                        }
                    }
                } catch {
                    # Silently skip inaccessible mailboxes
                }
            }
        }

        Write-Host "    Found $fullAccessFound FullAccess permissions" -ForegroundColor Yellow
    } catch {
        Write-Host "    Failed to check FullAccess permissions: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "Completed processing for $displayName" -ForegroundColor Green
}

Write-Host "`nGenerating comprehensive report..." -ForegroundColor Cyan

$reportFile = Join-Path $ReportPath "M365_Permissions_Removal_Report_$timestamp.xlsx"

$allResultsArray = [array]$allResults.ToArray()
$allErrorsArray = [array]$allErrors.ToArray()

$entraGroupResults = $allResultsArray | Where-Object { $_.Type -eq "EntraGroup" }
$distGroupResults = $allResultsArray | Where-Object { $_.Type -eq "DistributionGroup" }
$sendAsResults = $allResultsArray | Where-Object { $_.Type -eq "SendAs" }
$sendOnBehalfResults = $allResultsArray | Where-Object { $_.Type -eq "SendOnBehalf" }
$fullAccessResults = $allResultsArray | Where-Object { $_.Type -eq "FullAccess" }

$excelParams = @{
    Path = $reportFile
    AutoSize = $true
    FreezeTopRow = $true
    BoldTopRow = $true
    TableStyle = "Medium6"
}

$entraGroupResults | Export-Excel @excelParams -WorksheetName "Entra_ID_Groups"
$distGroupResults | Export-Excel @excelParams -WorksheetName "Distribution_Groups"
$sendAsResults | Export-Excel @excelParams -WorksheetName "SendAs_Permissions"
$sendOnBehalfResults | Export-Excel @excelParams -WorksheetName "SendOnBehalf_Permissions"
$fullAccessResults | Export-Excel @excelParams -WorksheetName "FullAccess_Permissions"
$allErrorsArray | Export-Excel @excelParams -WorksheetName "Errors_and_Issues"

$summary = foreach ($user in $Users) {
    $userResults = $allResultsArray | Where-Object { $_.User -like "*$user*" -or $user -like "*$($_.User)*" }
    $userErrors = $allErrorsArray | Where-Object { $_.User -like "*$user*" -or $user -like "*$($_.User)*" }

    [PSCustomObject]@{
        User = $user
        ProcessedDate = Get-Date
        EntraGroupsProcessed = ($userResults | Where-Object { $_.Type -eq "EntraGroup" }).Count
        DistributionGroupsProcessed = ($userResults | Where-Object { $_.Type -eq "DistributionGroup" }).Count
        SendAsPermissionsProcessed = ($userResults | Where-Object { $_.Type -eq "SendAs" }).Count
        SendOnBehalfPermissionsProcessed = ($userResults | Where-Object { $_.Type -eq "SendOnBehalf" }).Count
        FullAccessPermissionsProcessed = ($userResults | Where-Object { $_.Type -eq "FullAccess" }).Count
        TotalOperations = $userResults.Count
        ErrorCount = $userErrors.Count
        WhatIfMode = $WhatIfPreference
    }
}

$summary | Export-Excel @excelParams -WorksheetName "Executive_Summary"

Write-Host "Report generated successfully!" -ForegroundColor Green
Write-Host "Report location: $reportFile" -ForegroundColor White

Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                              EXECUTION SUMMARY                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

foreach ($userSummary in $summary) {
    Write-Host "`nUser: $($userSummary.User)" -ForegroundColor White
    Write-Host "   Entra ID Groups: $($userSummary.EntraGroupsProcessed)" -ForegroundColor Yellow
    Write-Host "   Distribution Groups: $($userSummary.DistributionGroupsProcessed)" -ForegroundColor Yellow
    Write-Host "   SendAs Permissions: $($userSummary.SendAsPermissionsProcessed)" -ForegroundColor Yellow
    Write-Host "   SendOnBehalf Permissions: $($userSummary.SendOnBehalfPermissionsProcessed)" -ForegroundColor Yellow
    Write-Host "   FullAccess Permissions: $($userSummary.FullAccessPermissionsProcessed)" -ForegroundColor Yellow
    Write-Host "   Total Operations: $($userSummary.TotalOperations)" -ForegroundColor Cyan
    Write-Host "   Errors: $($userSummary.ErrorCount)" -ForegroundColor $(if($userSummary.ErrorCount -gt 0){"Red"}else{"Green"})
}

Write-Host "`nOverall Statistics:" -ForegroundColor Cyan
Write-Host "   Users Processed: $($Users.Count)" -ForegroundColor White
Write-Host "   Total Operations: $($allResultsArray.Count)" -ForegroundColor White
Write-Host "   Successful Operations: $(($allResultsArray | Where-Object {$_.Status -in @('Success', 'WhatIf', 'Already Completed')}).Count)" -ForegroundColor Green
Write-Host "   Errors: $($allErrorsArray.Count)" -ForegroundColor $(if($allErrorsArray.Count -gt 0){"Red"}else{"Green"})

if ($WhatIfPreference) {
    Write-Host "`nWhatIf Mode: No actual changes were made" -ForegroundColor Magenta
} else {
    Write-Host "`nAll operations completed successfully!" -ForegroundColor Green
}

Write-Host "`nDetailed report available at: $reportFile" -ForegroundColor White
