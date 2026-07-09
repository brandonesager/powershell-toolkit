#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

using namespace System.Management.Automation.Host

<#
.SYNOPSIS
    Check and enable litigation hold for specified Contoso user accounts
.DESCRIPTION
    Checks current litigation hold status for specified users and enables if not already active.
    Exports results to designated helpdesk ticket folder for audit purposes.
    Uses modern Exchange Online PowerShell with OAuth authentication.
.CLOUD_CATEGORY
    Compliance
.PERMISSIONS_REQUIRED
    Exchange Administrator or Compliance Administrator role
    Exchange Online PowerShell connection with appropriate permissions
.TENANT_IMPACT
    Single-User - Only affects specified user mailboxes
.PREREQUISITES
    PowerShell 7+ required
    ExchangeOnlineManagement module v3.0+
    Modern authentication configured
.PARAMETER Users
    Array of user email addresses to check and enable litigation hold for.
    Defaults to predefined Contoso user accounts.

.PARAMETER ExportPath
    Directory path for exporting results (CSV, JSON, summary).
    Defaults to the script's directory ($PSScriptRoot).

.PARAMETER WhatIf
    Preview changes without enabling litigation holds.

.PARAMETER EnableTranscript
    Enable PowerShell transcript logging to the export path.

.NOTES
    Category: Environment-Specific
    Requires PowerShell 7+
    Modern authentication required
    Exchange Online scopes: Mail.Read, Mail.ReadWrite

    Quick execution methods:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\Enable-LitigationHold-Bulk.ps1'
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\Enable-LitigationHold-Bulk.ps1' -ExportPath 'C:\temp\litigation-results'
.KEYWORDS
    litigation, hold, Exchange, compliance, Contoso
#>

param(
    [string[]]$Users = @(
        'user1@contoso.com',
        'user2@contoso.com',
        'user3@contoso.com',
        'user4@contoso.com'
    ),
    [string]$ExportPath = $PSScriptRoot,
    [switch]$WhatIf,
    [switch]$EnableTranscript
)

# Function to check and install required modules with enhanced PowerShell 7 features
function Test-RequiredModule {
    param([string[]]$ModuleNames)

    $MissingModules = @()
    $ModuleNames | ForEach-Object -Parallel {
        $Module = $_
        if (-not (Get-Module -ListAvailable -Name $Module)) {
            Write-Output "[CLOUD]|WARN|MODULE|Module not installed: $Module|{`"action`":`"install_required`",`"psVersion`":`"$($PSVersionTable.PSVersion)`"}"
            return $Module
        }
        elseif (-not (Get-Module -Name $Module)) {
            Write-Output "[CLOUD]|INFO|MODULE|Importing module: $Module|{`"psVersion`":`"$($PSVersionTable.PSVersion)`"}"
            try {
                Import-Module $Module -Force -ErrorAction Stop
                Write-Output "[CLOUD]|SUCCESS|MODULE|Module imported: $Module|{`"version`":`"$((Get-Module $Module).Version)`"}"
            }
            catch {
                Write-Output "[CLOUD]|ERROR|MODULE|Failed to import module: $Module|{`"error`":`"$($_.Exception.Message)`"}"
                return $Module
            }
        }
        else {
            $Version = (Get-Module -Name $Module).Version.ToString()
            Write-Output "[CLOUD]|INFO|MODULE|Module already loaded: $Module|{`"version`":`"$Version`"}"
        }
    } -ThrottleLimit 5 | ForEach-Object { if ($_) { $MissingModules += $_ } }

    if ($MissingModules.Count -gt 0) {
        Write-Output "[CLOUD]|ERROR|MODULE|Missing required modules|{`"modules`":`"$($MissingModules -join ', ')`",`"installCommand`":`"Install-Module $($MissingModules -join ', ') -Force -AllowClobber`"}"
        return $false
    }
    return $true
}

# Function to test Exchange Online connection with modern auth
function Test-ExchangeConnection {
    param([string]$TenantId = "contoso.com")

    try {
        # Check if Exchange Online module is loaded
        if (-not (Get-Module -Name ExchangeOnlineManagement)) {
            Write-Output "[CLOUD]|INFO|CONNECT|ExchangeOnlineManagement module not loaded|{}"
            return $false
        }

        # Check for active Exchange Online sessions
        $Session = Get-PSSession | Where-Object {
            $_.ConfigurationName -eq 'Microsoft.Exchange' -and
            $_.State -eq 'Opened' -and
            $_.ComputerName -like '*outlook.office365.com'
        }

        if ($Session) {
            # Verify the session is working by testing a simple cmdlet
            try {
                $null = Get-OrganizationConfig -ErrorAction Stop | Select-Object -First 1
                Write-Output "[CLOUD]|SUCCESS|CONNECT|Exchange Online connection verified|{`"tenant`":`"$TenantId`",`"sessionId`":`"$($Session.Id)`"}"
                return $true
            }
            catch {
                Write-Output "[CLOUD]|WARN|CONNECT|Exchange Online session exists but not functional|{`"tenant`":`"$TenantId`",`"error`":`"$($_.Exception.Message)`"}"
                return $false
            }
        }

        Write-Output "[CLOUD]|INFO|CONNECT|Exchange Online connection required|{`"tenant`":`"$TenantId`"}"
        return $false
    }
    catch {
        Write-Output "[CLOUD]|INFO|CONNECT|Exchange Online connection required|{`"tenant`":`"$TenantId`",`"error`":`"$($_.Exception.Message)`"}"
        return $false
    }
}

# Function to check litigation hold status
function Get-LitigationHoldStatus {
    param(
        [string]$UserPrincipalName
    )

    try {
        $Mailbox = Get-EXOMailbox -Identity $UserPrincipalName -Properties LitigationHoldEnabled, LitigationHoldDate, LitigationHoldOwner -ErrorAction Stop

        $Status = @{
            UserPrincipalName = $UserPrincipalName
            DisplayName = $Mailbox.DisplayName
            LitigationHoldEnabled = $Mailbox.LitigationHoldEnabled
            LitigationHoldDate = $Mailbox.LitigationHoldDate
            LitigationHoldOwner = $Mailbox.LitigationHoldOwner
            CheckDate = Get-Date
            Action = 'None'
            Success = $true
            Error = $null
        }

        Write-Output "[CLOUD]|INFO|CHECK|Litigation hold status retrieved|{`"user`":`"$UserPrincipalName`",`"enabled`":$($Mailbox.LitigationHoldEnabled.ToString().ToLower())}"
        return [PSCustomObject]$Status
    }
    catch {
        $Status = @{
            UserPrincipalName = $UserPrincipalName
            DisplayName = 'Unknown'
            LitigationHoldEnabled = $false
            LitigationHoldDate = $null
            LitigationHoldOwner = $null
            CheckDate = Get-Date
            Action = 'Error'
            Success = $false
            Error = $_.Exception.Message
        }

        Write-Output "[CLOUD]|ERROR|CHECK|Failed to retrieve litigation hold status|{`"user`":`"$UserPrincipalName`",`"error`":`"$($_.Exception.Message)`"}"
        return [PSCustomObject]$Status
    }
}

# Function to enable litigation hold
function Enable-LitigationHold {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$UserPrincipalName
    )

    try {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Enable litigation hold")) {
            Set-Mailbox -Identity $UserPrincipalName -LitigationHoldEnabled $true -ErrorAction Stop
        }
        else {
            Write-Output "[CLOUD]|INFO|WHATIF|Would enable litigation hold|{`"user`":`"$UserPrincipalName`"}"
            return @{
                Success = $true
                Action = 'WhatIf'
                Error = $null
            }
        }
        Write-Output "[CLOUD]|SUCCESS|ENABLE|Litigation hold enabled|{`"user`":`"$UserPrincipalName`"}"

        return @{
            Success = $true
            Action = 'Enabled'
            Error = $null
        }
    }
    catch {
        Write-Output "[CLOUD]|ERROR|ENABLE|Failed to enable litigation hold|{`"user`":`"$UserPrincipalName`",`"error`":`"$($_.Exception.Message)`"}"

        return @{
            Success = $false
            Action = 'Failed'
            Error = $_.Exception.Message
        }
    }
}

# Function to write cloud exports (CSV + JSON summary)
function Write-CloudExports {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$ExportRoot,
        [datetime]$StartTime,
        [string]$Status = "SUCCESS"
    )

    try {
        # Ensure export directory exists
        if (-not (Test-Path $ExportRoot)) {
            New-Item -ItemType Directory -Force -Path $ExportRoot | Out-Null
        }

        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $Duration = (Get-Date) - $StartTime

        # Always create CSV (even if empty)
        $CsvPath = Join-Path $ExportRoot "results-$Timestamp.csv"
        if ($Results.Count -gt 0) {
            $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Force
        } else {
            # Create empty CSV with headers (needs to match PSCustomObject properties)
            "UserPrincipalName,DisplayName,LitigationHoldEnabled,LitigationHoldDate,LitigationHoldOwner,CheckDate,Action,Success,Error" | Out-File -FilePath $CsvPath -Force
        }

        # Create JSON summary with safe count calculations
        $JsonPath = Join-Path $ExportRoot "summary-$Timestamp.json"
        $AlreadyEnabledCount = ($Results | Where-Object { $_.LitigationHoldEnabled -and ($_.Action -in @('None','Already Enabled')) }).Count
        $EnabledCount = ($Results | Where-Object { $_.Action -eq 'Enabled' }).Count
        $ErrorCount = ($Results | Where-Object { -not $_.Success }).Count

        $Summary = @{
            Timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
            Status = $Status
            Tenant = "contoso.com"
            Duration = "$($Duration.TotalSeconds)s"
            UsersProcessed = $Results.Count
            AlreadyEnabled = $AlreadyEnabledCount
            NewlyEnabled = $EnabledCount
            Errors = $ErrorCount
            Ticket = ""
        }

        $Summary | ConvertTo-Json -Depth 2 | Out-File -FilePath $JsonPath -Force

        return @{ CsvPath = $CsvPath; JsonPath = $JsonPath }
    }
    catch {
        Write-Output "[CLOUD]|ERROR|EXPORT|Failed to write exports|{`"error`":`"$($_.Exception.Message)`"}"
        throw
    }
}

# Function to export results
function Export-LitigationHoldResult {
    param(
        [array]$Results,
        [string]$ExportPath
    )

    try {
        # Ensure export directory exists
        if (-not (Test-Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }

        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        # Export to CSV
        $CsvPath = Join-Path $ExportPath "litigation-hold-results-$Timestamp.csv"
        $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Force

        # Export to JSON for detailed data
        $JsonPath = Join-Path $ExportPath "litigation-hold-results-$Timestamp.json"
        $Results | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonPath -Force

        # Create summary report
        $SummaryPath = Join-Path $ExportPath "litigation-hold-summary-$Timestamp.txt"
        $Summary = @"
Contoso Litigation Hold Summary Report
Generated: $(Get-Date)
Ticket:

Users Processed: $($Results.Count)
Already Enabled: $(($Results | Where-Object { $_.LitigationHoldEnabled -and ($_.Action -eq 'None' -or $_.Action -eq 'Already Enabled') }).Count)
Newly Enabled: $(($Results | Where-Object { $_.Action -eq 'Enabled' }).Count)
Errors: $(($Results | Where-Object { -not $_.Success }).Count)

Detailed Results:
$($Results | ForEach-Object {
    "User: $($_.UserPrincipalName)"
    "  Name: $($_.DisplayName)"
    "  Litigation Hold: $($_.LitigationHoldEnabled)"
    "  Action: $($_.Action)"
    if ($_.Error) { "  Error: $($_.Error)" }
    ""
})

Files Generated:
- CSV: litigation-hold-results-$Timestamp.csv
- JSON: litigation-hold-results-$Timestamp.json
- Summary: litigation-hold-summary-$Timestamp.txt
"@

        $Summary | Out-File -FilePath $SummaryPath -Force

        Write-Output "[CLOUD]|SUCCESS|EXPORT|Results exported successfully|{`"csv`":`"$CsvPath`",`"json`":`"$JsonPath`",`"summary`":`"$SummaryPath`"}"

        return @{
            CsvPath = $CsvPath
            JsonPath = $JsonPath
            SummaryPath = $SummaryPath
        }
    }
    catch {
        Write-Output "[CLOUD]|ERROR|EXPORT|Failed to export results|{`"error`":`"$($_.Exception.Message)`"}"
        throw
    }
}

# Early transcript start (optional)
if ($EnableTranscript) {
    Start-Transcript -Path (Join-Path $ExportPath "transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt") -Force
}

# Main execution
$StartTime = Get-Date

try {
    Write-Output "[CLOUD]|INFO|START|Starting litigation hold check and enable process|{`"users`":$($Users.Count),`"whatif`":$($WhatIf.ToString().ToLower())}"

    # 1. Check required modules
    $RequiredModules = @('ExchangeOnlineManagement')
    if (-not (Test-RequiredModule -ModuleNames $RequiredModules)) {
        Write-Output "[CLOUD]|ERROR|PREREQ|Required modules not available|{}"
        exit 1
    }

    # 2. Initialize connection tracking
    $ExchangeConnectionRequired = $false

    # 3. Test and establish Exchange connection if needed
    if (-not (Test-ExchangeConnection -TenantId "contoso.com")) {
        Write-Output "[CLOUD]|INFO|CONNECT|Connecting to Exchange Online|{`"tenant`":`"contoso.com`"}"
        try {
            Connect-ExchangeOnline -ShowProgress:$false -ShowBanner:$false -ErrorAction Stop
            $ExchangeConnectionRequired = $true
            Write-Output "[CLOUD]|SUCCESS|CONNECT|Connected to Exchange Online|{`"tenant`":`"contoso.com`"}"
        }
        catch {
            Write-Output "[CLOUD]|ERROR|CONNECT|Failed to connect to Exchange Online|{`"tenant`":`"contoso.com`",`"error`":`"$($_.Exception.Message)`"}"
            exit 1
        }
    }
    else {
        Write-Output "[CLOUD]|INFO|CONNECT|Using existing Exchange Online session|{`"tenant`":`"contoso.com`"}"
    }

    # 4. Process each user
    # Initialize Results as generic list for better performance and early population
    $Results = [System.Collections.Generic.List[object]]::new()

    foreach ($User in $Users) {
        Write-Output "[CLOUD]|INFO|PROCESS|Processing user: $User|{}"

        # Check current status
        $Status = Get-LitigationHoldStatus -UserPrincipalName $User

        if ($Status.Success) {
            if (-not $Status.LitigationHoldEnabled) {
                # Enable litigation hold
                Write-Output "[CLOUD]|INFO|ACTION|Enabling litigation hold for $User|{}"
                if ($WhatIf) {
                    $EnableResult = Enable-LitigationHold -UserPrincipalName $User -WhatIf
                } else {
                    $EnableResult = Enable-LitigationHold -UserPrincipalName $User
                }

                $Status['Action'] = $EnableResult.Action
                if (-not $EnableResult.Success) {
                    $Status['Success'] = $false
                    $Status['Error'] = $EnableResult.Error
                }
            }
            else {
                Write-Output "[CLOUD]|INFO|SKIP|Litigation hold already enabled for $User|{}"
                $Status['Action'] = 'Already Enabled'
            }
        }

        $Results.Add($Status)
    }

    # 5. Export results
    Write-Output "[CLOUD]|INFO|EXPORT|Exporting results to $ExportPath|{}"
    $ExportResults = Export-LitigationHoldResult -Results $Results -ExportPath $ExportPath

    # 6. Summary
    # Use Write-CloudExports for consistent export logic
    $CloudExports = Write-CloudExports -Results $Results -ExportRoot $ExportPath -StartTime $StartTime -Status "SUCCESS"
    Write-Output "[CLOUD]|INFO|EXPORT|Cloud exports created|{`"csv`":`"$($CloudExports.CsvPath)`",`"json`":`"$($CloudExports.JsonPath)`"}"

    $Duration = (Get-Date) - $StartTime
    # Safe count calculations using .Count on filtered collections
    $SuccessCount = ($Results | Where-Object { $_.Success }).Count
    $EnabledCount = ($Results | Where-Object { $_.Action -eq 'Enabled' }).Count

    Write-Output "[CLOUD]|SUCCESS|COMPLETE|Litigation hold process completed successfully|{`"duration`":`"$($Duration.TotalSeconds)s`",`"processed`":$($Results.Count),`"successful`":$SuccessCount,`"enabled`":$EnabledCount}"

    Write-Output ""
    Write-Output "Summary:"
    Write-Output "- Users processed: $($Results.Count)"
    Write-Output "- Successful operations: $SuccessCount"
    Write-Output "- Newly enabled: $EnabledCount"
    Write-Output "- Legacy results exported to: $($ExportResults.SummaryPath)"
    Write-Output "- Cloud exports: $($CloudExports.CsvPath)"
    Write-Output "- Summary: $($CloudExports.JsonPath)"

    # 7. Cleanup: Disconnect if we connected in this session (commented for session reuse)
    if ($ExchangeConnectionRequired) {
        try {
            # Disconnect-ExchangeOnline -Confirm:$false
            Write-Output "[CLOUD]|INFO|CLEANUP|Exchange Online session maintained for additional scripts|{}"
        }
        catch {
            Write-Output "[CLOUD]|WARN|CLEANUP|Could not disconnect Exchange Online session|{`"error`":`"$($_.Exception.Message)`"}"
        }
    }
}
catch {
    $Duration = (Get-Date) - $StartTime
    Write-Output "[CLOUD]|ERROR|FAILURE|Contoso litigation hold process failed|{`"error`":`"$($_.Exception.Message)`",`"duration`":`"$($Duration.TotalSeconds)s`",`"tenant`":`"contoso.com`"}"

    # Export any results we have so far, even on failure
    # Always attempt to write exports (creates empty files if no results)
    try {
        Write-Output "[CLOUD]|INFO|EXPORT|Writing exports on failure|{`"resultsCount`":$($Results.Count)}"
        $CloudExports = Write-CloudExports -Results $Results -ExportRoot $ExportPath -StartTime $StartTime -Status "FAILURE"
        Write-Output "[CLOUD]|INFO|EXPORT|Failure exports created|{`"csv`":`"$($CloudExports.CsvPath)`",`"json`":`"$($CloudExports.JsonPath)`"}"
    }
    catch {
        Write-Output "[CLOUD]|WARN|EXPORT|Failed to create failure exports|{`"error`":`"$($_.Exception.Message)`"}"
    }

    # Legacy export attempt for backward compatibility
    if ($Results -and $Results.Count -gt 0) {
        try {
            $ExportResults = Export-LitigationHoldResult -Results $Results -ExportPath $ExportPath
        } catch { }
    }

    # Cleanup on error: Disconnect if we connected in this session
    if ($ExchangeConnectionRequired) {
        try {
            # Disconnect-ExchangeOnline -Confirm:$false
            Write-Output "[CLOUD]|INFO|CLEANUP|Exchange Online session maintained despite error|{}"
        }
        catch {
            Write-Output "[CLOUD]|WARN|CLEANUP|Could not disconnect Exchange Online session|{`"error`":`"$($_.Exception.Message)`"}"
        }
    }
    exit 1
}
finally {
    if ($EnableTranscript) {
        Stop-Transcript
    }
}
