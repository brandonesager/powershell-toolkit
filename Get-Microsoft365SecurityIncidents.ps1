<#
.SYNOPSIS
    Investigate Microsoft 365 Account Security Incidents

.DESCRIPTION
    Comprehensive security investigation tool for M365/Entra ID account compromise alerts.
    Performs multi-source analysis:
    - Exchange Online Message Trace for alert sender emails
    - Interactive and Non-Interactive Sign-in logs
    - Unified Audit Log searches for security-related activities

    Outputs formatted reports with Pacific Time conversion for review.

.NOTES
    Author: Brandon Sager
    Version: 1.0

    Requirements:
    - PowerShell 5.1+
    - ExchangeOnlineManagement module
    - Microsoft.Graph.Identity.SignIns module
    - Exchange Admin or Message Trace role
    - Global Reader or Security Reader role
#>

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement



[CmdletBinding(SupportsShouldProcess)]
param()

# Execution Policy Setup
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}
}

function Test-ScriptDependencies {
    param([string[]]$RequiredModules = @())
    foreach ($Module in $RequiredModules) {
        if ([string]::IsNullOrWhiteSpace($Module)) { continue }
        if (-not (Get-Module -ListAvailable -Name $Module)) {
            Write-Warning "Installing module: $Module"
            Install-Module -Name $Module -Scope CurrentUser -Force -AllowClobber
        }
    }
}

$TranscriptPath = "C:\Temp"
if (-not (Test-Path $TranscriptPath)) { New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null }
$ScriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$TranscriptFile = Join-Path $TranscriptPath "PS-Transcript_$($env:COMPUTERNAME)_$ScriptBaseName`_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($PID).log"
Start-Transcript -Path $TranscriptFile -Force

try {
    Write-Host "Starting $ScriptBaseName (Other)..." -ForegroundColor Green
    Write-Verbose "Transcript logging to: $TranscriptFile"

    Test-ScriptDependencies -RequiredModules @('ExchangeOnlineManagement')

    # CORE SCRIPT LOGIC - REFACTORED FROM ORIGINAL
    <#
    .SYNOPSIS
    Investigates potential Microsoft 365 / Entra ID account compromise alerts by checking
    Message Trace, Sign-in Logs (Interactive & Non-Interactive), and Unified Audit Logs
    for a specified user and time range. Outputs results to text files.

    .DESCRIPTION
    This script performs several checks to help determine the legitimacy of a security alert
    and identify suspicious activity related to a user account:
    1. Runs Exchange Online Message Trace for emails from a potential alert sender to the user.
    2. Retrieves Interactive Sign-in logs for the user within the specified timeframe.
    3. Retrieves Non-Interactive Sign-in logs for the user within the specified timeframe.
    4. Searches the Unified Audit Log for specific security-related activities performed by the user.
    Outputs from Sign-in and Audit logs are saved to formatted text files in a specified directory.
    Timestamps in the output files are converted to Pacific Time (PT).

    .PARAMETER UserUPN
    The User Principal Name (UPN) of the account to investigate.

    .PARAMETER StartDateUTC
    The start date and time (UTC) for the investigation window. Format: "YYYY-MM-DDTHH:MM:SSZ" or a format Get-Date understands.

    .PARAMETER EndDateUTC
    The end date and time (UTC) for the investigation window. Format: "YYYY-MM-DDTHH:MM:SSZ" or a format Get-Date understands.

    .PARAMETER AlertSenderAddress
    (Optional) The email address of the sender of the security alert email (e.g., "account-security-noreply@accountprotection.microsoft.com").
    If provided, a message trace will be run for this sender.

    .PARAMETER OutputDir
    The directory path where the output text files will be saved. Defaults to a subfolder named "AccountInvestigation_Output"
    in the current script execution directory.

    .EXAMPLE
    .\Investigate-M365AccountActivity.ps1 -UserUPN "user@contoso.com" -StartDateUTC "2025-05-01T00:00:00Z" -EndDateUTC "2025-05-03T23:59:59Z" -AlertSenderAddress "account-security-noreply@accountprotection.microsoft.com" -OutputDir "C:\Temp\InvestigationLogs"

    .NOTES
    Author: Brandon Sager
    Version: 1.0
    Requires Administrator privileges with appropriate roles:
    - Exchange Admin or Message Trace role (for Get-MessageTrace)
    - Global Reader or Security Reader (for Get-MgAuditLogSignIn)
    - Audit Logs role in Exchange Online (for Search-UnifiedAuditLog)
    Requires PowerShell Modules:
    - Microsoft.Graph.Identity.Signins (Install-Module Microsoft.Graph.Identity.Signins)
    - ExchangeOnlineManagement (Install-Module ExchangeOnlineManagement)
    Ensure you connect using Connect-MgGraph and Connect-ExchangeOnline before running,
    or uncomment the connection lines within the script. Adjust Graph scopes if needed.
    Risky User/Sign-in checks (Get-MgRiskyUser, Get-MgIdentityProtectionRiskySignIn) are commented out
    as they require Entra ID P2 licenses. Uncomment and ensure Microsoft.Graph.Identity.Protection
    module is installed if P2 license is available.
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$UserUPN,

        [Parameter(Mandatory=$true)]
        [string]$StartDateUTC,

        [Parameter(Mandatory=$true)]
        [string]$EndDateUTC,

        [Parameter(Mandatory=$false)]
        [string]$AlertSenderAddress,

        [Parameter(Mandatory=$false)]
        [string]$OutputDir = ".\AccountInvestigation_Output_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )

    try {
        $startTime = (Get-Date $StartDateUTC).ToUniversalTime()
        $endTime = (Get-Date $EndDateUTC).ToUniversalTime()

        $graphStartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $graphEndTime = $endTime.ToString("yyyy-MM-ddTHH:mm:ssZ")

    $pacificTimeZoneId = "Pacific Standard Time" # Handles PST/PDT automatically

    if (-not (Test-Path -Path $OutputDir)) {
        Write-Host "Creating output directory: $OutputDir"
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $messageTraceFile = Join-Path -Path $OutputDir -ChildPath "MessageTrace_Results.txt"
    $interactiveLogFile = Join-Path -Path $OutputDir -ChildPath "Interactive_SignIns.txt"
    $nonInteractiveLogFile = Join-Path -Path $OutputDir -ChildPath "NonInteractive_SignIns.txt"

    $auditLogFile = Join-Path -Path $OutputDir -ChildPath "UnifiedAuditLog_SecurityEvents.txt"

    Write-Host "Starting investigation for User: $UserUPN" -ForegroundColor Cyan
    Write-Host "Time Range (UTC): $startTime to $endTime" -ForegroundColor Cyan
    Write-Host "Output Directory: $OutputDir" -ForegroundColor Cyan
    Write-Host "Output Timestamps: Pacific Time (PT)" -ForegroundColor Cyan

    if (-not [string]::IsNullOrEmpty($AlertSenderAddress)) {
        Write-Host "`n[1] Running Message Trace for Sender: $AlertSenderAddress, Recipient: $UserUPN..." -ForegroundColor Yellow
        $trace = Get-MessageTrace -SenderAddress $AlertSenderAddress -RecipientAddress $UserUPN -StartDate $startTime -EndDate $endTime -PageSize 100 -ErrorAction Stop
            if ($trace) {
                Write-Host "Message Trace results found. Saving summary to '$messageTraceFile'." -ForegroundColor Green
                ($trace | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageTraceId | Format-Table -AutoSize -Wrap) | Out-File -FilePath $messageTraceFile -Encoding UTF8

                Write-Host "Attempting to get details for the first trace result (MessageTraceId: $($trace[0].MessageTraceId))..."
                Get-MessageTraceDetail -MessageTraceId $trace[0].MessageTraceId -RecipientAddress $UserUPN | Out-File -FilePath $messageTraceFile -Encoding UTF8 -Append
                Write-Host "Trace details appended to '$messageTraceFile'."
            } else {
                Write-Host "No messages found matching the Message Trace criteria in the last 10 days." -ForegroundColor Green
                "No messages found matching Message Trace criteria (Sender: $AlertSenderAddress, Recipient: $UserUPN, Time: $startTime to $endTime)" | Out-File -FilePath $messageTraceFile -Encoding UTF8
            }
    } else {
        Write-Host "`n[1] Message Trace skipped (No AlertSenderAddress provided)." -ForegroundColor Gray
    }

    Write-Host "`n[2] Retrieving Interactive Sign-ins and saving to '$interactiveLogFile'..." -ForegroundColor Yellow
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserUPN' and createdDateTime ge $graphStartTime and createdDateTime le $graphEndTime" -Top 500 -ErrorAction Stop |
            Select-Object @{N='CreatedDateTime (PT)'; E={ [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($_.CreatedDateTime, $pacificTimeZoneId).ToString('yyyy-MM-dd HH:mm:ss') }}, UserPrincipalName, AppDisplayName, IpAddress, @{N='Location';E={$_.Location.City + ", " + $_.Location.State + ", " + $_.Location.CountryOrRegion}}, @{N='DeviceOS';E={$_.DeviceDetail.OperatingSystem}}, Status, ConditionalAccessStatus, RiskState, RiskLevelAggregated, RiskLevelDuringSignIn, @{N='FailureReason'; E={$_.Status.FailureReason}}, AuthenticationRequirement |
            Format-Table -AutoSize -Wrap | Out-File -FilePath $interactiveLogFile -Encoding UTF8
        Write-Host "Interactive Sign-ins saved successfully." -ForegroundColor Green

    Write-Host "`n[3] Retrieving Non-Interactive Sign-ins and saving to '$nonInteractiveLogFile'..." -ForegroundColor Yellow
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserUPN' and createdDateTime ge $graphStartTime and createdDateTime le $graphEndTime" -SignInEventTypes nonInteractive -Top 500 -ErrorAction Stop |
            Select-Object @{N='CreatedDateTime (PT)'; E={ [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($_.CreatedDateTime, $pacificTimeZoneId).ToString('yyyy-MM-dd HH:mm:ss') }}, UserPrincipalName, AppDisplayName, IpAddress, @{N='Location';E={$_.Location.City + ", " + $_.Location.State + ", " + $_.Location.CountryOrRegion}}, Status, ConditionalAccessStatus, RiskState, RiskLevelAggregated, RiskLevelDuringSignIn, @{N='FailureReason'; E={$_.Status.FailureReason}}, AuthenticationRequirement |
            Format-Table -AutoSize -Wrap | Out-File -FilePath $nonInteractiveLogFile -Encoding UTF8
        Write-Host "Non-Interactive Sign-ins saved successfully." -ForegroundColor Green

    Write-Host "`n[5] Checking Unified Audit Log for security-related activities and saving to '$auditLogFile'..." -ForegroundColor Yellow

    $auditOperations = @(
        "PasswordLogonInitialAuthUsingPassword", # Failed login
        "UserLoginFailed", # General login failure
        "PasswordReset", # User password reset (self-service)
        "ResetPassword", # Admin password reset
        "UpdateUser", # User properties changed
        "ChangeUserPassword", # User changed own password
        "Add security info.", # MFA method added/updated
        "Delete security info.", # MFA method deleted
        "Register security information", # MFA registration completed
        "Set-Mailbox", # Mailbox settings changes (forwarding, etc.)
        "New-InboxRule", # Inbox rule creation
        "Set-InboxRule", # Inbox rule modification
        "Enable-InboxRule" # Inbox rule enabled
    )
    Write-Host "Searching for operations: $($auditOperations -join ', ')"
    Search-UnifiedAuditLog -StartDate $startTime -EndDate $endTime -UserIds $UserUPN -Operations $auditOperations -ResultSize 1000 -Formatted -ErrorAction Stop | Out-File -FilePath $auditLogFile -Encoding UTF8
        Write-Host "Audit log search complete. Results saved to '$auditLogFile'." -ForegroundColor Green

    Write-Host "`nInvestigation script finished." -ForegroundColor Cyan
    Write-Host "Review the output files in '$OutputDir' for details."

    } catch {
        Write-Error "Script failed: $_"
        exit 1
    }

    Write-Host "$ScriptBaseName completed successfully" -ForegroundColor Green

} catch {
    Write-Error "$ScriptBaseName failed: $_"
    exit 1
} finally {
    Stop-Transcript
}

