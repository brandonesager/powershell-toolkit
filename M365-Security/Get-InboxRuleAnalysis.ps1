<#
.SYNOPSIS
    Analyzes inbox rules for security threats and generates structured findings

.DESCRIPTION
    Processes inbox rule CSV exports and performs threat analysis to identify
    suspicious patterns such as forwarding, redirection, and hidden deletion rules.
    Outputs findings in OSCP-style CSV format with severity ratings and recommended
    actions. Designed for M365 security assessments and breach investigations.

.PARAMETER CsvPath
    Directory path containing inbox rule CSV exports. Default: C:\Temp\InboxRules

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-InboxRuleAnalysis.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-InboxRuleAnalysis.ps1' -CsvPath 'c:\temp\reports'

.NOTES
    Author: Brandon Sager
    Date: 2025-12-16
    
    Version : 1.0
    
    Requires:
    - PowerShell 5.1+
    - Inbox rule CSV exports from Exchange Online
#>

param(
    [Parameter(HelpMessage = "Directory path containing inbox rule CSV exports")]
    [string]$CsvPath = "C:\Temp\InboxRules"
)

function Analyze-RuleThreat {
    param([PSCustomObject]$Rule, [string]$Mailbox)

    $findings = @()

    # CRITICAL: Email Forwarding/Redirection
    if ($Rule.ForwardTo -and $Rule.ForwardTo -ne "") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "CRITICAL"
            Category = "Email Forwarding"
            Finding = "Rule forwards emails to external address"
            Details = $Rule.ForwardTo
            Action = "Review and verify authorization"
        }
    }

    if ($Rule.RedirectTo -and $Rule.RedirectTo -ne "") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "CRITICAL"
            Category = "Email Redirection"
            Finding = "Rule redirects emails"
            Details = $Rule.RedirectTo
            Action = "Immediately investigate and disable"
        }
    }

    if ($Rule.ForwardAsAttachmentTo -and $Rule.ForwardAsAttachmentTo -ne "") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "CRITICAL"
            Category = "Email Forwarding"
            Finding = "Rule forwards emails as attachments"
            Details = $Rule.ForwardAsAttachmentTo
            Action = "Immediately investigate and disable"
        }
    }

    # HIGH: Suspicious Deletion Without Keywords
    if ($Rule.DeleteMessage -eq "True" -and [string]::IsNullOrEmpty($Rule.SubjectContainsWords) -and [string]::IsNullOrEmpty($Rule.BodyContainsWords)) {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "HIGH"
            Category = "Suspicious Deletion"
            Finding = "Blanket deletion rule without keyword filter"
            Details = "Deletes all emails from: $($Rule.From)"
            Action = "Review sender and deletion scope"
        }
    }

    # HIGH: Soft Delete
    if ($Rule.SoftDeleteMessage -eq "True") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "HIGH"
            Category = "Hidden Deletion"
            Finding = "Soft-delete rule (14-day permanent removal)"
            Details = "Emails removed after 14 days, hidden from standard recovery"
            Action = "Review if intentional"
        }
    }

    # HIGH: Permanent Delete
    if ($Rule.PermanentDelete -eq "True") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "HIGH"
            Category = "Permanent Deletion"
            Finding = "Permanent deletion without recovery"
            Details = "Emails permanently deleted, no recovery option"
            Action = "Investigate reason for rule"
        }
    }

    # MEDIUM: Copy to Folder
    if ($Rule.CopyToFolder -and $Rule.CopyToFolder -ne "") {
        $findings += [PSCustomObject]@{
            Mailbox = $Mailbox
            RuleName = $Rule.Name
            Severity = "MEDIUM"
            Category = "Email Copying"
            Finding = "Rule copies emails to another location"
            Details = "Destination: $($Rule.CopyToFolder)"
            Action = "Verify if authorized"
        }
    }

    return $findings
}

# Load all CSV files from directory
Write-Host "Loading mailbox rules from: $CsvPath" -ForegroundColor Cyan
$csvFiles = Get-ChildItem -Path $CsvPath -Filter "*inbox-rules*.csv" -ErrorAction SilentlyContinue

if (-not $csvFiles) {
    Write-Warning "No inbox rule CSV files found in $CsvPath"
    Write-Host "Expected format: <mailbox>-inbox-rules.csv (e.g., user@contoso.com-inbox-rules.csv)"
    exit 1
}

# Analyze all CSV files
$allFindings = @()
foreach ($csvFile in $csvFiles) {
    # Extract mailbox name from filename (assumes format: mailbox-inbox-rules.csv)
    $mailboxName = $csvFile.BaseName -replace "-inbox-rules$", ""
    Write-Host "  Analyzing: $mailboxName" -ForegroundColor Gray

    $rules = Import-Csv $csvFile.FullName
    foreach ($rule in $rules) {
        $allFindings += Analyze-RuleThreat -Rule $rule -Mailbox $mailboxName
    }
}

# Export to CSV
$allFindings | Export-Csv "$CsvPath\Threat-Assessment-Findings.csv" -NoTypeInformation

# Display summary
Write-Host "`nAnalysis Complete" -ForegroundColor Green
Write-Host "CSV Files Processed: $($csvFiles.Count)"
Write-Host "Findings Detected: $($allFindings.Count)"
Write-Host "`nReport saved to: $CsvPath\Threat-Assessment-Findings.csv"

if ($allFindings.Count -gt 0) {
    Write-Host "`nCRITICAL Issues: $($allFindings | Where-Object Severity -eq "CRITICAL" | Measure-Object).Count" -ForegroundColor Red
    Write-Host "HIGH Issues: $($allFindings | Where-Object Severity -eq "HIGH" | Measure-Object).Count" -ForegroundColor Yellow
    Write-Host "MEDIUM Issues: $($allFindings | Where-Object Severity -eq "MEDIUM" | Measure-Object).Count" -ForegroundColor Cyan
}
