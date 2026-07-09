<#
.SYNOPSIS
    Exchange Online message trace for Meta/Instagram/Facebook emails

.DESCRIPTION
    Searches for Meta platform emails (Instagram, Facebook) to diagnose delivery issues.
    Common use case: Instagram recovery/password reset emails not arriving.

    Meta/Instagram sender domains:
    - facebookmail.com
    - instagram.com
    - mail.instagram.com
    - facebook.com
    - metamail.com

    Instagram recovery senders specifically:
    - security@mail.instagram.com
    - no-reply@mail.instagram.com

.PARAMETER RecipientDomain
    The recipient domain to filter by (e.g., "contoso.com")

.PARAMETER DaysBack
    Number of days to search back (default: 7)

.NOTES
    Requires: Exchange Online PowerShell module (Connect-ExchangeOnline)
    Category: M365-Exchange
.KEYWORDS
    Exchange, email, trace, delivery, diagnose
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RecipientDomain,

    [int]$DaysBack = 7
)

# Connect to Exchange Online if not already connected
if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' })) {
    Write-Host "Please connect to Exchange Online first:" -ForegroundColor Yellow
    Write-Host "  Connect-ExchangeOnline" -ForegroundColor Cyan
    return
}

$startDate = (Get-Date).AddDays(-$DaysBack)
$endDate = Get-Date
$domains = "facebookmail.com","instagram.com","mail.instagram.com","facebook.com","metamail.com"

Write-Host "Searching for Meta/Instagram emails to *@$RecipientDomain (last $DaysBack days)..." -ForegroundColor Cyan

$results = foreach ($d in $domains) {
    Write-Host "  Checking *@$d..." -ForegroundColor Gray
    try {
        Get-MessageTraceV2 -SenderAddress "*@$d" -StartDate $startDate -EndDate $endDate |
            Where-Object { $_.RecipientAddress -like "*@$RecipientDomain" }
    }
    catch {
        Write-Host "  ERROR tracing *@$d: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($results) {
    Write-Host "`nFound $($results.Count) messages:" -ForegroundColor Green
    $results | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status | Format-List

    # Highlight if recovery emails exist
    $recoveryEmails = $results | Where-Object {
        $_.SenderAddress -match 'security@|no-reply@' -and $_.SenderAddress -match 'instagram'
    }

    if ($recoveryEmails) {
        Write-Host "`n[FOUND] Instagram recovery emails:" -ForegroundColor Green
        $recoveryEmails | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status | Format-Table -AutoSize
    } else {
        Write-Host "`n[NOT FOUND] No Instagram recovery emails (security@, no-reply@) in results." -ForegroundColor Yellow
        Write-Host "This suggests Instagram never sent the recovery email, or the account uses a different email." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nNo Meta/Instagram emails found for *@$RecipientDomain in the last $DaysBack days." -ForegroundColor Yellow
}
