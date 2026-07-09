<#
.SYNOPSIS
    Reports primary and archive mailbox quota usage for an Exchange Online mailbox.

.DESCRIPTION
    Handles deserialized ByteQuantifiedSize objects returned by Exchange Online remote sessions.
    Standard .Value.ToBytes() and division operators fail on deserialized types — this script
    uses regex to extract the raw byte count from the string representation and strips commas.

.PARAMETER Identity
    UPN or alias of the mailbox.

.EXAMPLE
    .\Get-MailboxQuotaStatus.ps1 -Identity jsmith

.NOTES
    Requires active Exchange Online session (Connect-ExchangeOnline).
    Compatible with PS 5.1 and PS 7+.
#>

param(
    [Parameter(Mandatory)]
    [string]$Identity
)

$mailbox   = Get-Mailbox -Identity $Identity
$stats     = Get-MailboxStatistics -Identity $Identity
$archStats = Get-MailboxStatistics -Identity $Identity -Archive

# Parse bytes from string — handles commas in large numbers (e.g., "53,150,220,288 bytes")
$primaryQuotaBytes = [long](($mailbox.ProhibitSendQuota -replace '.*\(([\d,]+) bytes\).*','$1') -replace ',','')
$primaryUsedBytes  = [long](($stats.TotalItemSize        -replace '.*\(([\d,]+) bytes\).*','$1') -replace ',','')
$archiveQuotaBytes = [long](($mailbox.ArchiveQuota       -replace '.*\(([\d,]+) bytes\).*','$1') -replace ',','')
$archiveUsedBytes  = [long](($archStats.TotalItemSize    -replace '.*\(([\d,]+) bytes\).*','$1') -replace ',','')

[PSCustomObject]@{
    DisplayName        = $mailbox.DisplayName
    PrimaryQuotaGB     = [math]::Round($primaryQuotaBytes / 1GB, 2)
    PrimaryUsedGB      = [math]::Round($primaryUsedBytes  / 1GB, 2)
    PrimaryAvailableGB = [math]::Round(($primaryQuotaBytes - $primaryUsedBytes)  / 1GB, 2)
    PrimaryUsedPct     = [math]::Round($primaryUsedBytes  / $primaryQuotaBytes * 100, 1)
    ArchiveQuotaGB     = [math]::Round($archiveQuotaBytes / 1GB, 2)
    ArchiveUsedGB      = [math]::Round($archiveUsedBytes  / 1GB, 2)
    ArchiveAvailableGB = [math]::Round(($archiveQuotaBytes - $archiveUsedBytes)  / 1GB, 2)
    ArchiveUsedPct     = [math]::Round($archiveUsedBytes  / $archiveQuotaBytes * 100, 1)
}
