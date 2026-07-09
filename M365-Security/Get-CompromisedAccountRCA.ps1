<#
.SYNOPSIS
    Root-cause analysis pull for a potentially compromised M365 account.
.DESCRIPTION
    Read-only. Gathers all signals needed to determine why an account was flagged
    or placed on the restricted senders list after a credential reset or session
    revoke. Pulls sign-in logs, Identity Protection risk detections, risky user
    state, OAuth grants, message trace, unified audit log, inbox rules, forwarding
    state, and blocked sender status. Writes a timestamped transcript to
    04-artifacts and echoes the output path on exit.
    Requires live Connect-ExchangeOnline and Connect-MgGraph sessions (GDAP or
    direct tenant connection) before running.
.PARAMETER UserPrincipalName
    UPN of the account under investigation (e.g. user@domain.com).
.PARAMETER FlaggedTraceId
    MessageTraceId of the specific message that triggered the restriction, if known.
    Leave blank to skip Section 8.
.PARAMETER FlaggedClientIP
    Suspicious IP address to query in the sign-in log filter, if known.
    Leave blank to skip Section 3.
.PARAMETER ArtifactDir
    Directory to write the transcript. Defaults to the script's parent's 04-artifacts
    subfolder, creating it if needed. Falls back to $env:TEMP.
.PARAMETER HoursBack
    How many hours back to search sign-in logs and message trace. Default 12.
.NOTES
    Category: M365-Security
    PS 5.1 compatible.
    Run context: Local PS with live Exchange Online and Microsoft Graph sessions.
.KEYWORDS
    compromised, breach, restricted senders, RCA, sign-in, risk detection, inbox rules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$FlaggedTraceId = '',

    [Parameter(Mandatory = $false)]
    [string]$FlaggedClientIP = '',

    [Parameter(Mandatory = $false)]
    [string]$ArtifactDir = '',

    [Parameter(Mandatory = $false)]
    [int]$HoursBack = 12
)

# Resolve artifact directory
if (-not $ArtifactDir) {
    $scriptParent = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ArtifactDir  = Join-Path $scriptParent '04-artifacts'
}
if (-not (Test-Path $ArtifactDir)) {
    try { New-Item -ItemType Directory -Path $ArtifactDir -Force | Out-Null }
    catch { $ArtifactDir = $env:TEMP }
}

$slug    = ($UserPrincipalName -replace '[^a-zA-Z0-9]', '-').ToLower()
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$outFile = Join-Path $ArtifactDir "compromised-rca-$slug-$stamp.log"
Start-Transcript -Path $outFile -IncludeInvocationHeader | Out-Null

$startWindow = (Get-Date).AddHours(-$HoursBack)
$endWindow   = Get-Date

function Section($title) { "`n`n===== $title =====" }

Section '1. User baseline'
try {
    Get-MgUser -UserId $UserPrincipalName `
        -Property Id,UserPrincipalName,DisplayName,AccountEnabled,SignInSessionsValidFromDateTime,LastPasswordChangeDateTime `
        -ErrorAction Stop |
        Format-List Id,UserPrincipalName,DisplayName,AccountEnabled,SignInSessionsValidFromDateTime,LastPasswordChangeDateTime
} catch {
    "Get-MgUser FAILED: $($_.Exception.Message)"
}

Section "2. Sign-ins last $HoursBack hours (every auth attempt, IP, app, success/fail)"
try {
    $isoStart = $startWindow.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $isoStart"
    Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop |
        Sort-Object CreatedDateTime |
        Select-Object CreatedDateTime,
                      @{n='IP';e={$_.IpAddress}},
                      @{n='App';e={$_.AppDisplayName}},
                      @{n='Client';e={$_.ClientAppUsed}},
                      @{n='Status';e={if($_.Status.ErrorCode -eq 0){'Success'}else{"Fail ($($_.Status.ErrorCode))"}}},
                      @{n='Location';e={"$($_.Location.City), $($_.Location.CountryOrRegion)"}},
                      @{n='RiskState';e={$_.RiskState}},
                      @{n='RiskLevelDuringSignIn';e={$_.RiskLevelDuringSignIn}} |
        Format-Table -AutoSize -Wrap
} catch {
    "Get-MgAuditLogSignIn FAILED: $($_.Exception.Message)"
}

if ($FlaggedClientIP) {
    Section "3. Sign-ins matching flagged IP $FlaggedClientIP (anywhere in last 30 days)"
    try {
        $filter = "userPrincipalName eq '$UserPrincipalName' and ipAddress eq '$FlaggedClientIP'"
        Get-MgAuditLogSignIn -Filter $filter -Top 50 -ErrorAction Stop |
            Sort-Object CreatedDateTime |
            Select-Object CreatedDateTime,AppDisplayName,ClientAppUsed,
                          @{n='Status';e={if($_.Status.ErrorCode -eq 0){'Success'}else{"Fail ($($_.Status.ErrorCode))"}}},
                          @{n='Location';e={"$($_.Location.City), $($_.Location.CountryOrRegion)"}} |
            Format-Table -AutoSize -Wrap
    } catch {
        "Get-MgAuditLogSignIn (IP filter) FAILED: $($_.Exception.Message)"
    }
} else {
    "Section 3 skipped: no -FlaggedClientIP provided."
}

Section '4. Identity Protection risk detections (last 7 days)'
try {
    Get-MgIdentityProtectionRiskDetection -Filter "userPrincipalName eq '$UserPrincipalName'" -Top 50 -ErrorAction Stop |
        Sort-Object DetectedDateTime |
        Select-Object DetectedDateTime,RiskEventType,RiskLevel,RiskState,IpAddress,
                      @{n='Location';e={"$($_.Location.City), $($_.Location.CountryOrRegion)"}},
                      Source,Activity |
        Format-Table -AutoSize -Wrap
} catch {
    "Get-MgIdentityProtectionRiskDetection FAILED: $($_.Exception.Message)"
}

Section '5. Risky user status'
try {
    Get-MgRiskyUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop |
        Format-List RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime,IsDeleted,IsProcessing
} catch {
    "Get-MgRiskyUser FAILED: $($_.Exception.Message)"
}

Section '6. OAuth permission grants (persistence check)'
try {
    $grants = Get-MgUserOauth2PermissionGrant -UserId $UserPrincipalName -All -ErrorAction Stop
    if (-not $grants) {
        'No delegated OAuth grants on this principal.'
    } else {
        $grants | ForEach-Object {
            $sp = try { Get-MgServicePrincipal -ServicePrincipalId $_.ClientId -ErrorAction Stop } catch { $null }
            [pscustomobject]@{
                AppDisplayName = $sp.DisplayName
                AppId          = $sp.AppId
                PublisherName  = $sp.PublisherName
                Scopes         = $_.Scope
                ConsentType    = $_.ConsentType
                ResourceId     = $_.ResourceId
            }
        } | Format-Table -AutoSize -Wrap
    }
} catch {
    "Get-MgUserOauth2PermissionGrant FAILED: $($_.Exception.Message)"
}

Section "7. Outbound message trace last $HoursBack hours"
try {
    Get-MessageTrace -SenderAddress $UserPrincipalName -StartDate $startWindow -EndDate $endWindow `
        -PageSize 1000 -ErrorAction Stop |
        Sort-Object Received |
        Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,FromIP,Size,MessageId,MessageTraceId |
        Format-Table -AutoSize -Wrap
} catch {
    "Get-MessageTrace FAILED: $($_.Exception.Message)"
}

if ($FlaggedTraceId) {
    Section "8. Detail on flagged MessageTraceId $FlaggedTraceId"
    try {
        $flaggedTrace = Get-MessageTrace -MessageTraceId $FlaggedTraceId -SenderAddress $UserPrincipalName `
            -StartDate $startWindow.AddHours(-$HoursBack) -EndDate $endWindow -ErrorAction Stop
        if ($flaggedTrace) {
            $flaggedTrace | Format-List Received,SenderAddress,RecipientAddress,Subject,Status,FromIP,ToIP,Size,MessageId
            foreach ($t in $flaggedTrace) {
                "`n--- Detail events for recipient $($t.RecipientAddress) ---"
                try {
                    Get-MessageTraceDetail -MessageTraceId $t.MessageTraceId -RecipientAddress $t.RecipientAddress `
                        -ErrorAction Stop |
                        Sort-Object Date | Select-Object Date,Event,Action,Detail | Format-Table -AutoSize -Wrap
                } catch { "Get-MessageTraceDetail FAILED: $($_.Exception.Message)" }
            }
        } else {
            'No trace returned for the flagged MessageTraceId in the search window.'
        }
    } catch {
        "Get-MessageTrace (flagged ID) FAILED: $($_.Exception.Message)"
    }
} else {
    "Section 8 skipped: no -FlaggedTraceId provided."
}

Section '9. Mailbox audit log: actions today (Send, SendAs, rule creation, etc.)'
try {
    Search-UnifiedAuditLog -StartDate $startWindow -EndDate $endWindow `
        -UserIds $UserPrincipalName -ResultSize 500 -ErrorAction Stop |
        Sort-Object CreationDate |
        Select-Object CreationDate,UserIds,Operations,ClientIP,
                      @{n='ResultStatus';e={($_.AuditData | ConvertFrom-Json -ErrorAction SilentlyContinue).ResultStatus}} |
        Format-Table -AutoSize -Wrap
} catch {
    "Search-UnifiedAuditLog FAILED: $($_.Exception.Message)"
}

Section '10. Current inbox rules (check for attacker-planted rules)'
try {
    $rules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop
    if (-not $rules) {
        'No inbox rules.'
    } else {
        $rules | Select-Object Name,Enabled,Priority,Description,RedirectTo,ForwardTo,ForwardAsAttachmentTo,DeleteMessage,MoveToFolder |
            Format-List
    }
} catch {
    "Get-InboxRule FAILED: $($_.Exception.Message)"
}

Section '11. Current forwarding state'
try {
    Get-Mailbox -Identity $UserPrincipalName |
        Select-Object DisplayName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward | Format-List
} catch {
    "Get-Mailbox FAILED: $($_.Exception.Message)"
}

Section '12. Restricted senders list (final state)'
try {
    $state = Get-BlockedSenderAddress |
        Where-Object { $_.SenderAddress -eq $UserPrincipalName.ToUpper() -or $_.SenderAddress -eq $UserPrincipalName }
    if ($state) {
        $state | Format-List SenderAddress,Reason,CreatedDatetime,ChangedDatetime
    } else {
        'Confirmed: not on restricted senders list.'
    }
} catch {
    "Get-BlockedSenderAddress FAILED: $($_.Exception.Message)"
}

Stop-Transcript | Out-Null
"`nOutput: $outFile"
