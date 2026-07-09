<#
.SYNOPSIS
    Get-NPSRadiusByUser - NPS RADIUS auth events for a target user.

.DESCRIPTION
    Runs on a Windows Network Policy Server. Reads Security log NPS events
    (6272 granted, 6273 denied, 6274 discarded, 6278 quarantine-granted,
    6279 locked, 6280 unlocked) for the target user and outputs source IP,
    NAS info, network policy hit, and reason-code decoding.

    No outbound calls. Country/geo is not present in the NPS event payload.
    For geolocation, cross-reference the Calling-Station-Id (source IP)
    against the Entra sign-in log via Get-M365SignInsByCountry.ps1 - any
    NPS Extension for Microsoft Entra MFA flow writes a non-interactive
    Entra sign-in record with full city/country for the same user.

    Event ID and audit-policy references:
      - https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-network-policy-server
      - https://learn.microsoft.com/troubleshoot/windows-client/networking/802-1x-authentication-issues-troubleshooting

.PARAMETER User
    Target user. Accepts SamAccountName, UPN, or DOMAIN\user. Matched
    case-insensitive against SubjectUserName and FullyQualifiedSubjectUserName.

.PARAMETER Days
    Lookback window in days. Defaults to 30. Bound by actual Security log
    retention on the NPS server.

.PARAMETER FilterIP
    Optional. Only return events where Calling-Station-Id matches this string
    (partial match supported). Useful when you have a suspect IP from the
    Entra log and want to confirm RADIUS-side activity for it.

.EXAMPLE
    .\Get-NPSRadiusByUser.ps1 -User jane.doe

.EXAMPLE
    .\Get-NPSRadiusByUser.ps1 -User CONTOSO\jane.doe -Days 14

.EXAMPLE
    .\Get-NPSRadiusByUser.ps1 -User jane.doe -FilterIP "185.220."

.NOTES
    Category: Diagnostics
    Context:  Run on the NPS server (the box that holds the IAS/NPS role).
              Local Admin required to read the Security log.
    PS:       5.1

.KEYWORDS
    NPS, RADIUS, IAS, 6272, 6273, 6274, 6278, VPN, WiFi, 802.1x, auth
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$User,

    [Parameter(Mandatory = $false)]
    [int]$Days = 30,

    [Parameter(Mandatory = $false)]
    [string]$FilterIP
)

$ErrorActionPreference = 'Stop'

# IAS/NPS reason-code lookup. Codes Microsoft documents most often; the
# fallback path uses the rendered Reason text from the event itself when a
# code is not in this table.
$ReasonCodes = @{
    '0'   = 'Success'
    '8'   = 'The specified user account does not exist'
    '16'  = 'Authentication failed (bad credentials, expired password, or disabled)'
    '17'  = 'Change password failed'
    '21'  = 'No matching network policy'
    '22'  = 'Dial-in property locked out the account'
    '23'  = 'Dial-in property disabled the account'
    '36'  = 'Account locked out (bad password lockout)'
    '48'  = 'No connection request policy matched'
    '49'  = 'Invalid request'
    '53'  = 'Local users only restriction blocked the account'
    '65'  = 'Authentication type not allowed by network policy'
    '66'  = 'Calling-Station-Id rejected by network policy'
    '262' = 'Server certificate not trusted by the client'
    '263' = 'Server certificate chain invalid'
    '265' = 'Client certificate not trusted by the server'
    '295' = 'Global catalog unavailable'
    '296' = 'Domain controller unavailable'
    '300' = 'EAP type not configured'
    '301' = 'EAP negotiation failure'
}

# NPS events expose their detail through the EventData/Data XML nodes.
# Building a hashtable of Name -> #text means we can index by the familiar
# field name (SubjectUserName, CallingStationID, etc.) instead of walking XML.
function Get-EventData {
    param($Evt)
    $data = @{}
    $xml = [xml]$Evt.ToXml()
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }
    $data
}

# Match the user across the three NPS user-name fields. Accepts samAccountName,
# UPN, or DOMAIN\user; falls through to substring match so callers do not have
# to remember which form NPS logged for this RADIUS client.
function Test-UserMatch {
    param($Data, [string]$Target)
    $tLow = $Target.Trim().ToLower()
    foreach ($key in 'SubjectUserName','FullyQualifiedSubjectUserName','TargetUserName') {
        $v = $Data[$key]
        if ($v) {
            $vLow = ([string]$v).ToLower()
            if ($vLow -eq $tLow)               { return $true }
            if ($vLow.EndsWith("\$tLow"))      { return $true }
            if ($vLow.StartsWith("$tLow@"))    { return $true }
            if ($vLow.Contains($tLow))         { return $true }
        }
    }
    return $false
}

Write-Host "========== NPS RADIUS BY USER =========="
Write-Host "Server:  $env:COMPUTERNAME"
Write-Host "User:    $User"
Write-Host "Window:  last $Days days"
if ($FilterIP) { Write-Host "IPFilter: $FilterIP" }
Write-Host ""

# Pre-flight: verify NPS auditing subcategory is enabled. Without it, the
# Security log silently lacks 6272-6280 events and the analyst will think
# the user had no RADIUS activity when really the audit policy is off.
# Reference: troubleshoot-network-policy-server, Step 1.
try {
    $auditpol = & auditpol /get /subcategory:"Network Policy Server" 2>$null
    $auditLine = ($auditpol | Where-Object { $_ -match 'Network Policy Server' })
    if ($auditLine -and $auditLine -notmatch 'Success and Failure|Failure|Success') {
        Write-Warning "NPS audit subcategory is not enabled. Run as admin:"
        Write-Warning '  auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable'
    }
} catch {
    # auditpol unavailable (non-server SKU or restricted env). Continue regardless.
    Write-Verbose "auditpol pre-flight skipped: $($_.Exception.Message)"
}

$StartTime = (Get-Date).AddDays(-$Days)

# Server-side filter via FilterHashtable is much faster than Get-WinEvent | Where.
# Get-WinEvent throws a terminating error when zero events match, even with
# -ErrorAction SilentlyContinue, so we catch the "No events were found"
# variant explicitly and surface a helpful next step.
try {
    $Raw = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 6272,6273,6274,6278,6279,6280
        StartTime = $StartTime
    } -ErrorAction Stop
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No NPS auth events found on this server in the last $Days days."
        Write-Host "Confirm this is the NPS server and that NPS auditing is enabled:"
        Write-Host "  auditpol /get /subcategory:""Network Policy Server"""
        return
    }
    throw
}

Write-Host "Total NPS events in window (all users): $($Raw.Count)"

$Rows = foreach ($e in $Raw) {
    $d = Get-EventData -Evt $e
    if (-not (Test-UserMatch -Data $d -Target $User)) { continue }
    if ($FilterIP -and -not (($d['CallingStationID']) -like "*$FilterIP*")) { continue }

    # Resolve reason text: prefer the documented code table, then the
    # rendered Reason string from the event payload, finally blank.
    $reasonCode = $d['ReasonCode']
    $reasonText = if ($reasonCode -and $ReasonCodes.ContainsKey($reasonCode)) {
        $ReasonCodes[$reasonCode]
    } elseif ($d['Reason']) {
        $d['Reason']
    } else { '' }

    # Map raw event ID to a human-readable outcome. 6278 is granted with
    # quarantine constraints; treat as granted but flag the variant in output.
    $outcome = switch ($e.Id) {
        6272 { 'Granted' }
        6273 { 'Denied' }
        6274 { 'Discarded' }
        6278 { 'Granted (Quarantine)' }
        6279 { 'Account Locked' }
        6280 { 'Account Unlocked' }
        default { "Event $($e.Id)" }
    }

    [pscustomobject]@{
        TimeLocal     = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventId       = $e.Id
        Outcome       = $outcome
        User          = $d['SubjectUserName']
        FQUser        = $d['FullyQualifiedSubjectUserName']
        SourceIP      = $d['CallingStationID']
        NASIdent      = $d['NASIdentifier']
        NASIP         = $d['NASIPAddress']
        NASPortType   = $d['NASPortType']
        Client        = $d['ClientName']
        ClientIP      = $d['ClientIPAddress']
        ConnPolicy    = $d['ProxyPolicyName']
        NetworkPolicy = $d['NetworkPolicyName']
        AuthType      = $d['AuthenticationType']
        EAPType       = $d['EAPType']
        ReasonCode    = $reasonCode
        Reason        = $reasonText
    }
}

# Force array semantics so .Count works when 0 or 1 rows survived the filter.
$Rows = @($Rows)

if ($Rows.Count -eq 0) {
    Write-Host "No NPS events matched user '$User' in the last $Days days."
    Write-Host ""
    # When there's no match, show the analyst the users that DID hit NPS in
    # the window. Quick way to spot typos in the -User argument.
    Write-Host "Distinct users seen in window (top 20):"
    $Raw | ForEach-Object { (Get-EventData -Evt $_)['SubjectUserName'] } |
        Where-Object { $_ } |
        Group-Object |
        Sort-Object Count -Descending |
        Select-Object -First 20 |
        ForEach-Object { Write-Host ("  {0,-40} {1}" -f $_.Name, $_.Count) }
    return
}

$Success = $Rows | Where-Object { $_.EventId -in 6272,6278 }
$Failure = $Rows | Where-Object { $_.EventId -in 6273,6274 }
$Lockout = $Rows | Where-Object { $_.EventId -in 6279,6280 }

Write-Host ""
Write-Host "========== SUMMARY =========="
Write-Host ("Matches for {0}: {1}" -f $User, $Rows.Count)
Write-Host ("  Granted:  {0}" -f $Success.Count)
Write-Host ("  Denied:   {0}" -f ($Failure | Where-Object EventId -eq 6273).Count)
Write-Host ("  Discarded:{0}" -f ($Failure | Where-Object EventId -eq 6274).Count)
Write-Host ("  Lockout:  {0}" -f $Lockout.Count)
Write-Host ""
Write-Host "By source IP (Calling-Station-Id):"
$Rows | Group-Object SourceIP |
    Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("  {0,-30} {1}" -f ($_.Name -or '<empty>'), $_.Count) }
Write-Host ""
Write-Host "By network policy:"
$Rows | Group-Object NetworkPolicy |
    Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("  {0,-40} {1}" -f ($_.Name -or '<empty>'), $_.Count) }
Write-Host ""

if ($Success.Count -gt 0) {
    Write-Host "========== GRANTED ($($Success.Count)) =========="
    $Success | Format-Table TimeLocal,Outcome,SourceIP,NASIdent,NetworkPolicy,AuthType,EAPType -AutoSize
    Write-Host ""
}

if ($Failure.Count -gt 0) {
    Write-Host "========== DENIED / DISCARDED ($($Failure.Count)) =========="
    $Failure | Format-Table TimeLocal,Outcome,SourceIP,NASIdent,NetworkPolicy,AuthType,ReasonCode,Reason -AutoSize
    Write-Host ""
}

if ($Lockout.Count -gt 0) {
    Write-Host "========== LOCKOUT EVENTS ($($Lockout.Count)) =========="
    $Lockout | Format-Table TimeLocal,Outcome,User,SourceIP -AutoSize
    Write-Host ""
}

Write-Host "========== NEXT STEPS =========="
Write-Host "1. Take any non-internal SourceIP value above and run:"
Write-Host "   Get-M365SignInsByCountry.ps1 -UserPrincipalName <upn>"
Write-Host "   The Entra sign-in record for the matching NPS-Extension MFA"
Write-Host "   challenge carries city/country for that IP."
Write-Host "2. If no Entra match for a suspect IP, the IP may be on-prem"
Write-Host "   (corporate WiFi/VPN concentrator). Resolve against the site's"
Write-Host "   network documentation."
Write-Host "========== END =========="
