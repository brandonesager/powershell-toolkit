<#
.SYNOPSIS
    Get-M365SignInsByCountry - Entra sign-in audit filtered by user and country.

.DESCRIPTION
    Pulls interactive AND non-interactive sign-ins for a target user from the
    Microsoft Graph audit log, then filters client-side to the chosen country
    (default DE / Germany). Splits results into success and failure tables
    and prints a counts summary by app and source IP.

    Captures Entra-native sign-ins AND any NPS Extension for Microsoft Entra
    MFA challenges - those write a non-interactive sign-in record against the
    same UPN when the on-prem RADIUS auth completes, so the geo data appears
    in Entra even though NPS only saw the source IP.

.PARAMETER UserPrincipalName
    UPN of the user to investigate (e.g., jane.doe@contoso.org).

.PARAMETER Country
    ISO 3166-1 alpha-2 country code to filter on. Defaults to 'DE' (Germany).
    Common codes: US, DE, RU, CN, GB, IN, BR.

.PARAMETER Days
    Lookback window in days. Defaults to 30. Entra sign-in log retention is
    30 days without Entra ID P1/P2 + Log Analytics export, so larger values
    will silently return no data older than 30 days.

.EXAMPLE
    .\Get-M365SignInsByCountry.ps1 -UserPrincipalName jane.doe@contoso.org

.EXAMPLE
    .\Get-M365SignInsByCountry.ps1 -UserPrincipalName jane.doe@contoso.org -Country RU -Days 14

.NOTES
    Category: M365-Security
    Context:  Cloud (Microsoft Graph). Assumes active Connect-MgGraph
              session with AuditLog.Read.All and Directory.Read.All scopes.
    Module:   Microsoft.Graph.Reports (v1.0)
    PS:       5.1 or 7

.KEYWORDS
    M365, Entra, sign-in, signin, audit, geo, country, location, Germany,
    breach, investigation, foreign, anomaly, NPS, RADIUS
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$Country = 'DE',

    [Parameter(Mandatory = $false)]
    [int]$Days = 30
)

$ErrorActionPreference = 'Stop'

# Pre-flight: confirm Graph session is live and has the scopes we need.
# Fails fast with a clear message instead of a cryptic API error mid-run.
try {
    $ctx = Get-MgContext -ErrorAction Stop
} catch {
    $ctx = $null
}
if (-not $ctx) {
    Write-Error "No active Microsoft Graph session. Run: Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All'"
    return
}
$required = @('AuditLog.Read.All','Directory.Read.All')
$missing  = $required | Where-Object { $_ -notin $ctx.Scopes }
if ($missing) {
    Write-Warning "Current Graph context is missing scopes: $($missing -join ', '). Reconnect with -Scopes if calls fail."
}

# Build the lookback boundary as UTC ISO-8601. Graph $filter requires UTC.
$From    = (Get-Date).ToUniversalTime().AddDays(-$Days)
$FromIso = $From.ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "========== M365 SIGN-INS BY COUNTRY =========="
Write-Host "User:    $UserPrincipalName"
Write-Host "Country: $Country"
Write-Host "Window:  last $Days days (since $FromIso UTC)"
Write-Host "Tenant:  $($ctx.TenantId)"
Write-Host ""

# Filter strategy: server-side filter on UPN + date range. Country gets
# filtered client-side because Graph $filter on location/countryOrRegion is
# inconsistent across tenants and sometimes requires advanced-query semantics.
$BaseFilter   = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $FromIso"
$NonIntFilter = "$BaseFilter and signInEventTypes/any(t: t eq 'nonInteractiveUser')"

# Advanced query header. Required by Graph for filters on signInEventTypes
# and other complex traversals; harmless when not strictly required.
$AdvancedHeaders = @{ ConsistencyLevel = 'eventual' }

Write-Host "Querying interactive sign-ins..."
# v1.0 Get-MgAuditLogSignIn returns interactive sign-ins by default when no
# signInEventTypes filter is specified.
$Interactive = @(Get-MgAuditLogSignIn -Filter $BaseFilter -All -Headers $AdvancedHeaders -ErrorAction Stop)

Write-Host "Querying non-interactive sign-ins..."
# Explicit signInEventTypes filter required for non-interactive (e.g., token
# refresh, NPS Extension MFA challenges, service principal background auth).
$NonInteractive = @(Get-MgAuditLogSignIn -Filter $NonIntFilter -All -Headers $AdvancedHeaders -ErrorAction Stop)

# Dedupe on Id in case Graph returns the same record under both queries
# (rare but possible during result-set boundary edge cases).
$All = @($Interactive) + @($NonInteractive) |
       Sort-Object Id -Unique |
       Sort-Object CreatedDateTime -Descending

Write-Host "  Interactive:     $($Interactive.Count)"
Write-Host "  Non-Interactive: $($NonInteractive.Count)"
Write-Host "  Combined unique: $($All.Count)"
Write-Host ""

# Country match is case-insensitive ISO code comparison against Location.CountryOrRegion.
# Variable named $Hits to avoid the PowerShell automatic variable $Hits
# which the -match operator populates.
$Hits = $All | Where-Object {
    $_.Location -and $_.Location.CountryOrRegion -eq $Country
}

if (-not $Hits -or $Hits.Count -eq 0) {
    Write-Host "No sign-ins from $Country in the last $Days days for $UserPrincipalName."
    Write-Host ""
    # Surface what countries WERE seen so the analyst can quickly retarget
    # without re-running the script.
    Write-Host "Countries observed in window:"
    $All | Group-Object { $_.Location.CountryOrRegion } |
        Sort-Object Count -Descending |
        ForEach-Object { Write-Host ("  {0,-30} {1}" -f ($_.Name -or '<null>'), $_.Count) }
    return
}

# ErrorCode 0 = success. Any non-zero ErrorCode is a failure, including
# Conditional Access blocks (50053, 53003, etc.) and MFA failures (50074, 50158).
$Success = $Hits | Where-Object { $_.Status.ErrorCode -eq 0 }
$Failure = $Hits | Where-Object { $_.Status.ErrorCode -ne 0 }

Write-Host "========== SUMMARY =========="
Write-Host ("Matches from {0}: {1}" -f $Country, $Hits.Count)
Write-Host ("  Success: {0}" -f $Success.Count)
Write-Host ("  Failure: {0}" -f $Failure.Count)
Write-Host ""
Write-Host "By app:"
$Hits | Group-Object AppDisplayName |
    Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("  {0,-40} {1}" -f $_.Name, $_.Count) }
Write-Host ""
Write-Host "By source IP:"
$Hits | Group-Object IpAddress |
    Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_.Name, $_.Count) }
Write-Host ""

# Flatten the rich SignIn object into a printable row. Pulled into a helper
# so the table columns are defined once and reused for both Success and Failure.
function Format-Row($s) {
    [pscustomobject]@{
        TimeUTC   = ([datetime]$s.CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss")
        App       = $s.AppDisplayName
        EventType = ($s.SignInEventTypes -join ',')
        IP        = $s.IpAddress
        City      = $s.Location.City
        State     = $s.Location.State
        Country   = $s.Location.CountryOrRegion
        Status    = if ($s.Status.ErrorCode -eq 0) { 'Success' } else { 'Failure' }
        ErrorCode = $s.Status.ErrorCode
        Reason    = $s.Status.FailureReason
        CA        = $s.ConditionalAccessStatus
        AuthReq   = $s.AuthenticationRequirement
        Client    = $s.ClientAppUsed
        Device    = $s.DeviceDetail.OperatingSystem
        Browser   = $s.DeviceDetail.Browser
    }
}

if ($Success.Count -gt 0) {
    Write-Host "========== SUCCESS ($($Success.Count)) =========="
    $Success | ForEach-Object { Format-Row $_ } | Format-Table -AutoSize
    Write-Host ""
}

if ($Failure.Count -gt 0) {
    Write-Host "========== FAILURE ($($Failure.Count)) =========="
    $Failure | ForEach-Object { Format-Row $_ } | Format-Table -AutoSize
    Write-Host ""
}

Write-Host "========== END =========="
