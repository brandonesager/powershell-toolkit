#Requires -Version 7.0

<#
.SYNOPSIS
    Connect-MgGraphIdempotent — Idempotent Microsoft Graph connection with scope validation

.DESCRIPTION
    Ensures an active Graph session exists with ALL required scopes. If already
    connected with sufficient scopes, returns immediately (no-op). If connected
    but missing scopes, disconnects and reconnects. If not connected, connects.

    Safe to call multiple times — will never create duplicate sessions or prompt
    unnecessarily.

.PARAMETER Scopes
    Array of Microsoft Graph permission scopes required for the session.
    All scopes must be present or the session will be reconnected.

.PARAMETER NoWelcome
    Suppress the Graph SDK welcome banner. Default: $true.

.EXAMPLE
    .\Connect-MgGraphIdempotent.ps1 -Scopes @('DeviceManagementManagedDevices.Read.All')
    Connects only if not already connected with that scope

.EXAMPLE
    .\Connect-MgGraphIdempotent.ps1 -Scopes @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
    Validates both scopes are present; reconnects if either is missing

.EXAMPLE
    $ctx = .\Connect-MgGraphIdempotent.ps1 -Scopes @('User.Read.All')
    if ($ctx.Reconnected) { Write-Host "Had to reconnect" }
    Check whether a reconnect was needed

.NOTES
    Date: 2026-02-09
    Category: M365-Entra

.KEYWORDS
    Graph, connect, idempotent, session, scope
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Scopes,

    [bool]$NoWelcome = $true
)

$ErrorActionPreference = 'Stop'

$context = Get-MgContext
$reconnected = $false

if ($context) {
    $missing = $Scopes | Where-Object { $_ -notin $context.Scopes }
    if ($missing) {
        Write-Host "Session missing scopes: $($missing -join ', ') — reconnecting..." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        $context = $null
    } else {
        Write-Host "Graph session valid (all $($Scopes.Count) scope(s) present)." -ForegroundColor DarkGray
    }
}

if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    $connectParams = @{ Scopes = $Scopes }
    if ($NoWelcome) { $connectParams['NoWelcome'] = $true }
    Connect-MgGraph @connectParams
    $reconnected = $true
    $context = Get-MgContext
    Write-Host "Connected as $($context.Account) with $($context.Scopes.Count) scope(s)." -ForegroundColor Green
}

[PSCustomObject]@{
    Account     = $context.Account
    TenantId    = $context.TenantId
    Scopes      = $context.Scopes
    Reconnected = $reconnected
}
