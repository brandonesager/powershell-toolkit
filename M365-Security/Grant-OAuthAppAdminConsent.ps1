<#
.SYNOPSIS
    Grant admin consent for third-party OAuth apps in M365 tenant.
.DESCRIPTION
    When a tenant's user consent policy blocks third-party OAuth apps,
    this script grants admin consent for the required delegated permissions.

    Handles:
      1. Checks the current user consent policy
      2. Searches for app in Enterprise Applications
      3. Grants admin consent for delegated permissions
      4. Verifies the consent grant

    Common use case: Fireflies.ai, Otter.ai, CRM integrations, AI assistants
    blocked by "microsoft-user-default-recommended" consent policy.
.NOTES
    Run interactively as Global Admin in PS 7 with Microsoft.Graph module.
    If app isn't registered yet, use browser-based admin consent flow instead
    (see Step 3B).
#>

#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications

# ──────────────────────────────────────────────
# STEP 1: Connect to Microsoft Graph
# ──────────────────────────────────────────────
# Scopes needed: read auth policy, manage apps, grant consent
Connect-MgGraph -Scopes @(
    "Policy.Read.All",
    "Application.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Directory.ReadWrite.All"
)

# Verify connection
Get-MgContext | Select-Object Account, TenantId

# ──────────────────────────────────────────────
# STEP 2: Check current user consent policy
# ──────────────────────────────────────────────
$authPolicy = Get-MgPolicyAuthorizationPolicy
$authPolicy.DefaultUserRolePermissions | Format-List PermissionGrantPoliciesAssigned

# Expected output interpretation:
#   Empty or "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
#     → Users CAN consent (not our scenario)
#   "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"
#     → Users can consent to verified publishers only
#   Nothing assigned / restrictive policy
#     → Users CANNOT consent

# ──────────────────────────────────────────────
# STEP 3: Search for app in Enterprise Apps
# ──────────────────────────────────────────────
# Adjust display name filter for your app
$appDisplayName = "Fireflies"
$appSP = Get-MgServicePrincipal -Filter "displayName eq '$appDisplayName'" -All
if (-not $appSP) {
    $appSP = Get-MgServicePrincipal -Filter "startswith(displayName, '$appDisplayName')" -All
}

if ($appSP) {
    Write-Host "Found service principal:" -ForegroundColor Green
    $appSP | Select-Object DisplayName, AppId, Id
} else {
    Write-Host "App NOT found in Enterprise Apps — will register after OAuth flow." -ForegroundColor Yellow
    Write-Host "Proceed to Step 3B below." -ForegroundColor Yellow
}

# ──────────────────────────────────────────────
# STEP 3B: If not found — trigger admin consent via URL
# ──────────────────────────────────────────────
# If the app isn't registered yet, the fastest method is the admin consent URL.
# This requires the app's Application (client) ID.
#
# Option A: Look up the app ID from a test OAuth flow
#   - Go to the app's login page and start sign-in with Microsoft
#   - On the consent/error screen, the URL contains client_id=<APP_ID>
#   - Copy that value and use it below
#
# Option B: If you already have the app ID, uncomment and run:

# $appId = "<PASTE_APP_CLIENT_ID_HERE>"
# $tenantId = (Get-MgContext).TenantId
# $adminConsentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$appId"
# Write-Host "Open this URL in a browser as Global Admin:" -ForegroundColor Cyan
# Write-Host $adminConsentUrl

# After approving via URL, re-run the search:
# $appSP = Get-MgServicePrincipal -Filter "startswith(displayName, '$appDisplayName')" -All
# $appSP | Select-Object DisplayName, AppId, Id

# ──────────────────────────────────────────────
# STEP 4: Grant admin consent (once service principal exists)
# ──────────────────────────────────────────────
# After the app is registered (via Step 3 or 3B), grant admin consent
# for the delegated permissions it needs.

if ($appSP) {
    # Get the Microsoft Graph service principal (resource)
    $graphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -All

    # Check existing consent grants
    $existingGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($appSP.Id)'" -All
    if ($existingGrants) {
        Write-Host "Existing consent grants:" -ForegroundColor Cyan
        $existingGrants | Select-Object ClientId, ResourceId, Scope, ConsentType
    }

    # Grant admin consent for required scopes
    # Adjust Scope to match the app's requirements
    $params = @{
        ClientId    = $appSP.Id
        ConsentType = "AllPrincipals"           # Admin consent for all users
        ResourceId  = $graphSP.Id               # Microsoft Graph
        Scope       = "Calendars.Read Mail.Read User.Read openid profile email"
    }
    New-MgOauth2PermissionGrant -BodyParameter $params

    Write-Host "Admin consent granted" -ForegroundColor Green
}

# ──────────────────────────────────────────────
# STEP 5: Verify
# ──────────────────────────────────────────────
# Confirm the consent grant exists
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($appSP.Id)'" -All |
    Select-Object ClientId, ConsentType, Scope

# Check that app now appears in Enterprise Apps
Get-MgServicePrincipal -Filter "startswith(displayName, '$appDisplayName')" |
    Select-Object DisplayName, AppId, AccountEnabled

# ──────────────────────────────────────────────
# STEP 6: Cleanup — disconnect
# ──────────────────────────────────────────────
# Disconnect-MgGraph
