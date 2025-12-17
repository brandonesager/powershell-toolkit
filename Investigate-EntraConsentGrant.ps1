<#
.SYNOPSIS
    Investigates a specific 'Consent to application' event from Microsoft Entra ID audit logs
    to determine if it was an illicit grant.

.DESCRIPTION
    This script is designed for security administrators to investigate a potential illicit consent
    grant attack. It correlates the consent event with user sign-in activity, enriches the IP
    address with geolocation data, and retrieves exhaustive details about the application and
    service principal involved. All output is logged to a transcript file.
    
    Core Actions:
    1. Sets up logging to C:\temp\eventscompromise.txt.
    2. Checks for, installs, and imports the required Microsoft.Graph PowerShell modules.
    3. Connects to Microsoft Graph after checking if the running admin has sufficient permissions.
    4. Finds the exact sign-in log that matches the consent event's Correlation ID.
    5. Retrieves geolocation data for the IP address found in the sign-in log.
    6. Gathers details about the registered Application and the local Service Principal.
    7. Provides a dynamic summary and recommended remediation steps.

.PARAMETER UserPrincipalName
    Specifies the user principal name.

.PARAMETER CorrelationId
    Specifies the correlation id.

.PARAMETER AppId
    Specifies the app id.

.PARAMETER ServicePrincipalId
    Specifies the service principal id.

.PARAMETER EventTimestamp
    Specifies the event timestamp timestamp.

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Investigate-EntraConsentGrant.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Investigate-EntraConsentGrant.ps1' -UserPrincipalName 'user@domain.com' -CorrelationId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -AppId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

.NOTES
    Author: Brandon Sager
    Date: 12/26/2025
    
    Version:     1.3 (Error Corrected)
    Requires:    PowerShell 7+ and the Microsoft.Graph module.
    Permissions: The script will request the following MS Graph delegated permissions:
    - AuditLog.Read.All
    - Application.Read.All
    - User.Read.All
    - Directory.Read.All
#>

#region Parameters from Audit Log
Param(
    [Parameter(Mandatory=$true, HelpMessage="Enter the User Principal Name of the user who consented.")]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the Correlation ID from the audit log event.")]
    [string]$CorrelationId,

    [Parameter(Mandatory=$true, HelpMessage="Enter the AppId of the enterprise application.")]
    [string]$AppId,

    [Parameter(Mandatory=$true, HelpMessage="Enter the Object ID (Id) of the Service Principal.")]
    [string]$ServicePrincipalId,

    [Parameter(Mandatory=$true, HelpMessage="Enter the timestamp of the consent event (e.g., '7/7/2025 1:01 AM').")]
    [datetime]$EventTimestamp
)
#endregion

#region Setup and Prerequisite Checks
# --- Start Logging ---
$logPath = "C:\temp"
if (-not (Test-Path -Path $logPath)) {
    Write-Host "Creating log directory at $logPath..."
    New-Item -ItemType Directory -Path $logPath -ErrorAction SilentlyContinue | Out-Null
}
$logFile = Join-Path -Path $logPath -ChildPath "eventscompromise.txt"
Start-Transcript -Path $logFile -Append
Write-Host "--- Script Started: $(Get-Date) ---"
Write-Host "--- All output will be logged to $logFile ---"

# --- Module Installation and Import ---
Function Confirm-ModuleAvailability {
    param([string]$ModuleName, [string[]]$SubModules)

    Write-Host "`n--- Step 1: Checking for PowerShell Module: $ModuleName ---" -ForegroundColor Cyan
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module '$ModuleName' is not found. Attempting to install..." -ForegroundColor Yellow
        try {
            Install-Module $ModuleName -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
            Write-Host "Module '$ModuleName' installed successfully." -ForegroundColor Green
        } catch {
            Write-Error "Failed to install module '$ModuleName'. Please install it manually and re-run the script. Error: $($_.Exception.Message)"
            Stop-Transcript; exit
        }
    } else {
        Write-Host "Module '$ModuleName' is already installed." -ForegroundColor Green
    }
    foreach ($sub in $SubModules) { try { Import-Module $sub -ErrorAction Stop; Write-Host "Successfully loaded module: $sub" } catch { Write-Warning "Could not load submodule '$sub'." } }
}

$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns", "Microsoft.Graph.Applications", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.DirectoryManagement")
Confirm-ModuleAvailability -ModuleName "Microsoft.Graph" -SubModules $requiredModules

# --- Connect to Microsoft Graph ---
try {
    Write-Host "`nConnecting to Microsoft Graph..."
    $scopes = @("AuditLog.Read.All", "Application.Read.All", "User.Read.All", "Directory.Read.All")
    Connect-MgGraph -Scopes $scopes
    $adminContext = Get-MgContext
    Write-Host "Successfully connected. Running as:" $adminContext.Account -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph. Please ensure you have permissions. Error: $($_.Exception.Message)"
    Stop-Transcript; exit
}
#endregion

#region Admin Role Check
Function Test-AdminRole {
    Write-Host "`n--- Step 2: Verifying Administrator Roles ---" -ForegroundColor Cyan
    $recommendedRoles = @("Global Administrator", "Security Administrator", "Global Reader", "Security Reader")    
    try {
        # **FIXED**: Correctly iterate through role objects to get the displayName value.
        $userRoles = (Get-MgUserMemberOf -UserId $adminContext.Account -All).AdditionalProperties | Where-Object { $_.'@odata.type' -like '*directoryRole' } | ForEach-Object { $_.displayName }

        if ($userRoles) {
            Write-Host "Your assigned roles: $($userRoles -join ', ')"
            $match = $userRoles | Where-Object { $recommendedRoles -contains $_ }
            if ($match) {
                Write-Host "Sufficient permissions detected ('$($match | Select-Object -First 1)'). Proceeding..." -ForegroundColor Green
            } else {
                Write-Host "Could not detect a standard recommended role. If using custom roles, the script may still work." -ForegroundColor Yellow
            }
        } else { Write-Host "No directory roles found. Commands may fail due to insufficient permissions." -ForegroundColor Yellow }
    } catch { Write-Warning "Could not verify admin roles. This may be a permissions issue. Error: $($_.Exception.Message)" }
}
Test-AdminRole
#endregion

#region Investigation
# Initialize variables to avoid errors in the final summary
$signInDetails = $null; $geoResponse = $null; $appDetails = $null; $spDetails = $null; $ipAddress = $null; $app = $null; $sp = $null;

Write-Host "`n--- Step 3: Fetching Correlated Sign-in Event ---" -ForegroundColor Cyan
Write-Host "Searching for sign-in with Correlation ID: $CorrelationId"
try {
    $signInEvent = Get-MgAuditLogSignIn -Filter "correlationId eq '$CorrelationId'" -Top 1
    if ($signInEvent) {
        Write-Host "SUCCESS: Found the sign-in event that triggered the consent." -ForegroundColor Green
        $ipAddress = $signInEvent.IpAddress
        $signInDetails = [PSCustomObject]@{
            'Event Timestamp' = $signInEvent.CreatedDateTime
            'User' = $signInEvent.UserPrincipalName
            'IPAddress' = $ipAddress
            'Location' = "$($signInEvent.Location.City), $($signInEvent.Location.State), $($signInEvent.Location.CountryOrRegion)"
            'Device OS' = $signInEvent.DeviceDetail.OperatingSystem
            'Browser' = $signInEvent.DeviceDetail.Browser
            'ClientApp' = $signInEvent.ClientAppUsed
            'Authentication Method' = ($signInEvent.AuthenticationDetails.AuthenticationMethod -join ', ')
            'MFA Result' = $signInEvent.Status.AdditionalDetails
            'AppConsentedTo' = $signInEvent.AppDisplayName
        }
        $signInDetails | Format-List
    } else {
        Write-Warning "Could not find a sign-in event with that Correlation ID. This can happen with certain internal service flows."
        Write-Host "Searching for other sign-ins for '$UserPrincipalName' around the event time as a fallback..."  
        $startTime = $EventTimestamp.AddMinutes(-10).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endTime = $EventTimestamp.AddMinutes(10).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $filterString = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startTime and createdDateTime le $endTime"
        # **FIXED**: Changed -SortBy to -OrderBy and added 'desc' for correct sorting.
        $recentSignIns = Get-MgAuditLogSignIn -Filter $filterString -OrderBy "createdDateTime desc"
        if ($recentSignIns) {
            Write-Host "Found $($recentSignIns.Count) sign-in(s) for the user within a 20-minute window of the event:" -ForegroundColor Yellow
            $recentSignIns | Select-Object CreatedDateTime, IpAddress, @{N='Location';E={"$($_.Location.City), $($_.Location.CountryOrRegion)"}}, ClientAppUsed, AppDisplayName | Format-Table
            $ipAddress = ($recentSignIns | Select-Object -First 1).IpAddress
            Write-Host "Using IP Address '$ipAddress' from the most recent fallback sign-in for enrichment."       
        } else { Write-Warning "No recent sign-ins found for the user in that time window." }
    }
} catch { Write-Error "Failed to retrieve sign-in logs. Error: $($_.Exception.Message)" }

# --- Geolocation Analysis ---
if ($ipAddress) {
    Write-Host "`n--- Step 4: Fetching Geolocation Data for IP Address: $ipAddress ---" -ForegroundColor Cyan      
    try {
        $geoResponse = Invoke-RestMethod -Uri "http://ip-api.com/json/$ipAddress"
        $geoResponse | Format-List
    } catch { Write-Warning "Could not retrieve geolocation data for the IP. Error: $($_.Exception.Message)" }     
}

# --- Application and Service Principal Analysis ---
Write-Host "`n--- Step 5: Analyzing Application and Service Principal ---" -ForegroundColor Cyan
try {
    Write-Host "`n[5a] Fetching App Registration details (AppId: $AppId)..."
    # This command checks for an App Registration in YOUR tenant. It is expected to fail for third-party multi-tenant apps.
    $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    if ($app) {
        Write-Host "Found App Registration in local tenant." -ForegroundColor Green
        $appDetails = [PSCustomObject]@{
            'DisplayName' = $app.DisplayName
            'Created Date (UTC)' = $app.CreatedDateTime
            'Publisher Domain' = $app.PublisherDomain
            'Verified Publisher' = if ($app.VerifiedPublisher.DisplayName) { "$($app.VerifiedPublisher.DisplayName) (VERIFIED)" } else { "NO - This is a red flag" }
            'Sign-In Audience' = $app.SignInAudience
            'Homepage URL' = $app.Web.HomepageUrl
            'Redirect URLs' = $app.Web.RedirectUris -join ', '
        }
        $appDetails | Format-List
    } else { Write-Warning "IMPORTANT: App Registration not found in this tenant. This indicates it is a multi-tenant app registered elsewhere." }

    Write-Host "`n[5b] Fetching Service Principal details (Object ID: $ServicePrincipalId)..."
    $sp = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId
    if ($sp) {
        $spOwner = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id | Select-Object -ExpandProperty AdditionalProperties
        $spDetails = [PSCustomObject]@{
            'SP DisplayName' = $sp.DisplayName
            'SP Enabled' = $sp.AccountEnabled
            'Owned By' = if ($spOwner.userPrincipalName) { $spOwner.userPrincipalName } else { "Not owned by a user" }
            'Service Principal Type' = $sp.ServicePrincipalType
            'Tags' = $sp.Tags -join ', '
        }
        $spDetails | Format-List
    } else { Write-Warning "Could not find a Service Principal with ID: $ServicePrincipalId."}
} catch { Write-Error "Failed to analyze app/service principal. Error: $($_.Exception.Message)" }
#endregion

#region Conclusion and Recommendations
Write-Host "`n--- Step 6: Investigation Summary & Recommended Actions ---" -ForegroundColor Green
# **ENHANCED**: The summary now handles cases where the App Registration isn't found locally.
$appName = if ($appDetails.DisplayName) { $appDetails.DisplayName } else { $spDetails.'SP DisplayName' }
$appCreated = if ($appDetails.'Created Date (UTC)') { $appDetails.'Created Date (UTC)' } else { "N/A (External App)" }
$appPublisher = if ($appDetails.'Verified Publisher') { $appDetails.'Verified Publisher' } else { "N/A (External App)" }
$appHomepage = if ($appDetails.'Homepage URL') { $appDetails.'Homepage URL' } else { "N/A (External App)" }        

Write-Host "
RECOMMENDATION: Review the data above for indicators of compromise. Take action if suspicious.

CHECKLIST FOR ILLICIT CONSENT:
[ ] Sign-in Location: Is the IP/Country unusual for this user? Is it from a Hosting provider?
    - User Location: $($signInDetails.Location)
    - IP Details: ISP '$($geoResponse.isp)', Hosting: '$($geoResponse.hosting)'

[ ] Application Age: Was the application created very recently? (Malicious apps are often short-lived).
    - Created Date: $appCreated

[ ] Publisher Verification: Is the publisher UNVERIFIED? This is a major red flag for non-internal apps.
    - Status: $appPublisher

[ ] Application Details: Do the App Name, Homepage, or Redirect URLs look generic or suspicious?
    - Name: $appName
    - Homepage: $appHomepage

IMMEDIATE REMEDIATION STEPS IF SUSPICIOUS:
1. Disable the Application: Prevents the app from getting new tokens.
   - Go to 'Microsoft Entra admin center -> Identity -> Applications -> Enterprise applications'.
   - Search for AppID '$AppId' or Display Name '$appName'.
   - Go to 'Properties' and set 'Enabled for users to sign-in?' to 'No'.

2. Revoke Permissions: Removes the consent grant.
   - In the same Enterprise App, go to the 'Permissions' tab.
   - Click the 'Review admin consent' or 'Review permissions' button.
   - In the 'Delegated Permissions' list, find this grant and revoke it.

3. Secure the User Account: The user account may be compromised.
   - Initiate a secure password reset for the user '$UserPrincipalName'.
   - Revoke all of the user's active sessions in the Microsoft Entra user blade.
   - Review MFA methods on the account for any unauthorized changes.

4. Harden Tenant Settings: Prevent this from happening again.
   - Navigate to 'Enterprise applications -> Consent and permissions'.
   - Consider setting 'User consent for applications' to 'Do not allow user consent'.
   - Enable the 'Admin consent request workflow' so users can request access to legitimate apps.
"
#endregion

# --- End Logging ---
Write-Host "`n--- Script Finished: $(Get-Date) ---"
Stop-Transcript
Write-Host "Investigation transcript saved to $logFile" -ForegroundColor Green
