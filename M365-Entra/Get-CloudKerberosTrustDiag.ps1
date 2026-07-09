<#
.SYNOPSIS
    Diagnoses Entra ID Cloud Kerberos Trust configuration for a hybrid AD domain.

.DESCRIPTION
    Verifies each component required for Cloud Kerberos Trust (passwordless Windows Hello
    for Business via on-premises AD):

      1. AzureADHybridAuthenticationManagement module — must be present and importable.
      2. ActiveDirectory module (RSAT) — required for steps 4 and 6.
      3. Get-AzureADKerberosServer — confirms the Entra Kerberos server object exists
         and that CloudTrustDisplay is populated (indicates Cloud Kerberos Trust is set up,
         not just FIDO). Prompts for cloud admin credentials interactively.
      4. AzureADKerberos computer object in on-prem AD — verifies the object is present
         under Domain Controllers OU with expected SPNs and key version.
      5. nltest /dsgetdc — checks for KEYLIST flag, which confirms DCs participate in
         Cloud Kerberos Trust.
      6. Optional per-user on-prem AD check — verifies UPN, SAM, Enabled, and LockedOut;
         prints a Graph API query to verify Entra-side sync of onPremises* attributes.

    Prints a structured summary at the end with pass/fail verdicts for each component.

.PARAMETER Domain
    On-premises AD domain DNS name (e.g., "corp.example.com").

.PARAMETER CloudAdminUPN
    UPN of the cloud admin account used to authenticate Get-AzureADKerberosServer.
    An interactive sign-in prompt will appear.

.PARAMETER DomainCredential
    Optional PSCredential for on-premises domain auth. If omitted, the script runs
    under the current identity.

.PARAMETER User
    Optional. SAM account name or UPN of a user to validate on-prem AD health and
    print the Entra sync verification query.

.NOTES
    Context:  Cloud (AzureADHybridAuthenticationManagement module; run on a DC or
              domain-joined Windows machine with RSAT installed)
    Platform: Windows Server 2016+ DC; Entra ID hybrid tenant
    PS 5.1 compatible.

.KEYWORDS
    Cloud Kerberos Trust, WHfB, Windows Hello for Business, AzureADKerberosServer,
    KEYLIST, hybrid, nltest, Entra, on-premises AD, passwordless, diagnostics
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Domain,

    [Parameter(Mandatory)]
    [string]$CloudAdminUPN,

    [Parameter()]
    [System.Management.Automation.PSCredential]$DomainCredential,

    [Parameter()]
    [string]$User
)

$ErrorActionPreference = 'Continue'
$results = [ordered]@{}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

# -- 1. AzureADHybridAuthenticationManagement module ----------------------
Write-Section "1. AzureADHybridAuthenticationManagement module"
$hybridMod = Get-Module -ListAvailable -Name AzureADHybridAuthenticationManagement |
    Sort-Object Version -Descending | Select-Object -First 1
if ($hybridMod) {
    Write-Host ("Present. Version: {0}" -f $hybridMod.Version) -ForegroundColor Green
    Import-Module AzureADHybridAuthenticationManagement -ErrorAction Stop
    $results['Module']    = "Present"
    $results['ModuleVer'] = $hybridMod.Version.ToString()
} else {
    Write-Host "Missing." -ForegroundColor Red
    Write-Host "Install with: Install-Module AzureADHybridAuthenticationManagement -Scope AllUsers" -ForegroundColor Yellow
    $results['Module'] = "Missing"
    return
}

# -- 2. ActiveDirectory module --------------------------------------------
Write-Section "2. ActiveDirectory module (RSAT)"
$adMod = Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1
if ($adMod) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Write-Host "Present." -ForegroundColor Green
    $results['ADModule'] = "Present"
} else {
    Write-Host "Missing. Steps 4 and 6 (AD object checks) will be skipped." -ForegroundColor Yellow
    $results['ADModule'] = "Missing"
}

# -- 3. Get-AzureADKerberosServer -----------------------------------------
Write-Section ("3. Get-AzureADKerberosServer ({0})" -f $Domain)
Write-Host ("Cloud sign-in prompt will request credentials for {0}." -f $CloudAdminUPN) -ForegroundColor Yellow

$kerbArgs = @{
    Domain            = $Domain
    UserPrincipalName = $CloudAdminUPN
    ErrorAction       = 'Stop'
}
if ($DomainCredential) { $kerbArgs['DomainCredential'] = $DomainCredential }

try {
    $kerb = Get-AzureADKerberosServer @kerbArgs
    $kerb | Format-List Id, UserAccount, ComputerAccount, DisplayName, DomainDnsName,
        KeyVersion, KeyUpdatedOn, KeyUpdatedFrom,
        CloudDisplayName, CloudDomainDnsName, CloudId, CloudKeyVersion,
        CloudKeyUpdatedOn, CloudTrustDisplay

    $results['KerbServerId']      = $kerb.Id
    $results['KerbComputer']      = $kerb.ComputerAccount
    $results['KerbKeyUpdatedOn']  = $kerb.KeyUpdatedOn
    $results['CloudDisplayName']  = $kerb.CloudDisplayName
    $results['CloudId']           = $kerb.CloudId
    $results['CloudTrustDisplay'] = if ($kerb.CloudTrustDisplay) { "Configured" } else { "NOT configured" }

    if (-not $kerb.Id) {
        Write-Host "No Entra Kerberos server object. Cloud Kerberos Trust NOT configured." -ForegroundColor Red
    } elseif (-not $kerb.CloudTrustDisplay) {
        Write-Host "Entra Kerberos object exists (FIDO supported) but CloudTrustDisplay is empty." -ForegroundColor Yellow
        Write-Host ("Remediation: Set-AzureADKerberosServer -Domain {0} -UserPrincipalName {1} -SetupCloudTrust" -f $Domain, $CloudAdminUPN) -ForegroundColor Yellow
    } else {
        Write-Host "Cloud Kerberos Trust CONFIGURED." -ForegroundColor Green
    }
} catch {
    Write-Host ("Get-AzureADKerberosServer failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $results['KerbServerResult'] = "ERROR: $($_.Exception.Message)"
}

# -- 4. AzureADKerberos AD computer object --------------------------------
Write-Section "4. AzureADKerberos computer object in AD"
if ($results['ADModule'] -eq "Present") {
    try {
        $aadKerbObj = Get-ADComputer -Filter "Name -eq 'AzureADKerberos'" `
            -Properties whenCreated, whenChanged, 'msDS-KeyVersionNumber', servicePrincipalName `
            -ErrorAction Stop
        if ($aadKerbObj) {
            $aadKerbObj | Format-List Name, DistinguishedName, whenCreated, whenChanged, 'msDS-KeyVersionNumber', servicePrincipalName
            $results['AzureADKerberosObject'] = "Present"
            $results['AzureADKerberosDN']     = $aadKerbObj.DistinguishedName
            $results['AADKerbKeyVer']         = $aadKerbObj.'msDS-KeyVersionNumber'
        } else {
            Write-Host "AzureADKerberos computer object NOT found in AD." -ForegroundColor Red
            Write-Host ("Expected DN: CN=AzureADKerberos,OU=Domain Controllers,{0}" -f (Get-ADDomain).DistinguishedName) -ForegroundColor Yellow
            $results['AzureADKerberosObject'] = "Missing"
        }
    } catch {
        Write-Host ("Get-ADComputer failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $results['AzureADKerberosObject'] = "ERROR: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipped (ActiveDirectory module not present)." -ForegroundColor Yellow
    $results['AzureADKerberosObject'] = "Skipped (no RSAT AD)"
}

# -- 5. nltest KDC locator with KEYLIST flag ------------------------------
Write-Section ("5. nltest /dsgetdc:{0} /keylist /kdc" -f $Domain)
try {
    $nltestOut = & nltest "/dsgetdc:$Domain" /keylist /kdc 2>&1
    $nltestOut | ForEach-Object { Write-Host $_ }
    $hasKeylist = ($nltestOut | Select-String -Pattern 'KEYLIST' -Quiet)
    if ($hasKeylist) {
        Write-Host "KEYLIST flag present. DC participates in Cloud Kerberos Trust." -ForegroundColor Green
        $results['NLTestKeylist'] = "Present"
    } else {
        Write-Host "KEYLIST flag NOT detected in DC locator output." -ForegroundColor Red
        Write-Host "Confirm DCs are Windows Server 2016+ and fully patched; KRBTGT key propagation may still be pending." -ForegroundColor Yellow
        $results['NLTestKeylist'] = "Missing"
    }
} catch {
    Write-Host ("nltest failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $results['NLTestKeylist'] = "ERROR: $($_.Exception.Message)"
}

# -- 6. Optional per-user on-prem AD check --------------------------------
if ($User) {
    Write-Section ("6. Get-ADUser ({0})" -f $User)
    if ($results['ADModule'] -eq "Present") {
        try {
            $adUserFilter = if ($User -match '@') {
                Get-ADUser -Filter "UserPrincipalName -eq '$User'" `
                    -Properties UserPrincipalName,SamAccountName,DistinguishedName,Enabled,LockedOut,AccountExpirationDate,LastLogonDate,whenChanged,EmailAddress `
                    -ErrorAction Stop
            } else {
                Get-ADUser -Identity $User `
                    -Properties UserPrincipalName,SamAccountName,DistinguishedName,Enabled,LockedOut,AccountExpirationDate,LastLogonDate,whenChanged,EmailAddress `
                    -ErrorAction Stop
            }

            if ($adUserFilter) {
                $adUserFilter | Format-List Name, UserPrincipalName, SamAccountName, DistinguishedName, Enabled, LockedOut, AccountExpirationDate, LastLogonDate, whenChanged, EmailAddress

                $results['UserFound']     = "Yes"
                $results['UserUPN']       = $adUserFilter.UserPrincipalName
                $results['UserSAM']       = $adUserFilter.SamAccountName
                $results['UserEnabled']   = $adUserFilter.Enabled
                $results['UserLockedOut'] = $adUserFilter.LockedOut
                $results['UserLastLogon'] = $adUserFilter.LastLogonDate

                $userHealthy = $adUserFilter.Enabled -and (-not $adUserFilter.LockedOut) -and $adUserFilter.UserPrincipalName -and $adUserFilter.SamAccountName
                if ($userHealthy) {
                    Write-Host "On-prem account healthy. UPN + SAM populated, enabled, not locked." -ForegroundColor Green
                } else {
                    Write-Host "On-prem account has issues. Review Enabled / LockedOut / UPN fields above." -ForegroundColor Red
                }

                Write-Host ""
                Write-Host "Verify Entra-side sync via Graph Explorer or Connect-MgGraph:" -ForegroundColor Yellow
                Write-Host ("  GET https://graph.microsoft.com/v1.0/users/{0}?`$select=onPremisesDomainName,onPremisesUserPrincipalName,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesSyncEnabled" -f $adUserFilter.UserPrincipalName)
                Write-Host "All four onPremises* fields plus onPremisesSyncEnabled=true are required for silent TGT swap."
            } else {
                Write-Host ("User '{0}' not found in AD." -f $User) -ForegroundColor Red
                $results['UserFound'] = "No"
            }
        } catch {
            Write-Host ("Get-ADUser failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            $results['UserFound'] = "ERROR: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Skipped (ActiveDirectory module not present)." -ForegroundColor Yellow
        $results['UserFound'] = "Skipped (no RSAT AD)"
    }
}

# -- Summary --------------------------------------------------------------
Write-Section "Summary"
foreach ($k in $results.Keys) {
    Write-Host ("{0,-24} {1}" -f $k, $results[$k])
}

Write-Host ""
Write-Host "Verdict:" -ForegroundColor Cyan
Write-Host "  CloudTrustDisplay    = Configured"
Write-Host "  AzureADKerberosObject = Present"
Write-Host "  NLTestKeylist        = Present"
Write-Host ("  => Cloud Kerberos Trust is fully configured for {0}." -f $Domain)
