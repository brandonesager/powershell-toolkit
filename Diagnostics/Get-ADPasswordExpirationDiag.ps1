<#
.SYNOPSIS
    Diagnose AD user password expiration root cause.

.DESCRIPTION
    Determines whether a user's password expires under the Default Domain Policy or a
    Fine-Grained Password Policy (PSO). Checks UAC flags, forced-change status, lockout,
    and calculates exact expiration date.

    Run on a Domain Controller or server with RSAT (ActiveDirectory module) installed.
    Context: SYSTEM or admin
    Platform: Windows PowerShell 5.1

.PARAMETER SamAccountName
    Target user's SamAccountName. If omitted or not found, script searches by SearchTerm.

.PARAMETER SearchTerm
    Fallback display name search term when SamAccountName is unknown. Default: empty (no search).

.PARAMETER DomainController
    Optional: target a specific DC. Defaults to the DC the script runs on.

.EXAMPLE
    .\Get-ADPasswordExpirationDiag.ps1 -SamAccountName "jsmith"
    Diagnoses password state for user jsmith.

.EXAMPLE
    .\Get-ADPasswordExpirationDiag.ps1 -SearchTerm "Christine"
    Searches for users matching 'Christine' and diagnoses if exactly one match found.

.EXAMPLE
    .\Get-ADPasswordExpirationDiag.ps1
    Runs with no arguments — requires SearchTerm to be set or will error.

.NOTES
    RMM Deployment: Exit 0 = Success or multi-match disambiguation, Exit 1 = Failure
    Output: PSCustomObject on Write-Output for RMM variable capture
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$SamAccountName,

    [Parameter(Mandatory = $false)]
    [string]$SearchTerm,

    [Parameter(Mandatory = $false)]
    [string]$DomainController
)

$ErrorActionPreference = 'Stop'

# UAC bitmask constants
$UAC_DONT_EXPIRE   = 0x10000
$UAC_SMARTCARD     = 0x40000
$UAC_DISABLED      = 0x2
$UAC_PWD_NOTREQD   = 0x20
$UAC_PWD_CANTCHANGE = 0x40

$ADParams = @{}
if ($DomainController) { $ADParams['Server'] = $DomainController }

$PropertiesToGet = @(
    'PasswordLastSet','PasswordNeverExpires','LockedOut','UserAccountControl',
    'msDS-ResultantPSO','Enabled','DisplayName','Title'
)

try {
    Write-Host "============================================================"
    Write-Host "[START] AD Password Expiration Diagnosis"
    Write-Host "[INFO] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "[INFO] Computer: $env:COMPUTERNAME"
    Write-Host "============================================================"

    # Load AD module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "ERROR: ActiveDirectory module not available. Run on a DC with RSAT installed."
        exit 1
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[OK] ActiveDirectory module loaded"

    # --- User Resolution ---
    $User = $null

    if (-not [string]::IsNullOrWhiteSpace($SamAccountName)) {
        Write-Host "[DIAG] Attempting direct lookup: $SamAccountName"
        try {
            $User = Get-ADUser -Identity $SamAccountName -Properties $PropertiesToGet @ADParams
            Write-Host "[OK] User resolved: $($User.SamAccountName) ($($User.DisplayName))"
        } catch {
            Write-Host "[WARN] Direct lookup failed for '$SamAccountName' — falling back to search"
        }
    }

    if ($null -eq $User -and -not [string]::IsNullOrWhiteSpace($SearchTerm)) {
        Write-Host "[DISCOVERY] Searching for users matching '$SearchTerm'..."
        $candidates = Get-ADUser -Filter "Name -like '*$SearchTerm*' -or DisplayName -like '*$SearchTerm*' -or GivenName -like '*$SearchTerm*'" `
            -Properties $PropertiesToGet @ADParams

        if (-not $candidates) {
            Write-Output "ERROR: No users found matching '$SearchTerm'."
            exit 1
        }

        $candidateList = @($candidates)
        if ($candidateList.Count -gt 1) {
            Write-Host "============================================================"
            Write-Host "[MULTIPLE USERS FOUND] Re-run with -SamAccountName"
            Write-Host "============================================================"
            $candidateList | Select-Object SamAccountName, DisplayName, Enabled, PasswordLastSet, Title |
                Format-Table -AutoSize | Out-String | Write-Host
            Write-Output "MULTIPLE_MATCHES: Found $($candidateList.Count) users matching '$SearchTerm'. Re-run with specific -SamAccountName."
            exit 0
        }

        $User = $candidateList[0]
        Write-Host "[DISCOVERY] Single match — auto-selecting: $($User.SamAccountName)"
    }

    if ($null -eq $User) {
        Write-Output "ERROR: No SamAccountName or SearchTerm provided, or no match found."
        exit 1
    }

    # --- UAC Flag Parsing ---
    $uac = $User.UserAccountControl
    $pwdNeverExpires  = ($uac -band $UAC_DONT_EXPIRE) -ne 0
    $smartCardReqd    = ($uac -band $UAC_SMARTCARD) -ne 0
    $accountEnabled   = ($uac -band $UAC_DISABLED) -eq 0
    $pwdNotRequired   = ($uac -band $UAC_PWD_NOTREQD) -ne 0
    $pwdCantChange    = ($uac -band $UAC_PWD_CANTCHANGE) -ne 0
    $forcedChangeFlag = ($null -eq $User.PasswordLastSet)
    $lockedOut        = $User.LockedOut

    Write-Host "[DIAG] UAC flags — NeverExpires:$pwdNeverExpires SmartCard:$smartCardReqd ForcedChange:$forcedChangeFlag LockedOut:$lockedOut"

    # --- Policy Detection ---
    $psoName   = $null
    $maxAgeDays = 0

    $resultantPSO = $User.'msDS-ResultantPSO'
    if ($resultantPSO) {
        Write-Host "[DIAG] Fine-Grained Password Policy applies: $resultantPSO"
        $psoObj    = Get-ADFineGrainedPasswordPolicy -Identity $resultantPSO @ADParams
        $psoName   = $psoObj.Name
        $maxAgeDays = [Math]::Abs($psoObj.MaxPasswordAge.Days)
        $policySource = $psoName
    } else {
        Write-Host "[DIAG] No PSO — using Default Domain Policy"
        $domain    = Get-ADDomain @ADParams
        $domainObj = Get-ADObject $domain.DistinguishedName -Properties maxPwdAge @ADParams
        $maxAgeTicks = $domainObj.maxPwdAge
        if ($maxAgeTicks -ne 0) {
            $maxAgeDays = [TimeSpan]::FromTicks([Math]::Abs($maxAgeTicks)).Days
        }
        $policySource = 'Default Domain Policy'
    }

    Write-Host "[DIAG] Effective MaxPasswordAge: $maxAgeDays days (Source: $policySource)"

    # --- Expiration Calculation ---
    $expirationDate  = $null
    $daysUntilExpire = $null
    $isExpired       = $false

    if ($pwdNeverExpires -or $maxAgeDays -eq 0) {
        Write-Host "[DIAG] Password never expires (flag or policy age=0)"
    } elseif ($forcedChangeFlag) {
        Write-Host "[DIAG] Forced change at next logon (pwdLastSet=0)"
        $isExpired = $true
    } else {
        $expirationDate  = $User.PasswordLastSet.AddDays($maxAgeDays)
        $daysUntilExpire = [int]($expirationDate - (Get-Date)).TotalDays
        $isExpired       = $daysUntilExpire -lt 0
        Write-Host "[DIAG] Expiration: $expirationDate ($daysUntilExpire days)"
    }

    # --- Output Object ---
    $result = [PSCustomObject]@{
        User               = $User.SamAccountName
        DisplayName        = $User.DisplayName
        PolicySource       = $policySource
        PasswordLastSet    = $User.PasswordLastSet
        MaxPasswordAge     = $maxAgeDays
        ExpirationDate     = $expirationDate
        DaysUntilExpire    = $daysUntilExpire
        IsExpired          = $isExpired
        ForcedChangeFlag   = $forcedChangeFlag
        LockedOut          = $lockedOut
        PasswordNeverExpires = $pwdNeverExpires
        SmartCardRequired  = $smartCardReqd
        AccountEnabled     = $accountEnabled
        PasswordNotRequired = $pwdNotRequired
        PasswordCantChange = $pwdCantChange
    }

    Write-Host "============================================================"
    Write-Host "[COMPLETE] Diagnosis finished"
    Write-Host "============================================================"
    Write-Output $result
    exit 0

} catch {
    Write-Host "============================================================"
    Write-Host "[ERROR] Script execution failed"
    Write-Host "[ERROR] Message: $($_.Exception.Message)"
    Write-Host "[ERROR] Line: $($_.InvocationInfo.ScriptLineNumber)"
    Write-Host "[ERROR] Command: $($_.InvocationInfo.Line.Trim())"
    Write-Host "============================================================"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
