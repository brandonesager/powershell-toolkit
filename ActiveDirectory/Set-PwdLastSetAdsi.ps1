<#
.SYNOPSIS
    ADSI two-step pwdLastSet touch (set 0 then -1) for accounts where
    Set-ADUser -Replace @{pwdLastSet=-1} silently fails.

.DESCRIPTION
    When Set-ADUser -Replace @{pwdLastSet=-1} exits without error but the
    PasswordLastSet attribute does not update (a known behavioral difference in
    some AD schema versions and PS module builds), the ADSI interface reliably
    performs the same operation:
      Step 1: Put("pwdLastSet", 0)  - clears the value (forces must-change)
      Step 2: Put("pwdLastSet", -1) - sets to current time (normal active state)

    The -1 write instructs the DC to replace the value with the current timestamp.
    Without Step 1, some DCs silently skip the -1 write if pwdLastSet is not 0 first.

    Read-only Get-ADUser before and after confirms the change.

.PARAMETER UserDN
    Full Distinguished Name of the account to touch.
    Example: "CN=Jane Smith,OU=Users,DC=corp,DC=local"

.PARAMETER SamAccountName
    SamAccountName for the before/after Get-ADUser verification reads.
    If empty, DN leaf (CN value) is used as a fallback.

.NOTES
    Created: 2026-05-29
    Category: ActiveDirectory
    Context: RMM shell (SYSTEM, PS 5.1) - requires AD connectivity from the host

.KEYWORDS
    pwdLastSet, PasswordLastSet, ADSI, Set-ADUser, password expiry, reset, timestamp
#>
#!ps
#maxlength=100000
#timeout=120000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$UserDN,

    [string]$SamAccountName = ''
)

$ErrorActionPreference = 'Stop'

Write-Output "Set-PwdLastSetAdsi"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("UserDN    : {0}" -f $UserDN)
Write-Output ""

# Resolve SamAccountName from DN if not provided
if (-not $SamAccountName) {
    $SamAccountName = ($UserDN -split ',')[0] -replace '^CN=',''
    Write-Output ("SamAccountName: {0} (derived from DN leaf)" -f $SamAccountName)
}

# --- Before state ---
Write-Output "===== BEFORE ====="
try {
    $before = Get-ADUser -Identity $SamAccountName -Properties PasswordLastSet, pwdLastSet, PasswordNeverExpires, UserAccountControl -ErrorAction Stop
    $before | Select-Object SamAccountName, PasswordLastSet, pwdLastSet, PasswordNeverExpires, UserAccountControl | Format-List | Out-String | Write-Output
} catch {
    Write-Output ("Get-ADUser before failed: {0}. Proceeding with ADSI touch anyway." -f $_.Exception.Message)
}

$u = [ADSI]"LDAP://$UserDN"
Write-Output ("ADSI raw pwdLastSet before: {0}" -f $u.pwdLastSet.Value)
Write-Output ""

# --- Step 1: set to 0 (force must-change) ---
Write-Output "=== Step 1: Set pwdLastSet = 0 ==="
try {
    $u.Put("pwdLastSet", 0)
    $u.SetInfo()
    Write-Output "Step 1 OK."
} catch {
    Write-Output ("Step 1 FAILED: {0}" -f $_.Exception.Message)
    Write-Output "Aborting. Account not modified."
    exit 1
}

# --- Step 2: set to -1 (current time) ---
Write-Output ""
Write-Output "=== Step 2: Set pwdLastSet = -1 (server converts to now) ==="
try {
    $u.Put("pwdLastSet", -1)
    $u.SetInfo()
    Write-Output "Step 2 OK."
} catch {
    Write-Output ("Step 2 FAILED: {0}" -f $_.Exception.Message)
    Write-Output "WARNING: Account may be in must-change-at-next-logon state after Step 1."
    Write-Output ("Recovery: Set-ADUser -Identity {0} -Replace @{{pwdLastSet=-1}}" -f $SamAccountName)
    exit 1
}

# Refresh ADSI cache
$u.RefreshCache()
Write-Output ("ADSI raw pwdLastSet after:  {0}" -f $u.pwdLastSet.Value)
Write-Output ""

# --- After state ---
Write-Output "===== AFTER ====="
try {
    $after = Get-ADUser -Identity $SamAccountName -Properties PasswordLastSet, pwdLastSet, PasswordNeverExpires, UserAccountControl, 'msDS-UserPasswordExpiryTimeComputed' -ErrorAction Stop
    $after | Select-Object SamAccountName, PasswordLastSet, pwdLastSet, PasswordNeverExpires, UserAccountControl, 'msDS-UserPasswordExpiryTimeComputed' | Format-List | Out-String | Write-Output
} catch {
    Write-Output ("Get-ADUser after failed: {0}" -f $_.Exception.Message)
}

Write-Output "=== Done ==="
Write-Output "PasswordLastSet should now reflect the current timestamp."
Write-Output "If PasswordLastSet is still unchanged, verify the account is not protected against accidental deletion, and that this DC holds the PDC emulator role or is replicating correctly."
