<#
.SYNOPSIS
    Get-RecurringPasswordDiag-DC — Domain Controller password failure diagnostic

.DESCRIPTION
    Runs on a Domain Controller to diagnose recurring password failures.
    Checks AD account properties, lockout events, password policy, and
    Kerberos/NTLM authentication events for the target user.

.NOTES
    Category: Diagnostics

.KEYWORDS
    AD, diagnose, password, lockout, DC
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SamAccountName
)

$ErrorActionPreference = "Stop"
$ExitCode = 0

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Output "========== AD PASSWORD DIAGNOSTIC - DC =========="
    Write-Output "Target User: $SamAccountName"
    Write-Output "DC: $env:COMPUTERNAME"
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    # Get user properties
    Write-Output "=== AD Account Properties ==="
    $User = Get-ADUser -Identity $SamAccountName -Properties `
        LockedOut, LockoutTime, BadLogonCount, badPwdCount, `
        PasswordLastSet, PasswordExpired, PasswordNeverExpires, `
        LastLogonDate, Enabled, msDS-UserPasswordExpiryTimeComputed

    Write-Output "  Enabled:              $($User.Enabled)"
    Write-Output "  LockedOut:            $($User.LockedOut)"
    Write-Output "  LockoutTime:          $(if($User.LockoutTime){[DateTime]::FromFileTime($User.LockoutTime)}else{'N/A'})"
    Write-Output "  BadLogonCount:        $($User.BadLogonCount)"
    Write-Output "  badPwdCount:          $($User.badPwdCount)"
    Write-Output "  PasswordLastSet:      $($User.PasswordLastSet)"
    Write-Output "  PasswordExpired:      $($User.PasswordExpired)"
    Write-Output "  PasswordNeverExpires: $($User.PasswordNeverExpires)"
    Write-Output "  LastLogonDate:        $($User.LastLogonDate)"

    if ($User.'msDS-UserPasswordExpiryTimeComputed' -gt 0) {
        $Expiry = [DateTime]::FromFileTime($User.'msDS-UserPasswordExpiryTimeComputed')
        Write-Output "  Password Expires:     $Expiry"
    }
    Write-Output ""

    # Check lockout status across ALL DCs
    Write-Output "=== Lockout Status Across All DCs ==="
    $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    foreach ($DC in $DCs) {
        try {
            $DCUser = Get-ADUser -Identity $SamAccountName -Server $DC -Properties LockedOut, BadLogonCount -ErrorAction Stop
            $Status = if ($DCUser.LockedOut) { "LOCKED" } else { "OK" }
            Write-Output "  $DC : $Status (BadCount: $($DCUser.BadLogonCount))"
            if ($DCUser.LockedOut) { $ExitCode = 2 }
        } catch {
            Write-Output "  $DC : UNREACHABLE"
        }
    }
    Write-Output ""

    # Recent security events for this user
    Write-Output "=== Recent Auth Events (Last 24h) ==="
    $StartTime = (Get-Date).AddHours(-24)

    # Event 4740 = Account lockout
    $Lockouts = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4740
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[0].Value -eq $SamAccountName
    }

    if ($Lockouts) {
        Write-Output "  [4740] Account Lockouts:"
        foreach ($Event in $Lockouts | Select-Object -First 5) {
            $CallerComputer = $Event.Properties[1].Value
            Write-Output "    $($Event.TimeCreated) - Source: $CallerComputer"
        }
    } else {
        Write-Output "  [4740] No lockouts in last 24h"
    }

    # Event 4771 = Kerberos pre-auth failed
    $KerbFails = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4771
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[0].Value -eq $SamAccountName
    }

    if ($KerbFails) {
        Write-Output "  [4771] Kerberos Pre-Auth Failures:"
        $KerbFails | Group-Object { $_.Properties[6].Value } | ForEach-Object {
            Write-Output "    IP $($_.Name): $($_.Count) failures"
        }
        $ExitCode = 2
    } else {
        Write-Output "  [4771] No Kerberos pre-auth failures"
    }

    # Event 4776 = NTLM credential validation
    $NtlmFails = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4776
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[1].Value -eq $SamAccountName -and $_.Properties[4].Value -ne '0x0'
    }

    if ($NtlmFails) {
        Write-Output "  [4776] NTLM Validation Failures:"
        $NtlmFails | Group-Object { $_.Properties[2].Value } | ForEach-Object {
            Write-Output "    Workstation $($_.Name): $($_.Count) failures"
        }
        $ExitCode = 2
    } else {
        Write-Output "  [4776] No NTLM validation failures"
    }
    Write-Output ""

    # Password policy
    Write-Output "=== Domain Password Policy ==="
    $Policy = Get-ADDefaultDomainPasswordPolicy
    Write-Output "  Min Length:        $($Policy.MinPasswordLength)"
    Write-Output "  Lockout Threshold: $($Policy.LockoutThreshold)"
    Write-Output "  Lockout Duration:  $($Policy.LockoutDuration)"
    Write-Output "  Max Password Age:  $($Policy.MaxPasswordAge)"

    # Check for Fine-Grained Password Policy
    $FGPP = Get-ADUserResultantPasswordPolicy -Identity $SamAccountName -ErrorAction SilentlyContinue
    if ($FGPP) {
        Write-Output ""
        Write-Output "  [FGPP Applied]: $($FGPP.Name)"
        Write-Output "    Lockout Threshold: $($FGPP.LockoutThreshold)"
    }
    Write-Output ""

    # Check Azure AD Connect sync (if this is the AADConnect server)
    if (Get-Service -Name ADSync -ErrorAction SilentlyContinue) {
        Write-Output "=== Azure AD Connect Status ==="
        $SyncStatus = Get-ADSyncScheduler -ErrorAction SilentlyContinue
        if ($SyncStatus) {
            Write-Output "  Sync Enabled:      $($SyncStatus.SyncCycleEnabled)"
            Write-Output "  Next Sync:         $($SyncStatus.NextSyncCycleStartTimeInUTC)"
            Write-Output "  Last Sync Policy:  $($SyncStatus.SyncCyclePolicyType)"
        }
    }

    Write-Output ""
    Write-Output "========== DIAGNOSTIC COMPLETE =========="

} catch {
    Write-Output "FATAL ERROR: $($_.Exception.Message)"
    $ExitCode = 1
}

exit $ExitCode

<#
.NOTES
Run on any Domain Controller with AD module.

Event ID Reference:
  4740 = Account lockout
  4771 = Kerberos pre-auth failed (wrong password before lockout)
  4776 = NTLM credential validation (reports workstation source)

Exit Codes:
  0 = Info gathered, no issues found
  1 = Script error
  2 = Issues found (lockouts, auth failures)

For recurring morning password issues, look for:
- badPwdCount incrementing overnight
- Lockout source from mobile device or secondary workstation
- Kerberos failures from IP that isn't user's primary workstation
#>
