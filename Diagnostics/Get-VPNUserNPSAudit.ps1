<#
.SYNOPSIS
    Reviews NPS Security log events and AD attributes for a VPN user.

.DESCRIPTION
    Read-only. Pulls Security log NPS events (6272/6273/6274/6275/6276/6277/6278)
    for the target user over the lookback window, prints each full event body, and
    snapshots the AD attributes most relevant to VPN authorization:
    msNPAllowDialin, userAccountControl, memberOf, Enabled, LockedOut.

    If -CompareTo is supplied, also reads the comparison user's AD attributes and
    prints a group membership diff to surface missing VPN-relevant groups.

    Run on the NPS host (typically a domain controller) with the ActiveDirectory
    module available. SYSTEM or privileged account required to read Security log.

.PARAMETER User
    SAM account name of the VPN user to investigate.

.PARAMETER CompareTo
    Optional SAM account name of a known-working VPN user for group membership
    and dial-in attribute comparison.

.PARAMETER HoursBack
    Number of hours of Security log history to query. Default 4.

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1 on NPS/DC host)
    Platform: Windows Server with NPS role; ActiveDirectory RSAT required
    PS 5.1 compatible.

.KEYWORDS
    NPS, VPN, RADIUS, 6272, 6273, AD, msNPAllowDialin, dial-in, group membership, diagnostics
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$User,

    [string]$CompareTo = '',

    [int]$HoursBack = 4
)

Write-Output "=== NPS + AD review for '$User' on $env:COMPUTERNAME -- $(Get-Date) ==="
Write-Output "Lookback: $HoursBack hour(s)  CompareTo: $(if ($CompareTo) { $CompareTo } else { '<none>' })"

# --- NPS Security log events ---
$ids   = @(6272,6273,6274,6275,6276,6277,6278)
$since = (Get-Date).AddHours(-$HoursBack)

Write-Output "`n--- NPS events since $since (IDs: $($ids -join ', ')) ---"
$events = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $ids
        StartTime = $since
    } -ErrorAction Stop
} catch {
    Write-Output "Event query failed: $($_.Exception.Message)"
}

$resultMap = @{
    6272 = 'GRANTED'
    6273 = 'DENIED'
    6274 = 'DISCARDED'
    6275 = 'QUARANTINED'
    6276 = 'LOCKED_OUT'
    6277 = 'AUTH_FAILED'
    6278 = 'GRANTED_FULL_ACCESS'
}

$forUser = $events | Where-Object { $_.Message -match "(?i)\b$([regex]::Escape($User))\b" }
if ($forUser) {
    Write-Output ("Found {0} NPS event(s) for '{1}':" -f $forUser.Count, $User)
    foreach ($e in ($forUser | Sort-Object TimeCreated)) {
        Write-Output ""
        Write-Output ("=== {0}  Event {1} ({2})  Provider: {3} ===" -f $e.TimeCreated, $e.Id, $resultMap[$e.Id], $e.ProviderName)
        Write-Output $e.Message
    }
} else {
    Write-Output ("No NPS events found for user '{0}' in the last {1} hour(s)." -f $User, $HoursBack)
    if ($events) {
        Write-Output "`nMost recent 10 NPS auth events (any user):"
        $events | Sort-Object TimeCreated -Descending | Select-Object -First 10 |
            Select-Object TimeCreated, Id,
                @{n='Result';e={ $resultMap[$_.Id] }},
                @{n='AccountName';e={
                    if ($_.Message -match 'Account Name:\s+(\S[^\r\n]+)') { $Matches[1].Trim() }
                }} |
            Format-Table -AutoSize | Out-String | Write-Output
    }
}

# --- AD attributes for the target user ---
Write-Output "`n--- AD attributes for '$User' ---"
$userGroups = @()
$u = $null
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $u = Get-ADUser -Identity $User -Properties msNPAllowDialin,userAccountControl,memberOf,Enabled,LockedOut,AccountExpirationDate,PasswordExpired,PasswordLastSet,LastLogonDate -ErrorAction Stop

    $uacFlags = @{
        0x0002   = 'ACCOUNTDISABLE'
        0x0010   = 'LOCKOUT'
        0x0020   = 'PASSWD_NOTREQD'
        0x0040   = 'PASSWD_CANT_CHANGE'
        0x0200   = 'NORMAL_ACCOUNT'
        0x10000  = 'DONT_EXPIRE_PASSWORD'
        0x40000  = 'SMARTCARD_REQUIRED'
        0x800000 = 'PASSWORD_EXPIRED'
    }
    $flagsSet = @()
    foreach ($k in $uacFlags.Keys) {
        if ($u.userAccountControl -band $k) { $flagsSet += $uacFlags[$k] }
    }

    [pscustomobject]@{
        SamAccountName        = $u.SamAccountName
        Enabled               = $u.Enabled
        LockedOut             = $u.LockedOut
        PasswordExpired       = $u.PasswordExpired
        PasswordLastSet       = $u.PasswordLastSet
        AccountExpirationDate = $u.AccountExpirationDate
        LastLogonDate         = $u.LastLogonDate
        msNPAllowDialin       = $u.msNPAllowDialin
        UAC_Hex               = ('0x{0:X}' -f $u.userAccountControl)
        UAC_Flags             = ($flagsSet -join ', ')
        GroupCount            = $u.memberOf.Count
    } | Format-List | Out-String | Write-Output

    Write-Output "Groups (memberOf, sorted):"
    $userGroups = $u.memberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' } | Sort-Object
    $userGroups | ForEach-Object { Write-Output ("  {0}" -f $_) }
} catch {
    Write-Output ("AD lookup failed for '{0}': {1}" -f $User, $_.Exception.Message)
}

# --- Comparison user (if specified) ---
if ($CompareTo) {
    Write-Output "`n--- AD attributes for '$CompareTo' (comparison) ---"
    try {
        $c = Get-ADUser -Identity $CompareTo -Properties msNPAllowDialin,userAccountControl,memberOf,Enabled,LockedOut,LastLogonDate -ErrorAction Stop

        [pscustomobject]@{
            SamAccountName  = $c.SamAccountName
            Enabled         = $c.Enabled
            LockedOut       = $c.LockedOut
            LastLogonDate   = $c.LastLogonDate
            msNPAllowDialin = $c.msNPAllowDialin
            UAC_Hex         = ('0x{0:X}' -f $c.userAccountControl)
            GroupCount      = $c.memberOf.Count
        } | Format-List | Out-String | Write-Output

        $cmpGroups = $c.memberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' } | Sort-Object
        Write-Output "Groups (memberOf, sorted):"
        $cmpGroups | ForEach-Object { Write-Output ("  {0}" -f $_) }

        Write-Output ("`n--- Group membership diff ('{0}' vs '{1}') ---" -f $User, $CompareTo)
        $onlyInCompare = $cmpGroups | Where-Object { $_ -notin $userGroups }
        $onlyInUser    = $userGroups | Where-Object { $_ -notin $cmpGroups }

        if ($onlyInCompare) {
            Write-Output ("Groups '{0}' has that '{1}' is MISSING (likely VPN-relevant):" -f $CompareTo, $User)
            $onlyInCompare | ForEach-Object { Write-Output ("  + {0}" -f $_) }
        } else {
            Write-Output ("(no groups in '{0}' that '{1}' lacks)" -f $CompareTo, $User)
        }
        if ($onlyInUser) {
            Write-Output ("Groups '{0}' has that '{1}' lacks:" -f $User, $CompareTo)
            $onlyInUser | ForEach-Object { Write-Output ("  - {0}" -f $_) }
        }

        Write-Output "`n--- Dial-in attribute comparison ---"
        Write-Output ("  {0}.msNPAllowDialin = {1}" -f $User, $u.msNPAllowDialin)
        Write-Output ("  {0}.msNPAllowDialin = {1}" -f $CompareTo, $c.msNPAllowDialin)
        if ($u -and ($u.msNPAllowDialin -ne $c.msNPAllowDialin)) {
            Write-Output "  *** MISMATCH on msNPAllowDialin ***"
        }
    } catch {
        Write-Output ("Comparison AD lookup failed for '{0}': {1}" -f $CompareTo, $_.Exception.Message)
    }
} else {
    Write-Output "`n(No comparison user set. Supply -CompareTo <samAccountName> to diff groups and dial-in settings.)"
}

Write-Output "`n=== END ==="
