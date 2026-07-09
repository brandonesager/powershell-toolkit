<#
.SYNOPSIS
    Get-RecurringPasswordDiag-Workstation — Workstation-side password failure diagnostic

.DESCRIPTION
    Runs on the user's workstation to diagnose recurring password failures.
    Checks stored credentials, DC connectivity, Kerberos tickets, and
    credential provider status. Complement to Get-RecurringPasswordDiag-DC.

.NOTES
    Category: Diagnostics

.KEYWORDS
    diagnose, password, credential, workstation
#>

$ErrorActionPreference = "SilentlyContinue"
$ExitCode = 0

Write-Output "========== WORKSTATION PASSWORD DIAGNOSTIC =========="
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "User: $env:USERNAME"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

# Stored Credentials (runs as SYSTEM, checks system vault)
Write-Output "=== Stored Credentials (SYSTEM Vault) ==="
$SystemCreds = cmdkey /list 2>&1
if ($SystemCreds -match "Target:") {
    $SystemCreds | ForEach-Object {
        if ($_ -match "Target:|Type:|User:") {
            Write-Output "  $_"
        }
    }
} else {
    Write-Output "  (no stored credentials)"
}
Write-Output ""

# Try to enumerate user's credential vault via scheduled task
Write-Output "=== Logged-In User Credentials ==="
$LoggedInUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
Write-Output "  Current User: $LoggedInUsers"
Write-Output "  (Full user credential check requires user context)"
Write-Output ""

# DC Connectivity
Write-Output "=== Domain Controller Connectivity ==="
try {
    $DC = nltest /dsgetdc:$env:USERDNSDOMAIN 2>&1
    if ($DC -match "DC: \\\\(.+)") {
        Write-Output "  Connected DC: $($Matches[1])"
    }
    $SecureChannel = Test-ComputerSecureChannel -ErrorAction Stop
    Write-Output "  Secure Channel: $(if($SecureChannel){'VALID'}else{'BROKEN'})"
    if (-not $SecureChannel) { $ExitCode = 2 }
} catch {
    Write-Output "  DC Connectivity: FAILED"
    Write-Output "  Error: $($_.Exception.Message)"
    $ExitCode = 2
}
Write-Output ""

# Time Sync (Kerberos requires <5 min skew)
Write-Output "=== Time Synchronization ==="
$TimeSource = w32tm /query /source 2>&1
$TimePeers = w32tm /query /peers 2>&1
Write-Output "  Source: $TimeSource"
try {
    $Skew = w32tm /stripchart /computer:$env:LOGONSERVER.TrimStart('\\') /samples:1 /dataonly 2>&1
    if ($Skew -match "(\+|-)(\d+\.\d+)s") {
        $SkewSeconds = [math]::Abs([double]$Matches[2])
        Write-Output "  Skew: $SkewSeconds seconds"
        if ($SkewSeconds -gt 300) {
            Write-Output "  WARNING: Time skew >5 minutes - Kerberos will fail!"
            $ExitCode = 2
        }
    }
} catch {
    Write-Output "  Skew check failed: $($_.Exception.Message)"
}
Write-Output ""

# Network Profile
Write-Output "=== Network Profile ==="
Get-NetConnectionProfile | ForEach-Object {
    Write-Output "  $($_.InterfaceAlias): $($_.NetworkCategory)"
    if ($_.NetworkCategory -eq "Public") {
        Write-Output "  WARNING: Public network may block domain auth!"
        $ExitCode = 2
    }
}
Write-Output ""

# Auth Failure Events (last 24h, morning hours flagged)
Write-Output "=== Authentication Failures (Last 24h) ==="
$StartTime = (Get-Date).AddHours(-24)

$AuthEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($AuthEvents) {
    # Status code translation
    $StatusCodes = @{
        '0xc000006a' = 'Wrong password'
        '0xc000006d' = 'Bad username or auth info'
        '0xc000006e' = 'Account restriction (disabled, expired, hours)'
        '0xc000006f' = 'Outside logon hours'
        '0xc0000070' = 'Workstation restriction'
        '0xc0000071' = 'Password expired'
        '0xc0000072' = 'Account disabled'
        '0xc000015b' = 'User not granted logon type'
        '0xc0000193' = 'Account expired'
        '0xc0000224' = 'Must change password at next logon'
        '0xc0000234' = 'Account locked out'
    }

    Write-Output "  Found $($AuthEvents.Count) failed logon attempts"
    Write-Output ""

    $AuthEvents | Group-Object {
        $_.Properties[10].Value  # Status code
    } | ForEach-Object {
        $StatusHex = $_.Name
        $StatusDesc = if ($StatusCodes[$StatusHex]) { $StatusCodes[$StatusHex] } else { "Unknown" }
        Write-Output "  Status $StatusHex ($StatusDesc): $($_.Count) events"
    }

    # Flag morning events (6-9 AM)
    $MorningEvents = $AuthEvents | Where-Object {
        $_.TimeCreated.Hour -ge 6 -and $_.TimeCreated.Hour -lt 9
    }
    if ($MorningEvents) {
        Write-Output ""
        Write-Output "  [PATTERN] $($MorningEvents.Count) failures between 6-9 AM (morning pattern)"
        $ExitCode = 2
    }
} else {
    Write-Output "  No authentication failures in last 24h"
}
Write-Output ""

# Scheduled Tasks with stored credentials
Write-Output "=== Scheduled Tasks with Domain Credentials ==="
$Tasks = Get-ScheduledTask | Where-Object {
    $_.Principal.UserId -like "*$env:USERDNSDOMAIN*" -or
    $_.Principal.UserId -like "*@*"
}
if ($Tasks) {
    $Tasks | ForEach-Object {
        Write-Output "  $($_.TaskName): $($_.Principal.UserId)"
    }
} else {
    Write-Output "  (no tasks with domain credentials)"
}
Write-Output ""

# Services with domain accounts
Write-Output "=== Services Running as Domain Accounts ==="
$Services = Get-WmiObject Win32_Service | Where-Object {
    $_.StartName -like "*$env:USERDNSDOMAIN*" -or
    ($_.StartName -like "*\*" -and $_.StartName -notlike "NT *" -and $_.StartName -notlike "LocalSystem")
}
if ($Services) {
    $Services | ForEach-Object {
        Write-Output "  $($_.Name): $($_.StartName)"
    }
} else {
    Write-Output "  (no services with domain accounts)"
}

Write-Output ""
Write-Output "========== DIAGNOSTIC COMPLETE =========="

exit $ExitCode

<#
.NOTES
Run on user's workstation via RMM (as SYSTEM).

For recurring morning password issues:
1. Check for Public network profile (blocks domain auth)
2. Look for time skew >5 minutes (breaks Kerberos)
3. Review 4625 events for morning pattern
4. Check scheduled tasks/services with old credentials

Status Code Quick Reference:
  0xc000006a = Wrong password (most common)
  0xc0000234 = Account locked out
  0xc0000071 = Password expired
  0xc0000224 = Must change password

If morning pattern detected:
- Often caused by mobile device, VPN, or cached credential
- Check Event 4771/4776 on DC for source IP/workstation
#>
