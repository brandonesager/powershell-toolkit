<#
.SYNOPSIS
    Full compromised-account remediation: restricted-sender check/clear, AD password reset,
    delta sync, and Entra session revoke.

.DESCRIPTION
    Covers the complete remediation flow for a compromised account:

    Phase 1 (Cloud, EXO session): Check and remove the user from the Exchange Online
    Defender restricted-senders list (Remove-BlockedSenderAddress). Accounts restricted
    by Defender cannot send outbound mail even after a password reset; this block requires
    explicit removal separate from the compromise remediation.

    Phase 2 (RMM shell, on-prem DC, SYSTEM): Reset AD password with a generated
    strong passphrase (Word+Special+Word+Digit pattern). Unlocks account if locked.
    Triggers Entra Connect delta sync locally; falls back with a manual instruction
    if ADSync is not on the current host.

    Phase 3 (Cloud, Graph session): Revoke all Entra sign-in sessions via
    Revoke-MgUserSignInSession to invalidate any cached tokens from the attacker.

    Each phase can run independently. Read-only check (Get-BlockedSenderAddress) runs
    first and the script exits if the user is not on the restricted list.

    Hybrid environment note: AD is the password authority. Delta sync is required after
    the AD reset before Entra / M365 reflects the new hash.

.PARAMETER UserUPN
    UPN of the compromised user (e.g., jdoe@contoso.com).

.PARAMETER SamAccountName
    sAMAccountName for the AD password reset phase (e.g., jdoe).

.PARAMETER RemoveRestrictedSender
    Switch. Run Phase 1 (EXO restricted-sender check/clear). Requires live EXO session.

.PARAMETER ResetADPassword
    Switch. Run Phase 2 (AD reset + delta sync). Requires RMM shell / SYSTEM context
    on a domain-joined machine with ActiveDirectory module.

.PARAMETER RevokeEntraSessions
    Switch. Run Phase 3 (Entra session revoke). Requires live Graph session (User.ReadWrite.All).

.EXAMPLE
    # Phase 1 only (cloud shell):
    .\Invoke-CompromisedAccountRemediation.ps1 -UserUPN 'jdoe@contoso.com' -RemoveRestrictedSender

    # Phase 3 only (cloud shell):
    .\Invoke-CompromisedAccountRemediation.ps1 -UserUPN 'jdoe@contoso.com' -RevokeEntraSessions

.NOTES
    Created: 2026-05-29
    Category: M365-Security
    Context: Cloud (Phases 1, 3) / Commands/SYSTEM (Phase 2)

    Phase 2 context: Run via RMM RMM shell against the DC that hosts Entra Connect.
    Do not include Connect-/Disconnect- preamble for cloud phases; sessions are assumed live.

.KEYWORDS
    compromised account, restricted sender, blocked sender, Remove-BlockedSenderAddress,
    AD password reset, delta sync, Revoke-MgUserSignInSession, BEC, incident response
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$UserUPN,

    [string]$SamAccountName = '',

    [switch]$RemoveRestrictedSender,
    [switch]$ResetADPassword,
    [switch]$RevokeEntraSessions
)

$ErrorActionPreference = 'Continue'

Write-Host "`n=== Compromised Account Remediation ===" -ForegroundColor Cyan
Write-Host "User: $UserUPN  |  $(Get-Date)"

# ============================================================
# PHASE 1: EXO Restricted Sender Check / Clear
# ============================================================
if ($RemoveRestrictedSender) {
    Write-Host "`n=== Phase 1: Restricted Sender Check ===" -ForegroundColor Yellow

    $entry = Get-BlockedSenderAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.SenderAddress -ieq $UserUPN }

    if ($entry) {
        Write-Host "User IS on restricted senders list." -ForegroundColor Red
        $entry | Format-List SenderAddress, Reason, CreatedDatetime

        Write-Host "`nRemoving from restricted senders list..." -ForegroundColor Yellow
        try {
            Remove-BlockedSenderAddress -SenderAddress $UserUPN -ErrorAction Stop
            Write-Host "Remove-BlockedSenderAddress succeeded." -ForegroundColor Green
        } catch {
            Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host "`nVerifying removal (allow ~30s for Defender backend propagation)..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30
        $recheck = Get-BlockedSenderAddress -ErrorAction SilentlyContinue |
            Where-Object { $_.SenderAddress -ieq $UserUPN }
        if ($recheck) {
            Write-Host "WARNING: User still listed. Backend propagation may be delayed. Re-check in 2 min." -ForegroundColor Yellow
        } else {
            Write-Host "Confirmed: $UserUPN is no longer on the restricted senders list." -ForegroundColor Green
        }
    } else {
        Write-Host "User is NOT on the restricted senders list. No action needed." -ForegroundColor Green
    }
}

# ============================================================
# PHASE 2: AD Password Reset + Delta Sync (Commands/SYSTEM context)
# ============================================================
if ($ResetADPassword) {
    Write-Host "`n=== Phase 2: AD Password Reset ===" -ForegroundColor Yellow

    if (-not $SamAccountName) {
        Write-Host "SamAccountName not provided. Skipping Phase 2." -ForegroundColor Yellow
    } else {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            # Generate passphrase: Word+Special+Word+Digit
            $words    = @('Tiger','Eagle','Mango','Peach','Cloud','Storm','River','Stone','Beach',
                          'Cedar','Maple','Pearl','Coral','Amber','Honey','Daisy','Bread','Lemon',
                          'Berry','Penny','Brave','Happy','Music','Smart','Quick','Sweet','Quiet',
                          'Sunny','Magic','Quest','Field','Spark','Bloom','Pride','Apple','Olive',
                          'Grape','Pixel','Frost','Plant','Robin','Otter','Comet') | Where-Object { $_.Length -eq 5 }
            $specials = @('!','@','#','$','%','&','-','+','=')
            $w1 = Get-Random -InputObject $words
            $w2 = Get-Random -InputObject $words
            while ($w2 -eq $w1) { $w2 = Get-Random -InputObject $words }
            $sp   = Get-Random -InputObject $specials
            $d    = Get-Random -Minimum 2 -Maximum 10
            $pass = "$w1$sp$w2$d"
            $sec  = ConvertTo-SecureString -String $pass -AsPlainText -Force

            $adUser = Get-ADUser -Identity $SamAccountName -Properties LockedOut, Enabled -ErrorAction Stop
            Write-Host "Pre-reset: Enabled=$($adUser.Enabled)  LockedOut=$($adUser.LockedOut)"

            Set-ADAccountPassword -Identity $SamAccountName -NewPassword $sec -Reset -ErrorAction Stop
            Write-Host "AD password reset: OK" -ForegroundColor Green

            if ($adUser.LockedOut) {
                Unlock-ADAccount -Identity $SamAccountName -ErrorAction Stop
                Write-Host "Account unlocked: OK" -ForegroundColor Green
            }

            $post = Get-ADUser -Identity $SamAccountName -Properties PasswordLastSet, LockedOut
            Write-Host "Post-reset: PasswordLastSet=$($post.PasswordLastSet)  LockedOut=$($post.LockedOut)"
            Write-Host "---NEW PASSWORD---"
            Write-Host $pass
            Write-Host "---END PASSWORD---"

            # Delta sync
            if (Get-Module -ListAvailable -Name ADSync) {
                Import-Module ADSync -ErrorAction Stop
                Start-ADSyncSyncCycle -PolicyType Delta | Out-Null
                Write-Host "Delta sync started: OK" -ForegroundColor Green
            } else {
                Write-Host "ADSync not on this host. Run on Entra Connect server:" -ForegroundColor Yellow
                Write-Host "  Import-Module ADSync; Start-ADSyncSyncCycle -PolicyType Delta"
            }

        } catch {
            Write-Host "Phase 2 error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================================
# PHASE 3: Revoke Entra Sign-In Sessions
# ============================================================
if ($RevokeEntraSessions) {
    Write-Host "`n=== Phase 3: Revoke Entra Sessions ===" -ForegroundColor Yellow
    try {
        $mgUser = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction Stop
        if (-not $mgUser) { Write-Host "User not found in Entra."; return }

        Revoke-MgUserSignInSession -UserId $mgUser.Id -ErrorAction Stop | Out-Null
        Write-Host "All Entra sign-in sessions revoked for $UserUPN." -ForegroundColor Green
        Write-Host "Attacker tokens invalidated. Client must re-authenticate on next access."
    } catch {
        Write-Host "Phase 3 error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== Remediation complete ===" -ForegroundColor Cyan
Write-Host "Next steps:"
Write-Host "  1. Audit mailbox: Get-InboxRule, ForwardingAddress, ForwardingSmtpAddress, SendAs/FullAccess delegates."
Write-Host "  2. Review Entra Identity Protection risk flags (Risky Users blade)."
Write-Host "  3. Check MFA enrollment; reset Authenticator app if attacker had device access."
Write-Host "  4. Search message trace for outbound phishing: Get-MessageTraceV2 (requires 60-min delay for recent mail)."
Write-Host "  5. Notify leadership if phishing was sent externally (46+ delivered = reportable breach in most frameworks)."
