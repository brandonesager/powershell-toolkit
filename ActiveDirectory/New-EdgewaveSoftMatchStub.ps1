<#
.SYNOPSIS
    Create a disabled AD soft-match stub with proxyAddresses for a Contoso cloud-only shared mailbox,
    then trigger Entra Connect delta sync.

.DESCRIPTION
    Contoso routes inbound email through GoSecure (EdgeWave). Shared mailboxes created cloud-only
    are invisible to GoSecure's directory, causing 550 5.0.350 rejections from external senders.
    Fix: create a disabled AD stub in the EdgewaveOnly OU with:
    - Primary SMTP as proxyAddresses (SMTP:address, uppercase = primary).
    - mail attribute matching the primary SMTP.
    - Account disabled (shared mailboxes never sign in).
    Entra Connect picks up the object on delta sync and soft-matches it to the cloud mailbox,
    making GoSecure directory aware of the recipient.

    Critical: proxyAddresses must include SMTP: (uppercase) to assert the primary address.
    Without it, Entra Connect defaults the cloud primary to the onmicrosoft.com address.

    Pre-flight: conflict check for sAMAccountName, mail, and proxy before creating.
    Post-flight: prints verification query to confirm IsDirSynced=True and correct primary SMTP.

.PARAMETER DisplayName
    Display name of the mailbox (e.g., 'Example Shared Mailbox').

.PARAMETER SamAccountName
    sAMAccountName for the AD stub (max 20 chars for AD compatibility).

.PARAMETER PrimarySmtpAddress
    Primary SMTP address (e.g., 'sharedmailbox@contoso.com'). Used for both
    mail attribute and proxyAddresses.

.PARAMETER AdditionalProxyAddresses
    Optional array of additional proxy addresses in 'smtp:address' format (lowercase smtp = secondary).

.PARAMETER OuPath
    OU distinguished name. Defaults to the standard Contoso EdgewaveOnly Users OU.

.EXAMPLE
    .\New-EdgewaveSoftMatchStub.ps1 `
        -DisplayName 'Example Shared Mailbox' `
        -SamAccountName 'exampleshared' `
        -PrimarySmtpAddress 'sharedmailbox@contoso.com'

.NOTES
    Category: Environment-Specific/Contoso
    Context: Commands/SYSTEM (on-prem DC, contoso.com domain)

    After creation: allow 1-3 min for Entra Connect sync, then 5-15 min for GoSecure directory pickup.

.KEYWORDS
    Contoso, GoSecure, EdgeWave, soft-match, stub, AD, proxyAddresses, shared mailbox, 550 5.0.350
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$DisplayName,

    [Parameter(Mandatory)]
    [ValidateLength(1,20)]
    [string]$SamAccountName,

    [Parameter(Mandatory)]
    [string]$PrimarySmtpAddress,

    [string[]]$AdditionalProxyAddresses = @(),

    [string]$OuPath = 'OU=Contoso Users,OU=EdgewaveOnly,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

$upn   = $PrimarySmtpAddress
$mail  = $PrimarySmtpAddress
$proxy = @("SMTP:$PrimarySmtpAddress") + $AdditionalProxyAddresses

Write-Output "=== Pre-flight: conflict check ==="
$conflict = Get-ADObject -LDAPFilter "(|(sAMAccountName=$SamAccountName)(mail=$mail)(proxyAddresses=SMTP:$mail)(proxyAddresses=smtp:$mail))" `
    -Properties distinguishedName -ErrorAction SilentlyContinue
if ($conflict) {
    Write-Output "ABORT: conflicting object already exists:"
    $conflict | ForEach-Object { Write-Output "  $($_.distinguishedName)" }
    return
}
Write-Output "  Clean."

Write-Output "`n=== Pre-flight: target OU ==="
$ou = Get-ADOrganizationalUnit -Identity $OuPath -ErrorAction SilentlyContinue
if (-not $ou) {
    Write-Output "ABORT: OU not found: $OuPath"
    return
}
Write-Output "  OK: $($ou.DistinguishedName)"

if ($PSCmdlet.ShouldProcess($DisplayName, "Create disabled AD stub in $OuPath")) {
    Write-Output "`n=== Creating disabled AD stub ==="
    $pw = ConvertTo-SecureString -String ('TmpStub!' + (Get-Random -Maximum 999999) + '#Z') -AsPlainText -Force
    $params = @{
        Name              = $DisplayName
        DisplayName       = $DisplayName
        SamAccountName    = $SamAccountName
        UserPrincipalName = $upn
        EmailAddress      = $mail
        Path              = $OuPath
        AccountPassword   = $pw
        Enabled           = $false
    }
    try {
        New-ADUser @params -ErrorAction Stop
        Write-Output "  Created."
    } catch {
        Write-Output "ABORT: New-ADUser failed: $($_.Exception.Message)"
        return
    }

    # Set proxyAddresses (New-ADUser does not accept proxyAddresses directly)
    Set-ADUser -Identity $SamAccountName -Replace @{ proxyAddresses = $proxy } -ErrorAction Stop
    Write-Output "  proxyAddresses set: $($proxy -join '; ')"

    Write-Output "`n=== Post-create verification ==="
    $new = Get-ADUser -Identity $SamAccountName `
        -Properties mail, proxyAddresses, Enabled, DistinguishedName, UserPrincipalName, DisplayName
    Write-Output ("Name     : " + $new.Name)
    Write-Output ("DN       : " + $new.DistinguishedName)
    Write-Output ("sAM      : " + $new.SamAccountName)
    Write-Output ("UPN      : " + $new.UserPrincipalName)
    Write-Output ("Mail     : " + $new.mail)
    Write-Output ("Proxies  : " + (($new.proxyAddresses) -join '; '))
    Write-Output ("Enabled  : " + $new.Enabled)

    Write-Output "`n=== Entra Connect delta sync ==="
    try {
        Import-Module ADSync -ErrorAction Stop
        $sync = Start-ADSyncSyncCycle -PolicyType Delta
        Write-Output "  Result: $($sync.Result)"
    } catch {
        Write-Output "WARN: ADSync not on this host: $($_.Exception.Message)"
        Write-Output "  Run on Entra Connect server: Start-ADSyncSyncCycle -PolicyType Delta"
    }

    Write-Output ""
    Write-Output "Done. Wait 1-3 min for sync, then verify:"
    Write-Output "  Get-Recipient '$mail' | fl IsDirSynced,OnPremisesObjectId,PrimarySmtpAddress"
    Write-Output "GoSecure picks up new recipients on its next directory sync (typically <=15 min)."
}
