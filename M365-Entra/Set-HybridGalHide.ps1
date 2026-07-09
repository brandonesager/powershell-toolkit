<#
.SYNOPSIS
    Hide a hybrid-synced user from the Exchange GAL by setting msExchHideFromAddressLists in on-prem AD,
    then trigger Entra Connect delta sync.

.DESCRIPTION
    For hybrid Exchange environments, Set-Mailbox -HiddenFromAddressListsEnabled is blocked on
    dir-synced mailboxes. The correct approach is to set msExchHideFromAddressLists on the
    on-prem AD user object and let Entra Connect propagate the change to Exchange Online.

    Script:
    1. Verifies the AD user exists and reads the current attribute value.
    2. Sets msExchHideFromAddressLists = $true.
    3. Verifies the write succeeded.
    4. Attempts Start-ADSyncSyncCycle -PolicyType Delta on the current machine.
       If ADSync is not present (not the Entra Connect server), prints the manual delta sync command.

    Run via RMM shell against a domain-joined machine (DC preferred).
    ActiveDirectory module required (available on DCs by default).

.PARAMETER SamAccountName
    sAMAccountName of the on-prem AD user to hide from the GAL.

.EXAMPLE
    .\Set-HybridGalHide.ps1 -SamAccountName 'jdoe'

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: Commands/SYSTEM (on-prem DC or domain member)

    Note: The AD part runs on-prem. Exchange Online reflects the change after Entra Connect sync
    (5-15 min for GAL update). Verify in EXO via:
    Get-Mailbox <UPN> | Select-Object HiddenFromAddressListsEnabled

.KEYWORDS
    GAL, hide, msExchHideFromAddressLists, hybrid, Entra Connect, delta sync, decommission, offboarding
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$SamAccountName
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

Write-Output "=== GAL Hide: $SamAccountName ==="

$adUser = Get-ADUser -Identity $SamAccountName -Properties msExchHideFromAddressLists -ErrorAction Stop
Write-Output "Found: $($adUser.DisplayName) ($($adUser.UserPrincipalName))"
Write-Output "Current msExchHideFromAddressLists: $($adUser.msExchHideFromAddressLists)"

if ($adUser.msExchHideFromAddressLists -eq $true) {
    Write-Output "Already hidden from address lists. No change needed."
} else {
    if ($PSCmdlet.ShouldProcess($SamAccountName, "Set msExchHideFromAddressLists = True")) {
        Set-ADUser -Identity $SamAccountName -Replace @{ msExchHideFromAddressLists = $true }
        $verify = Get-ADUser -Identity $SamAccountName -Properties msExchHideFromAddressLists
        Write-Output "Verified msExchHideFromAddressLists: $($verify.msExchHideFromAddressLists)"
    }
}

# Delta sync
Write-Output "`n=== Triggering Entra Connect delta sync ==="
try {
    Import-Module ADSync -ErrorAction Stop
    Start-ADSyncSyncCycle -PolicyType Delta | Out-Null
    Write-Output "Delta sync started on this machine."
} catch {
    Write-Output "ADSync module not found on this machine."
    Write-Output "Run on the Entra Connect server:"
    Write-Output "  Import-Module ADSync; Start-ADSyncSyncCycle -PolicyType Delta"
}

Write-Output "`nGAL change will reflect in Exchange Online in 5-15 min after sync completes."
Write-Output "Verify: Get-Mailbox $SamAccountName | Select-Object HiddenFromAddressListsEnabled"
