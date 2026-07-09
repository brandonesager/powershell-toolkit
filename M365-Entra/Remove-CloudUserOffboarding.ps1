#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Remove-CloudUserOffboarding — Cloud offboarding (EXO + Graph) for Contoso users

.DESCRIPTION
    Revokes sessions, converts mailbox to shared, sets auto-reply, removes
    delegates and forwarding rules, removes M365 licenses.

    Run from local workstation. No need to wait for Entra Connect delta sync —
    all operations target EXO/Graph independently. Sync catches up on its own.
    Pair with Disable-ADUserOffboarding.ps1 which handles on-prem AD steps.

    Uses Invoke-Step wrapper for accurate pass/fail reporting per step.
    Continues through all steps on failure and prints summary at end.

.PARAMETER UserPrincipalName
    UPN of the user to offboard (e.g. jdoe@contoso.com).

.PARAMETER SupervisorName
    Supervisor display name for auto-reply. If omitted, looked up from AD manager attribute.

.PARAMETER SupervisorEmail
    Supervisor email for auto-reply. If omitted, looked up from AD manager attribute.

.PARAMETER SkipAutoReply
    Switch. Skip setting auto-reply (e.g. if not requested).

.NOTES
    Category: Environment-Specific
    Client: Contoso (contoso.com / contoso.com)

.KEYWORDS
    Contoso, cloud, offboard, Exchange, Graph, mailbox, license
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [string]$SupervisorName,

    [string]$SupervisorEmail,

    [switch]$SkipAutoReply
)

# ============================================================
# STEP RUNNER
# ============================================================
$script:Steps = [System.Collections.Generic.List[PSCustomObject]]::new()

function Invoke-Step {
    param([string]$Number, [string]$Label, [scriptblock]$Action)
    try {
        $ErrorActionPreference = 'Stop'
        . $Action
        Write-Host "[$Number] $Label" -ForegroundColor Green
        $script:Steps.Add([PSCustomObject]@{ Step = $Number; Label = $Label; Pass = $true })
    } catch {
        Write-Host "[$Number] FAILED — $Label" -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor Red
        $script:Steps.Add([PSCustomObject]@{ Step = $Number; Label = $Label; Pass = $false })
    }
}

# ============================================================
# CONNECTION CHECKS
# ============================================================
if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "User.ReadWrite.All","User.RevokeSessions.All"
}
if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    Connect-ExchangeOnline
}

# ============================================================
# RESOLVE DISPLAY NAME + SUPERVISOR
# ============================================================
$MgUser = Get-MgUser -UserId $UserPrincipalName -Property DisplayName -ErrorAction Stop
$DisplayName = $MgUser.DisplayName

if (-not $SupervisorName -or -not $SupervisorEmail) {
    try {
        $Sam = ($UserPrincipalName -split "@")[0]
        $ADUser = Get-ADUser -Identity $Sam -Properties Manager
        if ($ADUser.Manager) {
            $Mgr = Get-ADUser -Identity $ADUser.Manager -Properties DisplayName, EmailAddress
            if (-not $SupervisorName)  { $SupervisorName  = $Mgr.DisplayName }
            if (-not $SupervisorEmail) { $SupervisorEmail = $Mgr.EmailAddress }
        }
    } catch {
        Write-Host "[!] Could not look up supervisor from AD. Provide -SupervisorName and -SupervisorEmail." -ForegroundColor Red
    }
}

Write-Host "`nCloud offboarding: $DisplayName ($UserPrincipalName)" -ForegroundColor Cyan
if ($SupervisorName) { Write-Host "Supervisor: $SupervisorName ($SupervisorEmail)`n" }

# ============================================================
# STEPS
# ============================================================
Invoke-Step "1" "Sign-in sessions revoked" {
    $null = Revoke-MgUserSignInSession -UserId $UserPrincipalName
}

Invoke-Step "2" "Mailbox converted to Shared" {
    Set-Mailbox -Identity $UserPrincipalName -Type Shared
}

Invoke-Step "3" "Copy Items Sent As enabled" {
    Set-Mailbox -Identity $UserPrincipalName -MessageCopyForSentAsEnabled $true
}

Invoke-Step "4" "Auto-reply set" {
    if ($SkipAutoReply) {
        Write-Host "     Skipped (-SkipAutoReply)"
    } elseif ($SupervisorName -and $SupervisorEmail) {
        $AutoReplyMessage = "Thank you for your email. $DisplayName is no longer with the organization. Please contact $SupervisorName at $SupervisorEmail for assistance."
        Set-MailboxAutoReplyConfiguration -Identity $UserPrincipalName `
            -AutoReplyState Enabled `
            -InternalMessage $AutoReplyMessage `
            -ExternalMessage $AutoReplyMessage `
            -ExternalAudience All
        Write-Host "     $AutoReplyMessage"
    } else {
        Write-Host "     Skipped (no supervisor info)"
    }
}

Invoke-Step "5" "Mailbox delegates removed" {
    $Permissions = Get-MailboxPermission -Identity $UserPrincipalName | Where-Object {
        $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and !$_.IsInherited
    }
    $script:RemovedDelegates = @()
    foreach ($Perm in $Permissions) {
        Remove-MailboxPermission -Identity $UserPrincipalName -User $Perm.User -AccessRights $Perm.AccessRights -Confirm:$false
        $script:RemovedDelegates += "$($Perm.User) ($($Perm.AccessRights -join ', '))"
    }
    $script:RemovedDelegates | ForEach-Object { Write-Host "     - $_" }
}

Invoke-Step "6" "Forwarding inbox rules disabled" {
    $ForwardRules = Get-InboxRule -Mailbox $UserPrincipalName | Where-Object {
        $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo
    }
    foreach ($Rule in $ForwardRules) {
        Disable-InboxRule -Mailbox $UserPrincipalName -Identity $Rule.Identity -Confirm:$false
        Write-Host "     Disabled: $($Rule.Name)"
    }
    if (-not $ForwardRules) { Write-Host "     None found" }
}

Invoke-Step "7" "M365 licenses removed" {
    $UserLic = Get-MgUser -UserId $UserPrincipalName -Property AssignedLicenses
    $Licenses = $UserLic.AssignedLicenses
    $script:RemovedLicenseNames = @()
    if ($Licenses.Count -gt 0) {
        $LicenseSkus = $Licenses | ForEach-Object { $_.SkuId }
        $null = Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses @() -RemoveLicenses $LicenseSkus
        $SkuMap = @{}
        Get-MgSubscribedSku | ForEach-Object { $SkuMap[$_.SkuId] = $_.SkuPartNumber }
        $script:RemovedLicenseNames = $LicenseSkus | ForEach-Object { $SkuMap[$_] }
        $script:RemovedLicenseNames | ForEach-Object { Write-Host "     - $_" }
    } else {
        Write-Host "     None assigned"
    }
}

# ============================================================
# VERIFICATION
# ============================================================
Write-Host "`n========== CLOUD VERIFICATION ==========" -ForegroundColor Cyan
try {
    $MbxCheck = Get-Mailbox -Identity $UserPrincipalName
    Write-Host "Mailbox Type:       $($MbxCheck.RecipientTypeDetails)"
    Write-Host "Hidden from GAL:    $($MbxCheck.HiddenFromAddressListsEnabled)"
    Write-Host "CopySentAs:         $($MbxCheck.MessageCopyForSentAsEnabled)"
    $OofCheck = Get-MailboxAutoReplyConfiguration -Identity $UserPrincipalName
    Write-Host "Auto-Reply State:   $($OofCheck.AutoReplyState)"
    $LicCheck = (Get-MgUser -UserId $UserPrincipalName -Property AssignedLicenses).AssignedLicenses
    Write-Host "Licenses:           $($LicCheck.Count)"
} catch {
    Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "============================================" -ForegroundColor Cyan

# ============================================================
# SUMMARY
# ============================================================
$Passed = ($script:Steps | Where-Object { $_.Pass }).Count
$Failed = ($script:Steps | Where-Object { -not $_.Pass }).Count
Write-Host "`n$Passed passed, $Failed failed out of $($script:Steps.Count) steps" -ForegroundColor $(if ($Failed -eq 0) { 'Green' } else { 'Red' })
if ($Failed -gt 0) {
    Write-Host "`nFailed steps — re-run these manually:" -ForegroundColor Red
    $script:Steps | Where-Object { -not $_.Pass } | ForEach-Object {
        Write-Host "  [$($_.Step)] $($_.Label)" -ForegroundColor Red
    }
}

if ($script:RemovedLicenseNames.Count -gt 0) {
    Write-Host "`n--- Licenses removed (copy for resolution note) ---" -ForegroundColor Yellow
    $script:RemovedLicenseNames | ForEach-Object { Write-Host "  $_" }
}
if ($script:RemovedDelegates.Count -gt 0) {
    Write-Host "`n--- Delegates removed ---" -ForegroundColor Yellow
    $script:RemovedDelegates | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`n--- MANUAL STEPS ---" -ForegroundColor Yellow
Write-Host "[ ] Egnyte: Move private folder to xDeactivatedUsers" -ForegroundColor Yellow
Write-Host "[ ] Adobe: Check for assigned Acrobat license" -ForegroundColor Yellow
Write-Host "[ ] Zoom: Remove user's Zoom account" -ForegroundColor Yellow
Write-Host "[ ] PSA: Mark contact inactive" -ForegroundColor Yellow
Write-Host "[ ] Documentation platform: Delete orphaned contact" -ForegroundColor Yellow
Write-Host "[ ] Printers: Remove from site printer address books (if applicable)" -ForegroundColor Yellow
