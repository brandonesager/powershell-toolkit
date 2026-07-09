#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Disable-ADUserOffboarding — On-prem AD offboarding for Contoso users

.DESCRIPTION
    Disables AD account, updates description, removes group memberships,
    adds DeactivatedENG, hides from GAL, moves to retention OU.
    Optionally clears phone fields for temp hires.

    Run on DC01 or DC02 via remote session.

    Uses Invoke-Step wrapper for accurate pass/fail reporting per step.
    Continues through all steps on failure and prints summary at end.

    Auto-creates the monthly sub-OU under Deactivated if it doesn't exist.
    Looks up job title and supervisor from AD automatically.

.PARAMETER SamAccountName
    AD sAMAccountName of the user to offboard.

.PARAMETER TicketNumber
    PSA ticket number for the description field.

.PARAMETER RetentionType
    Standard (monthly OU), Litigation, or VIP. Defaults to Standard.

.PARAMETER IsTempHire
    Switch. Clears Home and Office phone fields (temp hire MFA cleanup).

.NOTES
    Category: Environment-Specific
    Client: Contoso

.KEYWORDS
    Contoso, AD, offboard, disable, on-prem
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$SamAccountName,

    [Parameter(Mandatory)]
    [string]$TicketNumber,

    [ValidateSet("Standard", "Litigation", "VIP")]
    [string]$RetentionType = "Standard",

    [switch]$IsTempHire
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
# OU PATHS
# ============================================================
$ParentStandardRetentionOU = "OU=Deactivated,OU=Egnyte,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com"
$LitigationHoldOU         = "OU=LitigationHold,OU=Retain,OU=EdgewaveOnly,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com"
$VIPHoldOU                = "OU=VIP,OU=Retain,OU=EdgewaveOnly,OU=Managed Users,OU=Managed Objects,DC=contoso,DC=com"

# ============================================================
# RESOLVE TARGET OU
# ============================================================
switch ($RetentionType) {
    "Standard" {
        $MonthFolder = (Get-Date -Format "yyyy-MM")
        $TargetOU = "OU=$MonthFolder,$ParentStandardRetentionOU"
        $OUExists = Get-ADOrganizationalUnit -Filter "Name -eq '$MonthFolder'" -SearchBase $ParentStandardRetentionOU -ErrorAction SilentlyContinue
        if (-not $OUExists) {
            New-ADOrganizationalUnit -Name $MonthFolder -Path $ParentStandardRetentionOU
            Write-Host "[OU] Created sub-OU: $MonthFolder" -ForegroundColor Green
        }
    }
    "Litigation" { $TargetOU = $LitigationHoldOU }
    "VIP"        { $TargetOU = $VIPHoldOU }
}

# ============================================================
# LOOK UP USER DETAILS
# ============================================================
$UserDetails = Get-ADUser -Identity $SamAccountName -Properties DisplayName, Title, Manager, HomePhone, OfficePhone -ErrorAction Stop
$DisplayName = $UserDetails.DisplayName
$JobTitle    = if ($UserDetails.Title) { $UserDetails.Title } else { "Employee" }
$EffectiveDate = Get-Date -Format "MM/dd/yy"

Write-Host "`nOffboarding: $DisplayName ($SamAccountName)" -ForegroundColor Cyan
Write-Host "Ticket: #$TicketNumber | Retention: $RetentionType | Temp: $IsTempHire`n"

# ============================================================
# STEPS
# ============================================================
Invoke-Step "1" "Account disabled" {
    Disable-ADAccount -Identity $SamAccountName
}

Invoke-Step "2" "Description updated" {
    $script:Description = "Disabled $EffectiveDate (Reference Ticket#$TicketNumber) - $JobTitle"
    Set-ADUser -Identity $SamAccountName -Description $script:Description
    Write-Host "     $script:Description"
}

Invoke-Step "3" "Added to DeactivatedENG" {
    Add-ADGroupMember -Identity "DeactivatedENG" -Members $SamAccountName
}

Invoke-Step "4" "Group memberships removed" {
    $Groups = Get-ADUser -Identity $SamAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf
    $script:RemovedGroups = @()
    foreach ($Group in $Groups) {
        $GroupName = (Get-ADGroup -Identity $Group).Name
        if ($GroupName -notin @("Domain Users", "DeactivatedENG")) {
            Remove-ADGroupMember -Identity $Group -Members $SamAccountName -Confirm:$false
            $script:RemovedGroups += $GroupName
        }
    }
    $script:RemovedGroups | ForEach-Object { Write-Host "     - $_" }
}

Invoke-Step "5" "Phone fields cleared (temp hire MFA)" {
    if ($IsTempHire) {
        Set-ADUser -Identity $SamAccountName -HomePhone $null -OfficePhone $null
    } else {
        Write-Host "     Skipped (permanent hire)"
    }
}

Invoke-Step "6" "Hidden from GAL" {
    Set-ADUser -Identity $SamAccountName -Replace @{msExchHideFromAddressLists = $true}
}

Invoke-Step "7" "Moved to retention OU" {
    $ADUser = Get-ADUser -Identity $SamAccountName
    Move-ADObject -Identity $ADUser.DistinguishedName -TargetPath $TargetOU
    Write-Host "     $TargetOU"
}

# ============================================================
# VERIFICATION
# ============================================================
Write-Host "`n========== AD VERIFICATION ==========" -ForegroundColor Cyan
try {
    $Check = Get-ADUser -Identity $SamAccountName -Properties Enabled, Description, MemberOf, HomePhone, OfficePhone, msExchHideFromAddressLists
    Write-Host "Account Enabled:     $($Check.Enabled)"
    Write-Host "Description:         $($Check.Description)"
    Write-Host "Hidden from GAL:     $($Check.msExchHideFromAddressLists)"
    Write-Host "Home Phone:          $($Check.HomePhone)"
    Write-Host "Office Phone:        $($Check.OfficePhone)"
    Write-Host "Groups remaining:    $($Check.MemberOf.Count)"
} catch {
    Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan

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

if ($script:RemovedGroups.Count -gt 0) {
    Write-Host "`n--- Groups removed (copy for resolution note) ---" -ForegroundColor Yellow
    $script:RemovedGroups | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`nAD complete. Run Remove-CloudUserOffboarding.ps1 from workstation." -ForegroundColor Yellow
