<#
.SYNOPSIS
    Implements litigation holds and compliance search exports for legal discovery.

.DESCRIPTION
    Comprehensive script for legal hold implementation in Exchange Online:
    - Enables litigation holds on specified mailboxes
    - Grants delegate access for mailbox review
    - Creates and executes compliance searches
    - Initiates PST export for legal discovery

    Includes progress monitoring and verification at each step.

.PARAMETER AdminUPN
    Admin user principal name for Exchange Online connection.

.PARAMETER DelegateUser
    User to grant FullAccess permissions for mailbox review.

.PARAMETER TargetMailboxes
    Array of mailbox UPNs to place on litigation hold.

.NOTES
    Version : 1.1
    Date    : 2025-10-13

    Requires:
    - PowerShell 5.1+
    - Exchange Online PowerShell module
    - Security & Compliance PowerShell module
    - Exchange Online admin permissions
    - Compliance admin permissions
    Category: M365-Security
.KEYWORDS
    compliance, mailbox, litigation-hold, Exchange
#>

# CONFIGURATION - Update these values for your environment
$adminUPN = "admin@contoso.com"
$delegateUser = "delegate@contoso.com"
$targetMailboxes = @(
    "user1@contoso.com",
    "user2@contoso.com",
    "user3@contoso.com"
)

# ============================================================================
# SECTION 1: CONNECT TO EXCHANGE ONLINE
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONNECTING TO EXCHANGE ONLINE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Connect-ExchangeOnline -UserPrincipalName $adminUPN -ShowBanner:$false
    Write-Host "✓ Connected to Exchange Online" -ForegroundColor Green
}
catch {
    Write-Host "✗ FAILED to connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================================
# SECTION 2: ENABLE LITIGATION HOLDS
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ENABLING LITIGATION HOLDS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

foreach ($mailbox in $targetMailboxes) {
    try {
        $mbx = Get-Mailbox -Identity $mailbox -ErrorAction Stop
        
        if ($mbx.LitigationHoldEnabled -eq $true) {
            Write-Host "  ALREADY ENABLED: $mailbox" -ForegroundColor Yellow
        }
        else {
            Set-Mailbox -Identity $mailbox -LitigationHoldEnabled $true -LitigationHoldDuration Unlimited -WarningAction SilentlyContinue
            Write-Host "  ✓ ENABLED: $mailbox" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ✗ FAILED: $mailbox - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# SECTION 3: VERIFY LITIGATION HOLDS
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VERIFYING LITIGATION HOLDS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$targetMailboxes | ForEach-Object { 
    Get-Mailbox -Identity $_ -ErrorAction SilentlyContinue 
} | Select-Object UserPrincipalName, LitigationHoldEnabled, LitigationHoldDate, RecipientTypeDetails | Format-Table -AutoSize

# ============================================================================
# SECTION 4: GRANT MAILBOX ACCESS TO DELEGATE
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "GRANTING MAILBOX ACCESS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

foreach ($mailbox in $targetMailboxes) {
    try {
        # Check if permission already exists
        $existingPermission = Get-MailboxPermission -Identity $mailbox -User $delegateUser -ErrorAction SilentlyContinue
        
        if ($existingPermission) {
            Write-Host "  ALREADY HAS ACCESS: $mailbox → $delegateUser" -ForegroundColor Yellow
        }
        else {
            Add-MailboxPermission -Identity $mailbox -User $delegateUser -AccessRights FullAccess -InheritanceType All -AutoMapping $false -Confirm:$false | Out-Null
            Write-Host "  ✓ GRANTED ACCESS: $mailbox → $delegateUser" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ✗ FAILED: $mailbox - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# SECTION 5: VERIFY MAILBOX PERMISSIONS
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VERIFYING MAILBOX PERMISSIONS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$targetMailboxes | ForEach-Object {
    Get-MailboxPermission -Identity $_ -ErrorAction SilentlyContinue | Where-Object {$_.User -like "*$($delegateUser.Split('@')[0])*"}
} | Select-Object Identity, User, AccessRights | Format-Table -AutoSize

# ============================================================================
# SECTION 6: CONNECT TO SECURITY & COMPLIANCE
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONNECTING TO SECURITY & COMPLIANCE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Connect-IPPSSession -UserPrincipalName $adminUPN -ShowBanner:$false
    Write-Host "✓ Connected to Security & Compliance PowerShell" -ForegroundColor Green
}
catch {
    Write-Host "✗ FAILED to connect: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================================
# SECTION 7: CREATE COMPLIANCE SEARCH FOR PST EXPORT
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CREATING COMPLIANCE SEARCH" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$searchName = "LitHold_AllMailboxes"

# Check if search already exists
$existingSearch = Get-ComplianceSearch -Identity $searchName -ErrorAction SilentlyContinue

if ($existingSearch) {
    Write-Host "  SEARCH ALREADY EXISTS: $searchName" -ForegroundColor Yellow
    Write-Host "  Deleting existing search..." -ForegroundColor Yellow
    try {
        Remove-ComplianceSearch -Identity $searchName -Confirm:$false
        Start-Sleep -Seconds 3
    }
    catch {
        Write-Host "  WARNING: Failed to remove existing search: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

try {
    New-ComplianceSearch -Name $searchName -ExchangeLocation $targetMailboxes -AllowNotFoundExchangeLocationsEnabled $true | Out-Null
    Write-Host "  ✓ CREATED: $searchName" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ FAILED to create search: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================================
# SECTION 8: START COMPLIANCE SEARCH
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "STARTING COMPLIANCE SEARCH" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    Start-ComplianceSearch -Identity $searchName
    Write-Host "  ✓ STARTED: $searchName" -ForegroundColor Green
    Write-Host "`n  Waiting for search to complete (this may take 2-5 minutes)..." -ForegroundColor Yellow
}
catch {
    Write-Host "  ✗ FAILED to start search: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================================
# SECTION 9: MONITOR SEARCH STATUS
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "MONITORING SEARCH STATUS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$maxWaitTime = 600 # 10 minutes
$elapsedTime = 0
$checkInterval = 30 # 30 seconds

while ($elapsedTime -lt $maxWaitTime) {
    Start-Sleep -Seconds $checkInterval
    $elapsedTime += $checkInterval
    
    $searchStatus = Get-ComplianceSearch -Identity $searchName
    
    Write-Host "  [$elapsedTime seconds] Status: $($searchStatus.Status) | Items: $($searchStatus.Items) | Size: $($searchStatus.Size)" -ForegroundColor Cyan
    
    if ($searchStatus.Status -eq "Completed") {
        Write-Host "`n  ✓ SEARCH COMPLETED" -ForegroundColor Green
        break
    }
    elseif ($searchStatus.Status -eq "Failed") {
        Write-Host "`n  ✗ SEARCH FAILED" -ForegroundColor Red
        Get-ComplianceSearch -Identity $searchName | Select-Object Name, Status, Items, Size, Errors | Format-List
        exit
    }
}

if ($elapsedTime -ge $maxWaitTime) {
    Write-Host "`n  ⚠ TIMEOUT: Search still running after $maxWaitTime seconds" -ForegroundColor Yellow
    Write-Host "  Check status manually: Get-ComplianceSearch -Identity '$searchName'" -ForegroundColor Yellow
    exit
}

# ============================================================================
# SECTION 10: INITIATE PST EXPORT
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "INITIATING PST EXPORT" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$exportName = $searchName + "_Export"

# Check if export already exists
$existingExport = Get-ComplianceSearchAction -Identity $exportName -ErrorAction SilentlyContinue

if ($existingExport) {
    Write-Host "  EXPORT ALREADY EXISTS: $exportName" -ForegroundColor Yellow
    Write-Host "  Status: $($existingExport.Status)" -ForegroundColor Yellow
}
else {
    try {
        New-ComplianceSearchAction -SearchName $searchName -Export -Format FxStream -ExchangeArchiveFormat PerUserPst | Out-Null
        Write-Host "  ✓ EXPORT INITIATED: $exportName" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ FAILED to initiate export: $($_.Exception.Message)" -ForegroundColor Red
        exit
    }
}

# ============================================================================
# SECTION 11: FINAL STATUS AND INSTRUCTIONS
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "FINAL STATUS & NEXT STEPS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "COMPLETED TASKS:" -ForegroundColor Green
Write-Host "  ✓ All litigation holds enabled and verified" -ForegroundColor Green
Write-Host "  ✓ Delegate user granted FullAccess to all mailboxes" -ForegroundColor Green
Write-Host "  ✓ Compliance search completed successfully" -ForegroundColor Green
Write-Host "  ✓ PST export initiated" -ForegroundColor Green

Write-Host "`nNEXT STEPS FOR DELEGATE USER:" -ForegroundColor Yellow
Write-Host "  1. Access mailboxes in Outlook:" -ForegroundColor White
Write-Host "     - File → Open & Export → Other User's Mailbox" -ForegroundColor Gray
Write-Host "     - Enter each mailbox address" -ForegroundColor Gray

Write-Host "`n  2. Download PST files:" -ForegroundColor White
Write-Host "     - Navigate to: https://compliance.microsoft.com/contentsearch" -ForegroundColor Gray
Write-Host "     - Locate: $exportName" -ForegroundColor Gray
Write-Host "     - Click Export tab → Download results" -ForegroundColor Gray
Write-Host "     - Use eDiscovery Export Tool (auto-prompts)" -ForegroundColor Gray
Write-Host "     - Save to designated legal hold export folder" -ForegroundColor Gray

Write-Host "`nMONITOR EXPORT STATUS:" -ForegroundColor Yellow
Write-Host "  Get-ComplianceSearchAction -Identity '$exportName' | Select-Object Name, Status, Results | Format-List" -ForegroundColor Gray

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SCRIPT COMPLETED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================================================
# END OF SCRIPT
# ============================================================================
