<#
.SYNOPSIS
    Mailbox & license diagnostic for Exchange Online send failures.
.DESCRIPTION
    Checks mailbox status, quota, folder sizes, license provisioning,
    and recent message trace. Requires ExchangeOnlineManagement and
    Microsoft.Graph.Users modules.
.PARAMETER UPN
    User principal name to diagnose.
.EXAMPLE
    .\Get-MailboxLicenseDiagnostic.ps1 -UPN user@contoso.com
.SOURCE
    Date: 2026-02-10
#>
param(
    [Parameter(Mandatory)]
    [string]$UPN
)

$ErrorActionPreference = 'Stop'

# --- Connection check ---
Write-Host "`n=== Mailbox & License Diagnostic ===" -ForegroundColor Cyan
Write-Host "Target: $UPN`n"

try { Get-EXOMailbox -Identity $UPN -ErrorAction Stop | Out-Null }
catch [System.Management.Automation.CommandNotFoundException] {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false
}
catch {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false
}

try { Get-MgUser -UserId $UPN -ErrorAction Stop | Out-Null }
catch [System.Management.Automation.CommandNotFoundException] {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes User.Read.All, Organization.Read.All -NoWelcome
}
catch {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes User.Read.All, Organization.Read.All -NoWelcome
}

# --- 1. Mailbox existence & type ---
Write-Host "`n--- 1. Mailbox Status ---" -ForegroundColor Green
try {
    $mbx = Get-EXOMailbox -Identity $UPN -PropertySets Quota
    Write-Host "Display Name     : $($mbx.DisplayName)"
    Write-Host "Mailbox Type     : $($mbx.RecipientTypeDetails)"
    Write-Host "Prohibit Send    : $($mbx.ProhibitSendQuota)"
    Write-Host "Prohibit SendRecv: $($mbx.ProhibitSendReceiveQuota)"
    Write-Host "Issue Warning    : $($mbx.IssueWarningQuota)"
    Write-Host "Litigation Hold  : $($mbx.LitigationHoldEnabled)"
} catch {
    Write-Host "MAILBOX NOT FOUND — license may not have provisioned yet" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)"
}

# --- 2. Mailbox statistics ---
Write-Host "`n--- 2. Mailbox Size ---" -ForegroundColor Green
try {
    $stats = Get-EXOMailboxStatistics -Identity $UPN
    Write-Host "Total Size       : $($stats.TotalItemSize)"
    Write-Host "Item Count       : $($stats.ItemCount)"
    Write-Host "Deleted Size     : $($stats.TotalDeletedItemSize)"

    # Parse size for quota comparison
    if ($stats.TotalItemSize -match '([\d,\.]+)\s+bytes') {
        $sizeBytes = [int64]($Matches[1] -replace ',','')
        $sizeGB = [math]::Round($sizeBytes / 1GB, 2)
        Write-Host "Size (GB)        : $sizeGB GB"
        if ($sizeGB -gt 49) {
            Write-Host "WARNING: Mailbox approaching 50 GB default limit!" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Could not get mailbox stats: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 3. Key folder sizes ---
Write-Host "`n--- 3. Key Folders ---" -ForegroundColor Green
try {
    $folders = Get-EXOMailboxFolderStatistics -Identity $UPN |
        Where-Object { $_.Name -in @('Inbox','Sent Items','Deleted Items','Junk Email','Outbox','Drafts') } |
        Select-Object Name, ItemsInFolder, FolderSize |
        Sort-Object ItemsInFolder -Descending
    $folders | Format-Table -AutoSize
} catch {
    Write-Host "Could not get folder stats: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 4. License & service plan status ---
Write-Host "--- 4. License Details ---" -ForegroundColor Green
try {
    $licenses = Get-MgUserLicenseDetail -UserId $UPN -Property SkuPartNumber, ServicePlans
    foreach ($lic in $licenses) {
        Write-Host "`nSKU: $($lic.SkuPartNumber)" -ForegroundColor White
        $exchPlans = $lic.ServicePlans | Where-Object {
            $_.ServicePlanName -match 'EXCHANGE|INFORMATION_BARRIERS|MIP_S'
        }
        if ($exchPlans) {
            $exchPlans | Format-Table ServicePlanName, ProvisioningStatus -AutoSize
        }

        # Flag any errors
        $errorPlans = $lic.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Error' }
        if ($errorPlans) {
            Write-Host "LICENSE ERRORS DETECTED:" -ForegroundColor Red
            $errorPlans | Format-Table ServicePlanName, ProvisioningStatus -AutoSize
        }
    }
    if (-not $licenses) {
        Write-Host "NO LICENSES ASSIGNED" -ForegroundColor Red
    }
} catch {
    Write-Host "Could not get license details: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 5. License assignment state (error check) ---
Write-Host "--- 5. License Assignment State ---" -ForegroundColor Green
try {
    $user = Get-MgUser -UserId $UPN -Property LicenseAssignmentStates
    foreach ($state in $user.LicenseAssignmentStates) {
        $status = if ($state.Error) { "ERROR: $($state.Error)" } else { "OK" }
        Write-Host "SKU $($state.SkuId) — $status"
        if ($state.Error) {
            Write-Host "  Subcode: $($state.ErrorSubcode)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Could not check assignment state: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 6. Recent message trace (last 24h) ---
Write-Host "`n--- 6. Message Trace (last 24h, outbound) ---" -ForegroundColor Green
try {
    $trace = Get-MessageTrace -SenderAddress $UPN -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) |
        Select-Object Received, RecipientAddress, Subject, Status |
        Sort-Object Received -Descending |
        Select-Object -First 10
    if ($trace) {
        $trace | Format-Table -AutoSize
    } else {
        Write-Host "No outbound messages in last 24h" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not run message trace: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n=== Diagnostic Complete ===" -ForegroundColor Cyan
