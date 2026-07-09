#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostic one-liner for Konica MFP SMB scan destination issues.

.DESCRIPTION
    Checks all common failure points for SMB scanning from MFPs.

.NOTES
    Date: 2025-12-05
    Context: Contoso scanner "failing to connect to server" errors
    Category: Diagnostics
.EXAMPLE
    # Run diagnostics for SMB scan setup
    .\Get-MFPScanDiagnostics.ps1

.KEYWORDS
    scanner, MFP, SMB, diagnose, Konica
#>

[CmdletBinding()]
param()

try {
    Write-Host "=== MFP SCAN SHARE DIAGNOSTIC ===" -ForegroundColor Cyan

    # 1. Network Profile (Public blocks SMB)
    Write-Host "`n[1] Network Profile:" -ForegroundColor Yellow
    Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory | Format-Table -AutoSize
    $publicProfile = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' }
    if ($publicProfile) {
        Write-Host "  WARNING: Public profile detected - SMB will be blocked!" -ForegroundColor Red
        Write-Host "  Fix: Set-NetConnectionProfile -InterfaceAlias '$($publicProfile.InterfaceAlias)' -NetworkCategory Private" -ForegroundColor Yellow
    }

    # 2. SMB Shares containing 'Scan'
    Write-Host "[2] SMB Shares:" -ForegroundColor Yellow
    $shares = Get-SmbShare | Where-Object { $_.Name -like "*Scan*" }
    if ($shares) {
        $shares | Select-Object Name, Path, Description | Format-Table -AutoSize
    }
    else {
        Write-Host "  No scan shares found - share may need to be created" -ForegroundColor Red
    }

    # 3. Service accounts for scanning
    Write-Host "[3] Service Accounts:" -ForegroundColor Yellow
    $scanUsers = Get-LocalUser | Where-Object { $_.Name -match 'scan|mfp' }
    if ($scanUsers) {
        $scanUsers | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize
    }
    else {
        Write-Host "  No scan service accounts found" -ForegroundColor Red
    }

    # 4. Scans folders on C: drive
    Write-Host "[4] Scans Folders:" -ForegroundColor Yellow
    $scanFolders = Get-ChildItem C:\ -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Scan*" }
    if ($scanFolders) {
        $scanFolders | Select-Object Name, FullName | Format-Table -AutoSize
        if ($scanFolders.Count -gt 1) {
            Write-Host "  WARNING: Multiple scan folders found - may cause confusion" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  No scan folders found in C:\" -ForegroundColor Red
    }

    # 5. Firewall rules for File and Printer Sharing
    Write-Host "[5] Firewall Rules:" -ForegroundColor Yellow
    $fwRules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true }
    $ruleCount = ($fwRules | Measure-Object).Count
    Write-Host "  File and Printer Sharing rules enabled: $ruleCount"
    if ($ruleCount -lt 5) {
        Write-Host "  WARNING: Some rules may be disabled" -ForegroundColor Yellow
        Write-Host "  Fix: Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'" -ForegroundColor Yellow
    }

    # 6. Check C:\Scans permissions if it exists
    Write-Host "[6] Scans Folder Permissions:" -ForegroundColor Yellow
    if (Test-Path "C:\Scans") {
        $acl = Get-Acl "C:\Scans"
        $acl.Access | Where-Object { $_.IdentityReference -match 'scan|mfp|Everyone|Users' } |
            Select-Object IdentityReference, FileSystemRights, AccessControlType | Format-Table -AutoSize
    }
    else {
        Write-Host "  C:\Scans does not exist" -ForegroundColor Red
    }

    Write-Host "`n=== DIAGNOSTIC COMPLETE ===" -ForegroundColor Cyan

    # Summary of common fixes
    Write-Host "`nCommon Fixes:" -ForegroundColor White
    Write-Host "  1. Set network to Private: Set-NetConnectionProfile -InterfaceAlias 'Ethernet' -NetworkCategory Private"
    Write-Host "  2. Enable firewall rules: Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'"
    Write-Host "  3. Create scan share: New-SmbShare -Name 'Scans' -Path 'C:\Scans' -FullAccess 'local.mfp.scan'"

    exit 0
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
