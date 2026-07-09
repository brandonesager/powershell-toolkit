# Configure-MFPScanShare-RMM.ps1
# RMM-deployable version for MFP scan share configuration (when account already exists)
# Error: Konica error 16714711 (SMB connection/authentication failure)

<#
.SYNOPSIS
    Configures MFP scan share infrastructure when local.mfp.scan account already exists.

.DESCRIPTION
    Non-interactive version for RMM deployment. Assumes local.mfp.scan account exists.
    Configures:
    - Network profile (Private)
    - SMB2/SMB3 protocols
    - File and Printer Sharing firewall rules
    - C:\Scans folder with NTFS permissions
    - SMB share with proper permissions

.NOTES
    Run via RMM SYSTEM remote session as SYSTEM. Use after verifying local.mfp.scan account exists.
    Category: RMM-Deployment
.KEYWORDS
    scanner, MFP, SMB, RMM, SYSTEM
#>

$ServiceAccountName = "local.mfp.scan"
$ServiceAccountFullName = "$env:COMPUTERNAME\$ServiceAccountName"
$ScanFolderPath = "C:\Scans"
$ShareName = "Scans"

# Verify account exists
$Account = Get-LocalUser -Name $ServiceAccountName -EA SilentlyContinue
if (-not $Account) { 
    Write-Output "ERROR: Account $ServiceAccountName does not exist"
    exit 1 
}
Write-Output "Account verified: $ServiceAccountFullName"

try {
    # Network Profile -> Private
    Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne 'Private' } | ForEach-Object {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
        Write-Output "Set $($_.InterfaceAlias) to Private"
    }

    # SMB Protocol
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
    Write-Output "SMB2/3 enabled"

    # Firewall
    Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -EA SilentlyContinue
    Write-Output "Firewall rules enabled"

    # Scans folder
    if (-not (Test-Path $ScanFolderPath)) {
        New-Item -ItemType Directory -Path $ScanFolderPath -Force | Out-Null
    }
    icacls $ScanFolderPath /grant "${ServiceAccountFullName}:(OI)(CI)F" /T /C /Q
    Write-Output "Folder created/permissions set: $ScanFolderPath"

    # SMB Share
    $Share = Get-SmbShare -Name $ShareName -EA SilentlyContinue
    if (-not $Share) {
        New-SmbShare -Name $ShareName -Path $ScanFolderPath -FullAccess $ServiceAccountFullName -Description "MFP Scanner"
        Write-Output "Created share: \\$env:COMPUTERNAME\$ShareName"
    } else {
        # Update permissions on existing share
        Grant-SmbShareAccess -Name $ShareName -AccountName $ServiceAccountFullName -AccessRight Full -Force | Out-Null
        Write-Output "Updated existing share permissions"
    }

    # Verify
    Write-Output "`n=== RESULT ==="
    Get-SmbShare -Name $ShareName | Select-Object Name, Path, ShareState | Format-List
    Get-SmbShareAccess -Name $ShareName | Select-Object AccountName, AccessRight | Format-List
    Write-Output "Share UNC: \\$env:COMPUTERNAME\$ShareName"

    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
