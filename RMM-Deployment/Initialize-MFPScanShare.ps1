<#
.SYNOPSIS
    Set up network sharing for multifunction printer scanning

.DESCRIPTION
    Creates and configures a local service account, SMB share, and NTFS permissions
    for MFP (multifunction printer) scan-to-folder functionality. Configures network
    profile, firewall rules, and SMB protocols for secure file sharing.

.PARAMETER ServiceAccountPassword
    SecureString password for the local.mfp.scan service account

.PARAMETER SharePath
    Path for the scan folder (default: C:\Scans)

.EXAMPLE
    .\Initialize-MFPScanShare.ps1 -ServiceAccountPassword (Read-Host -AsSecureString "Password")

.EXAMPLE
    .\Initialize-MFPScanShare.ps1 -ServiceAccountPassword $secPwd -SharePath "D:\Scans"

.NOTES
    Date: 2026-02-06
    Category: RMM-Deployment

.KEYWORDS
    scanner, MFP, SMB, provision, SYSTEM
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [SecureString]$ServiceAccountPassword,

    [string]$SharePath = "C:\Scans"
)

$ErrorActionPreference = "Stop"

try {
    # Verify administrative privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Output "ERROR: This script requires administrative privileges."
        exit 1
    }

    # -------------------------
    # SECTION 1: Local Service Account Management
    # -------------------------
    Write-Output "=== CONFIGURING LOCAL SERVICE ACCOUNT ==="

    $ServiceAccountName = "local.mfp.scan"
    $ServiceAccountFullName = "$env:COMPUTERNAME\$ServiceAccountName"
    $PlainPassword = (New-Object System.Net.NetworkCredential("", $ServiceAccountPassword)).Password

    Write-Output "Setting up service account: $ServiceAccountName"
    try {
        $ExistingUser = Get-LocalUser -Name $ServiceAccountName -ErrorAction Stop
        Write-Output "Account '$ServiceAccountName' found. Resetting password..."
        $ExistingUser | Set-LocalUser -Password $ServiceAccountPassword
        Write-Output "Password reset successfully for '$ServiceAccountName'"
    }
    catch {
        Write-Output "Account '$ServiceAccountName' not found. Creating new account..."
        try {
            New-LocalUser -Name $ServiceAccountName -Password $ServiceAccountPassword -FullName "MFP Scanner Service Account" -Description "Service account for MFP scanning" -PasswordNeverExpires -UserMayNotChangePassword
            Write-Output "Successfully created account '$ServiceAccountName'"
        }
        catch {
            Write-Output "ERROR: Failed to create account '$ServiceAccountName': $($_.Exception.Message)"
            exit 1
        }
    }

    # -------------------------
    # SECTION 2: Network Profile Configuration
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURING NETWORK PROFILE ==="

    Write-Output "Detecting active Ethernet adapters..."
    $EthernetAdapters = Get-NetConnectionProfile | Where-Object {
        $_.InterfaceAlias -like "Ethernet*" -and $_.ConnectionState -eq "Connected"
    }

    if ($EthernetAdapters) {
        foreach ($Adapter in $EthernetAdapters) {
            Write-Output "Found adapter: $($Adapter.InterfaceAlias) - Current category: $($Adapter.NetworkCategory)"

            if ($Adapter.NetworkCategory -ne "Private") {
                try {
                    Set-NetConnectionProfile -InterfaceAlias $Adapter.InterfaceAlias -NetworkCategory Private
                    Write-Output "Set '$($Adapter.InterfaceAlias)' to Private network category"
                }
                catch {
                    Write-Output "WARNING: Failed to set network category for '$($Adapter.InterfaceAlias)': $($_.Exception.Message)"
                }
            }
            else {
                Write-Output "'$($Adapter.InterfaceAlias)' already set to Private"
            }
        }
    }
    else {
        Write-Output "WARNING: No active Ethernet adapters found"
    }

    # -------------------------
    # SECTION 3: SMB Protocol Configuration
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURING SMB PROTOCOL ==="

    Write-Output "Enabling SMB2/SMB3 protocols for secure file sharing..."
    try {
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
        Write-Output "SMB2/SMB3 protocols enabled"
    }
    catch {
        Write-Output "WARNING: Failed to configure SMB protocols: $($_.Exception.Message)"
    }

    # -------------------------
    # SECTION 4: Windows Firewall Configuration
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURING WINDOWS FIREWALL ==="

    Write-Output "Enabling File and Printer Sharing firewall rules..."
    try {
        Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction Stop
        Write-Output "File and Printer Sharing firewall rules enabled"
    }
    catch {
        Write-Output "WARNING: Failed to enable firewall rules: $($_.Exception.Message)"
    }

    # -------------------------
    # SECTION 5: Scans Folder Creation and NTFS Permissions
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURING SCANS FOLDER ==="

    $ScanFolderPath = $SharePath

    Write-Output "Checking if scan folder exists: $ScanFolderPath"
    if (-not (Test-Path $ScanFolderPath)) {
        try {
            New-Item -ItemType Directory -Path $ScanFolderPath -Force | Out-Null
            Write-Output "Created scan folder: $ScanFolderPath"
        }
        catch {
            Write-Output "ERROR: Failed to create scan folder: $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Output "Scan folder already exists: $ScanFolderPath"
    }

    Write-Output "Applying NTFS permissions for '$ServiceAccountFullName'..."
    try {
        $IcaclsResult = & icacls "`"$ScanFolderPath`"" /grant "`"$ServiceAccountFullName`:(OI)(CI)F`"" /T /C 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Output "NTFS permissions applied successfully"
        }
        else {
            Write-Output "WARNING: NTFS permission command completed with warnings: $IcaclsResult"
        }
    }
    catch {
        Write-Output "ERROR: Failed to apply NTFS permissions: $($_.Exception.Message)"
        exit 1
    }

    # -------------------------
    # SECTION 6: SMB Network Share Configuration
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURING SMB NETWORK SHARE ==="

    $ShareName = "Scans"

    Write-Output "Checking if SMB share '$ShareName' exists..."
    $ExistingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue

    if (-not $ExistingShare) {
        try {
            New-SmbShare -Name $ShareName -Path $ScanFolderPath -FullAccess $ServiceAccountFullName -Description "MFP Scanner shared folder"
            Write-Output "Created SMB share '$ShareName' pointing to $ScanFolderPath"
        }
        catch {
            Write-Output "ERROR: Failed to create SMB share: $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Output "SMB share '$ShareName' already exists"

        try {
            Revoke-SmbShareAccess -Name $ShareName -AccountName $ServiceAccountFullName -Confirm:$false -ErrorAction SilentlyContinue
            Grant-SmbShareAccess -Name $ShareName -AccountName $ServiceAccountFullName -AccessRight Full -Confirm:$false
            Write-Output "Updated SMB share permissions for '$ServiceAccountFullName'"
        }
        catch {
            Write-Output "WARNING: Failed to update share permissions: $($_.Exception.Message)"
        }
    }

    Write-Output "Configuring advanced sharing properties..."
    try {
        Set-SmbShare -Name $ShareName -ConcurrentUserLimit 0 -Confirm:$false
        Set-SmbShare -Name $ShareName -FolderEnumerationMode AccessBased -Confirm:$false
        Write-Output "Advanced sharing properties configured"
    }
    catch {
        Write-Output "WARNING: Failed to configure advanced sharing properties: $($_.Exception.Message)"
    }

    # -------------------------
    # SECTION 7: Configuration Summary and Verification
    # -------------------------
    Write-Output ""
    Write-Output "=== CONFIGURATION SUMMARY ==="

    Write-Output "Service Account: $ServiceAccountFullName"
    Write-Output "Scan Folder: $ScanFolderPath"
    Write-Output "Share Name: \\$env:COMPUTERNAME\$ShareName"
    Write-Output "Share Path: $ScanFolderPath"

    Write-Output ""
    Write-Output "Verifying share configuration..."
    try {
        $ShareInfo = Get-SmbShare -Name $ShareName
        Write-Output "Share Status: Active"
        Write-Output "Share Path: $($ShareInfo.Path)"

        $ShareAccess = Get-SmbShareAccess -Name $ShareName
        Write-Output ""
        Write-Output "Share Permissions:"
        foreach ($Access in $ShareAccess) {
            Write-Output "  $($Access.AccountName): $($Access.AccessRight)"
        }
    }
    catch {
        Write-Output "WARNING: Failed to verify share configuration: $($_.Exception.Message)"
    }

    # -------------------------
    # SECTION 8: Security Monitoring (Recent Authentication Events)
    # -------------------------
    Write-Output ""
    Write-Output "=== SECURITY MONITORING ==="

    Write-Output "Checking for recent failed logon attempts (last 15 minutes)..."
    try {
        $FailedLogons = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625)]]" -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-15) } |
            Select-Object TimeCreated,
                         @{Name='Account';Expression={$_.Properties[5].Value}},
                         @{Name='Workstation';Expression={$_.Properties[11].Value}},
                         @{Name='SourceIP';Expression={$_.Properties[19].Value}}

        if ($FailedLogons) {
            Write-Output "Recent failed logon attempts found:"
            $FailedLogons | Format-Table -AutoSize | Out-String | Write-Output
        }
        else {
            Write-Output "No recent failed logon attempts detected"
        }
    }
    catch {
        Write-Output "Unable to retrieve security logs (this is normal if no events exist)"
    }

    Write-Output "Checking for recent SMB authentication failures (last 15 minutes)..."
    try {
        $SmbFailures = Get-WinEvent -LogName "Microsoft-Windows-SmbServer/Security" -FilterXPath "*[System[(EventID=551)]]" -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-15) } |
            Select-Object TimeCreated, Id, Message

        if ($SmbFailures) {
            Write-Output "Recent SMB authentication failures found:"
            $SmbFailures | Format-Table -AutoSize | Out-String | Write-Output
        }
        else {
            Write-Output "No recent SMB authentication failures detected"
        }
    }
    catch {
        Write-Output "Unable to retrieve SMB security logs (this is normal if no events exist)"
    }

    Write-Output ""
    Write-Output "=== SETUP COMPLETED SUCCESSFULLY ==="
    Write-Output "Your MFP scanner should now be able to access the share at: \\$env:COMPUTERNAME\Scans"
    Write-Output "Use credentials: $ServiceAccountFullName with the password you specified"

    exit 0

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "Stack: $($_.ScriptStackTrace)"
    exit 1
}
