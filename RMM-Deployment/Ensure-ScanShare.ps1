<#
.SYNOPSIS
    Ensure SMB scan share exists with correct permissions for MFP scan-to-folder

.DESCRIPTION
    Idempotent script for RMM (PowerShell 5.1, SYSTEM context).
    Creates or repairs SMB share for MFP scanning. Verifies NTFS and share permissions.
    Reports workstation IP for MFP address book configuration.

    Exit Codes:
    - 0: Share exists and is correctly configured
    - 112: Share created or permissions fixed
    - 1: Error occurred

.PARAMETER ShareName
    Name of the SMB share (default: scans)

.PARAMETER FolderPath
    Local path for scan folder (default: C:\Scans)

.EXAMPLE
    .\Ensure-ScanShare.ps1
    .\Ensure-ScanShare.ps1 -ShareName "MyScanShare" -FolderPath "D:\Scans"

.NOTES
    Date: 2026-01-26
#>
param(
    [string]$ShareName = "scans",
    [string]$FolderPath = "C:\Scans"
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

try {
    $fixedSomething = $false

    # Get workstation IP (exclude loopback and APIPA)
    Write-Log "Getting workstation IP address..."
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.InterfaceAlias -notmatch 'Loopback' -and
        $_.PrefixOrigin -ne 'WellKnown' -and
        $_.IPAddress -notmatch '^169\.254\.'
    }

    if ($null -eq $ipAddresses -or $ipAddresses.Count -eq 0) {
        Write-Output "ERROR: No valid IPv4 address found"
        exit 1
    }

    $workstationIP = $ipAddresses[0].IPAddress
    Write-Log "Workstation IP: $workstationIP"

    # Check if folder exists
    Write-Log "Checking folder: $FolderPath"
    if (-not (Test-Path $FolderPath)) {
        Write-Log "Creating folder: $FolderPath" "WARN"
        New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
        $fixedSomething = $true
    }

    # Check if share exists
    Write-Log "Checking SMB share: $ShareName"
    $existingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue

    if ($null -eq $existingShare) {
        # Create share
        Write-Log "Creating SMB share: $ShareName -> $FolderPath" "WARN"
        New-SmbShare -Name $ShareName -Path $FolderPath -FullAccess "Everyone" | Out-Null
        $fixedSomething = $true
        Write-Log "Share created successfully"
    } else {
        Write-Log "Share exists: $($existingShare.Path)"

        # Verify share points to correct path
        if ($existingShare.Path -ne $FolderPath) {
            Write-Log "Share path mismatch: expected $FolderPath, found $($existingShare.Path)" "WARN"
            $FolderPath = $existingShare.Path
        }

        # Check share permissions
        $shareAccess = Get-SmbShareAccess -Name $ShareName
        $everyoneAccess = $shareAccess | Where-Object { $_.AccountName -eq "Everyone" }

        if ($null -eq $everyoneAccess -or $everyoneAccess.AccessRight -ne "Full") {
            Write-Log "Fixing share permissions - granting Everyone Full access" "WARN"
            Grant-SmbShareAccess -Name $ShareName -AccountName "Everyone" -AccessRight Full -Force | Out-Null
            $fixedSomething = $true
        } else {
            Write-Log "Share permissions OK: Everyone has Full access"
        }
    }

    # Check NTFS permissions
    Write-Log "Checking NTFS permissions on: $FolderPath"
    $acl = Get-Acl $FolderPath
    $everyoneNTFS = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone" -and
        $_.FileSystemRights -match "FullControl"
    }

    if ($null -eq $everyoneNTFS) {
        Write-Log "Fixing NTFS permissions - granting Everyone FullControl" "WARN"
        $result = icacls $FolderPath /grant "Everyone:(OI)(CI)F" /T 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "ERROR: Failed to set NTFS permissions: $result"
            exit 1
        }
        $fixedSomething = $true
    } else {
        Write-Log "NTFS permissions OK: Everyone has FullControl"
    }

    # Final status report
    Write-Log "=== SCAN SHARE STATUS ===" "INFO"
    Write-Log "Workstation IP: $workstationIP"
    Write-Log "Share Path: \\$env:COMPUTERNAME\$ShareName"
    Write-Log "Local Path: $FolderPath"
    Write-Log "Share Permissions: Everyone = Full"
    Write-Log "NTFS Permissions: Everyone = FullControl"

    # Output for RMM variable capture
    $output = @{
        Status = if ($fixedSomething) { "FIXED" } else { "OK" }
        WorkstationIP = $workstationIP
        ShareUNC = "\\$env:COMPUTERNAME\$ShareName"
        LocalPath = $FolderPath
        ComputerName = $env:COMPUTERNAME
    }
    Write-Output ($output | ConvertTo-Json -Compress)

    # Exit with appropriate code
    if ($fixedSomething) {
        Write-Log "Share was created or permissions were fixed" "WARN"
        exit 112  # Partial success - fixed issues
    } else {
        Write-Log "All checks passed - share ready for scanning"
        exit 0
    }

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Log "Exception: $($_.Exception.Message)" "ERROR"
    exit 1
}
