<#
.SYNOPSIS
    Creates a temporary SMB share on a workstation for reverse-push file transfers
.DESCRIPTION
    Run via SYSTEM remote session (SYSTEM context) on the destination workstation.
    Creates a staging folder, shares it as {ShareName}$ with FullAccess for the
    specified domain admin account, and grants matching NTFS permissions.
    Use when the source server cannot authenticate to the workstation as SYSTEM
    (server-push pattern avoids workstation needing to pull from the server).

    After the transfer completes, remove the share:
        Remove-SmbShare -Name $shareName -Force

.PARAMETER StagingPath
    Local path for the staging folder. Default: C:\Temp\FileTransfer
.PARAMETER ShareName
    SMB share name (trailing $ makes it hidden). Default: FileTransfer$
.PARAMETER GrantUser
    Domain account to grant FullAccess (share + NTFS). Default: prompt required.

.EXAMPLE
    # Run defaults — edit variables at top of script before deploying
    .\New-TempFileTransferShare.ps1

.NOTES
    Context: SYSTEM remote session (SYSTEM)
#>

# --- Configuration ---
$stagingPath = 'C:\Temp\FileTransfer'   # Adjust per transfer
$shareName   = 'FileTransfer$'           # $ suffix hides from browse
$grantUser   = 'DOMAIN\mspadmin'         # Replace DOMAIN with actual domain

# --- Create staging folder ---
if (-not (Test-Path $stagingPath)) {
    New-Item -Path $stagingPath -ItemType Directory -Force | Out-Null
    Write-Host "Created: $stagingPath"
} else {
    Write-Host "Exists: $stagingPath"
}

# --- Remove existing share if present (idempotent) ---
$existing = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Remove-SmbShare -Name $shareName -Force
    Write-Host "Removed existing share: $shareName"
}

# --- Create share with FullAccess for domain admin ---
New-SmbShare -Name $shareName -Path $stagingPath -FullAccess $grantUser `
    -Description 'Temp file transfer staging' | Out-Null
Write-Host "Share created: \\$env:COMPUTERNAME\$shareName"

# --- Grant matching NTFS permissions ---
$acl  = Get-Acl $stagingPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $grantUser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
)
$acl.AddAccessRule($rule)
Set-Acl -Path $stagingPath -AclObject $acl
Write-Host "NTFS FullControl granted to $grantUser"

# --- Disk space check ---
$drive = (Get-Item $stagingPath).PSDrive.Name
$free  = [math]::Round((Get-PSDrive $drive).Free / 1GB, 1)
Write-Host "Free space on ${drive}: ${free} GB"

# --- Next step prompt ---
Write-Host "`n--- From source server (SYSTEM remote session) ---"
Write-Host "robocopy ""<source-path>"" ""\\$env:COMPUTERNAME\$shareName"" <filter> /J /Z /ETA /LOG:C:\Temp\transfer.log /TEE /NP"
Write-Host "`n--- Cleanup after copy ---"
Write-Host "Remove-SmbShare -Name '$shareName' -Force"
