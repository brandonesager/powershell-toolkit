#!ps
#timeout=20000
#maxlength=3000
<#
.SYNOPSIS
    Test SMB auth + write to a scan-to-folder share using a service account credential.

.DESCRIPTION
    Emulates what an MFP does when scanning to folder: maps the SMB share with the
    supplied service account credential, writes a small test file, and removes it.
    Validates password match and write permission without waiting for a physical scan.

    Useful at any stage of a scan-to-folder ticket: after creating the local account,
    after rotating the password, or when isolating "Failed to connect to server" from
    other Konica error codes.

.PARAMETER ServiceAccount
    Local account name. Defaults to local.mfp.scan.

.PARAMETER Password
    Plain-text password. Pulled from your password/documentation system before invocation.

.PARAMETER Share
    Share name on the workstation. Defaults to Scans.

.PARAMETER ComputerName
    Workstation hosting the share. Defaults to local machine; supply a remote name to
    test from another box on the same subnet (closer to the MFP's path).

.NOTES
    Category: Diagnostics
    Context: RMM shell (SYSTEM, #!ps) or SYSTEM remote session

.EXAMPLE
    & .\Test-SmbScanAuth.ps1 -Password '<pwd>'

.EXAMPLE
    & .\Test-SmbScanAuth.ps1 -ServiceAccount 'mfp.scanner' -Password '<pwd>' -Share 'ScanDrop'

.KEYWORDS
    scan, MFP, SMB, scan-to-folder, auth, credential, test, validate, Konica, Kyocera
#>

param(
    [string]$ServiceAccount = 'local.mfp.scan',
    [Parameter(Mandatory = $true)][string]$Password,
    [string]$Share = 'Scans',
    [string]$ComputerName = $env:COMPUTERNAME
)

$path = "\\$ComputerName\$Share"
$user = "$ComputerName\$ServiceAccount"

try {
    New-SmbMapping -RemotePath $path -UserName $user -Password $Password -ErrorAction Stop | Out-Null
    Write-Output "AUTH OK: mapped $path as $ServiceAccount"
    $stamp = Get-Date -Format 'HHmmss'
    $f = Join-Path $path "preflight-test-$stamp.txt"
    "scan-test $(Get-Date)" | Out-File -FilePath $f -Encoding ASCII
    if (Test-Path $f) {
        $size = (Get-Item $f).Length
        Write-Output "WRITE OK: $((Get-Item $f).Name) ($size bytes)"
        Remove-Item $f -Force
        Write-Output "CLEANUP OK"
    } else {
        Write-Output "WRITE FAILED"
    }
    Remove-SmbMapping -RemotePath $path -Force -UpdateProfile -ErrorAction SilentlyContinue
} catch {
    Write-Output "AUTH FAILED: $($_.Exception.Message)"
    Remove-SmbMapping -RemotePath $path -Force -UpdateProfile -ErrorAction SilentlyContinue
}
