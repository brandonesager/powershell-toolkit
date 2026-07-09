<#
.SYNOPSIS
    Add a per-SPN NTLM-only credential delegation exception so mstsc "Remember me"
    persists for a specific RDP target that uses NTLM (Win7/2008 R2/non-domain host).

.DESCRIPTION
    Windows 11 (and Win10 with updated security defaults) refuses to delegate saved
    credentials to NTLM-only targets unless the CredentialsDelegation policy explicitly
    allows it. This script enables AllowSavedCredentialsWhenNTLMOnly and adds a single
    SPN entry for the specified target, leaving all other targets unchanged.

    Registry path:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
        AllowSavedCredentialsWhenNTLMOnly = 1
        ConcatenateDefaults_AllowSavedNTLMOnly = 1
      HKLM\...\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly\
        1 = "TERMSRV/<target>"

    The script does not disable global DisablePasswordSaving if it is set; that requires
    a separate GPO change. Run Get-RdpCredDelegationState.ps1 first to confirm the
    correct fix path.

    Runs gpupdate /target:computer /force after writing.

.PARAMETER TargetSPN
    The SPN string in "TERMSRV/<hostname-or-ip>" format.
    Example: "TERMSRV/10.32.1.25" or "TERMSRV/backup.corp.local"

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1)

.KEYWORDS
    RDP, mstsc, NTLM, saved credentials, CredentialsDelegation, AllowSavedCredentialsWhenNTLMOnly,
    Win11, Remember me, TERMSRV, SPN
#>
#!ps
#maxlength=100000
#timeout=120000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$TargetSPN
)

$ErrorActionPreference = 'Stop'

$cdPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
$listKey = Join-Path $cdPath 'AllowSavedCredentialsWhenNTLMOnly'

Write-Output "Set-RdpCredDelegationNtlmOnly"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("TargetSPN : {0}" -f $TargetSPN)
Write-Output ""

# --- Before ---
Write-Output "=== Before ==="
if (Test-Path $cdPath) {
    Get-ItemProperty $cdPath | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | Write-Output
} else { Write-Output "  $cdPath not present" }
if (Test-Path $listKey) {
    Get-ItemProperty $listKey | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | Write-Output
} else { Write-Output "  $listKey not present" }
Write-Output ""

# --- Apply ---
Write-Output "=== Applying ==="

if (-not (Test-Path $cdPath))  { New-Item $cdPath  -Force | Out-Null; Write-Output ("  Created: {0}" -f $cdPath) }
if (-not (Test-Path $listKey)) { New-Item $listKey -Force | Out-Null; Write-Output ("  Created: {0}" -f $listKey) }

# Check for next available numeric index in the SPN list
$existing = Get-ItemProperty $listKey -ErrorAction SilentlyContinue
$alreadyPresent = $existing.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -eq $TargetSPN }
if ($alreadyPresent) {
    Write-Output ("  SPN already in list at index {0}: {1}" -f $alreadyPresent.Name, $alreadyPresent.Value)
} else {
    $indices = @($existing.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | Select-Object -ExpandProperty Name | ForEach-Object { [int]$_ })
    $nextIdx = if ($indices.Count -gt 0) { ($indices | Measure-Object -Maximum).Maximum + 1 } else { 1 }
    New-ItemProperty $listKey -Name ([string]$nextIdx) -PropertyType String -Value $TargetSPN -Force | Out-Null
    Write-Output ("  Added SPN at index {0}: {1}" -f $nextIdx, $TargetSPN)
}

New-ItemProperty $cdPath -Name 'AllowSavedCredentialsWhenNTLMOnly'         -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty $cdPath -Name 'ConcatenateDefaults_AllowSavedNTLMOnly'    -PropertyType DWord -Value 1 -Force | Out-Null
Write-Output "  AllowSavedCredentialsWhenNTLMOnly = 1"
Write-Output "  ConcatenateDefaults_AllowSavedNTLMOnly = 1"
Write-Output ""

# --- After ---
Write-Output "=== After ==="
Get-ItemProperty $cdPath  | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | Write-Output
Get-ItemProperty $listKey | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | Write-Output

# --- gpupdate ---
Write-Output "=== Refreshing computer policy ==="
& gpupdate /target:computer /force 2>&1 | Out-String | Write-Output

Write-Output "=== Done ==="
Write-Output "Have the user:"
Write-Output "  1. Close mstsc completely."
Write-Output ("  2. Reopen Remote Desktop, connect to {0}." -f ($TargetSPN -replace '^TERMSRV/', ''))
Write-Output "  3. Enter credentials and tick 'Remember me'."
Write-Output "  4. Disconnect and reconnect - credentials should pre-fill."
