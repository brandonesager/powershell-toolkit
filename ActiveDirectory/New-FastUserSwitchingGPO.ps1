<#
.SYNOPSIS
    Create a GPO that sets "Hide entry points for Fast User Switching" to Disabled,
    and link it to a target OU. Overrides tattooed local registry values.

.DESCRIPTION
    A tattooed HideFastUserSwitching=1 value in HKLM\Policies\System (left behind
    by a removed GPO) cannot be cleared by direct registry edit from SYSTEM because
    Group Policy reapplies the value on the next refresh. The correct fix is to
    create a new GPO that explicitly sets the value to 0 (Disabled), which overrides
    the tattoo at next GP refresh without requiring a reboot.

    This script:
      1. Creates the GPO.
      2. Sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
         HideFastUserSwitching = 0 (DWord) under Computer Configuration.
      3. Links the GPO to the target OU.
      4. Verifies the link and the registry policy value.

    WRITE OPERATION. Requires GroupPolicy module and domain admin rights.
    Run on a domain controller via RMM shell.

.PARAMETER GpoName
    Display name for the new GPO. Default: "Enable Fast User Switching".

.PARAMETER TargetOU
    Distinguished name of the OU to link the GPO to.
    Example: "OU=Desktops,OU=Computers,DC=corp,DC=local"

.NOTES
    Created: 2026-05-29
    Category: ActiveDirectory
    Context: RMM shell (SYSTEM, PS 5.1 on DC)

.KEYWORDS
    Fast User Switching, HideFastUserSwitching, GPO, tattoo, override, Group Policy,
    domain controller
#>
#!ps
#maxlength=100000
#timeout=120000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$GpoName,

    [Parameter(Mandatory)]
    [string]$TargetOU
)

$ErrorActionPreference = 'Stop'

$regKey   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$regValue = 'HideFastUserSwitching'

Write-Output "New-FastUserSwitchingGPO"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("GPO Name  : {0}" -f $GpoName)
Write-Output ("Target OU : {0}" -f $TargetOU)
Write-Output ""

Import-Module GroupPolicy -ErrorAction Stop

# --- Create GPO ---
Write-Output "=== Step 1: Create GPO ==="
$existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($existingGpo) {
    Write-Output "GPO already exists: $GpoName (ID: $($existingGpo.Id))"
    $gpo = $existingGpo
} else {
    $gpo = New-GPO -Name $GpoName -Comment "Sets HideFastUserSwitching=0 (FUS enabled). Overrides tattooed registry values. Created by New-FastUserSwitchingGPO.ps1."
    Write-Output ("Created: {0}  ID: {1}" -f $gpo.DisplayName, $gpo.Id)
}

# --- Set registry policy ---
Write-Output ""
Write-Output "=== Step 2: Set registry policy HideFastUserSwitching = 0 ==="
Set-GPRegistryValue -Name $GpoName -Key $regKey -ValueName $regValue -Type DWord -Value 0
Write-Output ("Set {0} = 0 (DWORD) under Computer Configuration" -f $regValue)

# --- Link to OU ---
Write-Output ""
Write-Output "=== Step 3: Link to OU ==="
$existingLink = (Get-GPInheritance -Target $TargetOU).GpoLinks |
                Where-Object { $_.DisplayName -eq $GpoName }
if ($existingLink) {
    Write-Output "Link already exists on $TargetOU"
} else {
    New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes
    Write-Output ("Linked to: {0}" -f $TargetOU)
}

# --- Verify ---
Write-Output ""
Write-Output "=== Step 4: Verify ==="
$linked = Get-GPInheritance -Target $TargetOU
$match  = $linked.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
if ($match) {
    Write-Output ("GPO link confirmed  Enabled: {0}  Enforced: {1}" -f $match.Enabled, $match.Enforced)
} else {
    Write-Output "WARNING: GPO link NOT found on $TargetOU"
}

$setting = Get-GPRegistryValue -Name $GpoName -Key $regKey -ErrorAction SilentlyContinue
if ($setting) {
    Write-Output ("Registry policy: {0} = {1} ({2})" -f $setting.ValueName, $setting.Value, $setting.Type)
} else {
    Write-Output "WARNING: Registry value not confirmed in GPO."
}

Write-Output ""
Write-Output "=== Done ==="
Write-Output "Workstations will apply the new setting on next Group Policy refresh (~90 min) or gpupdate /force."
Write-Output "FUS will become visible on the logon screen after the next lock/logon cycle."
