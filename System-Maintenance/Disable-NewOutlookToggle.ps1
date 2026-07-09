<#
.SYNOPSIS
    Hide the "Try the new Outlook" toggle and disable auto-migration for a specific user,
    SID-parameterized. Runs as SYSTEM via RMM shell.

.DESCRIPTION
    Sets three registry values under the target user's HKU hive:
      1. HKU\<SID>\...\Outlook\Options\General\HideNewOutlookToggle = 1
         Removes the "Try the new Outlook" toggle from the Outlook title bar.
      2. HKU\<SID>\...\Outlook\Options\General\DoNewOutlookAutoMigration = 0
         Prevents Outlook from automatically migrating to the new version.
      3. HKU\<SID>\...\Policies\Microsoft\office\16.0\outlook\preferences\NewOutlookMigrationUserSetting = 0
         Policy key that blocks the migration user-side preference.

    The user hive must be loaded (user must be logged in) for HKU writes to work
    from SYSTEM context. Run while the user is active in remote support tooling.

    Verifies each value after write and reports.

.PARAMETER UserSID
    Security Identifier of the target user's account.
    Obtain via: (New-Object System.Security.Principal.NTAccount('DOMAIN','user')).Translate([System.Security.Principal.SecurityIdentifier]).Value
    Or from SC Commands: $sid = (Get-WmiObject Win32_UserAccount -Filter "Name='username'").SID

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1, RMM RMM shell)

.KEYWORDS
    Outlook, new Outlook, toggle, migration, HideNewOutlookToggle, DoNewOutlookAutoMigration,
    NewOutlookMigrationUserSetting, HKU, SID
#>
#!ps
#maxlength=100000
#timeout=60000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$UserSID
)

$ErrorActionPreference = 'Stop'

$generalPath = "Registry::HKU\$UserSID\Software\Microsoft\Office\16.0\Outlook\Options\General"
$policyPath  = "Registry::HKU\$UserSID\Software\Policies\Microsoft\office\16.0\outlook\preferences"

Write-Output "Disable-NewOutlookToggle"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("UserSID   : {0}" -f $UserSID)
Write-Output ""

# Verify hive is loaded
if (-not (Test-Path "Registry::HKU\$UserSID")) {
    Write-Output "ABORT: HKU\$UserSID not found. User must be logged in for SYSTEM to write to their hive."
    Write-Output "Confirm the user has an active (or at least loaded) Windows session and re-run."
    exit 1
}

# Ensure general key exists
if (-not (Test-Path $generalPath)) {
    New-Item -Path $generalPath -Force | Out-Null
    Write-Output "Created: $generalPath"
}

# 1. HideNewOutlookToggle
Set-ItemProperty -Path $generalPath -Name 'HideNewOutlookToggle' -Value 1 -Type DWord
Write-Output "SET: HideNewOutlookToggle = 1"

# 2. DoNewOutlookAutoMigration
Set-ItemProperty -Path $generalPath -Name 'DoNewOutlookAutoMigration' -Value 0 -Type DWord
Write-Output "SET: DoNewOutlookAutoMigration = 0"

# 3. Policy key
if (-not (Test-Path $policyPath)) {
    New-Item -Path $policyPath -Force | Out-Null
    Write-Output "Created: $policyPath"
}
Set-ItemProperty -Path $policyPath -Name 'NewOutlookMigrationUserSetting' -Value 0 -Type DWord
Write-Output "SET: NewOutlookMigrationUserSetting = 0"

Write-Output ""
Write-Output "--- Verification ---"
$g = Get-ItemProperty $generalPath -ErrorAction SilentlyContinue
$p = Get-ItemProperty $policyPath  -ErrorAction SilentlyContinue
Write-Output ("HideNewOutlookToggle           : {0}" -f $g.HideNewOutlookToggle)
Write-Output ("DoNewOutlookAutoMigration      : {0}" -f $g.DoNewOutlookAutoMigration)
Write-Output ("NewOutlookMigrationUserSetting : {0}" -f $p.NewOutlookMigrationUserSetting)

$ok = ($g.HideNewOutlookToggle -eq 1) -and ($g.DoNewOutlookAutoMigration -eq 0) -and ($p.NewOutlookMigrationUserSetting -eq 0)
Write-Output ""
if ($ok) {
    Write-Output "OK: All three values verified. User must restart Outlook for changes to take effect."
} else {
    Write-Output "WARN: One or more values did not verify. Check registry paths and re-run."
    exit 1
}
