<#
.SYNOPSIS
    Forensic audit for CyberQP (QuickPass) agent installation status.

.DESCRIPTION
    Detects current installation state, registry/file remnants, and recent uninstall
    events for the CyberQP (formerly QuickPass) Server Agent on Windows Server.

    Four states detected:
    - INSTALLED: Service exists or install folder present
    - RECENTLY_UNINSTALLED: Uninstall event found in Application log (last 10 days)
    - PREVIOUSLY_INSTALLED: Remnants present, no recent uninstall event
    - NEVER_INSTALLED: Zero artifacts detected

    Context: SYSTEM
    Platform: Windows PowerShell 5.1

.EXAMPLE
    .\Get-CyberQPAudit.ps1
    Returns PSCustomObject with full audit results for RMM variable capture.

.NOTES
    Date: 2026-01-05

    CyberQP Credential Provider GUID: {67D6B25B-3419-4C60-A4B5-A7CE535AD300}
    Registry key: HKLM:\SOFTWARE\Quickpass Software
    Registry key: HKLM:\SOFTWARE\Quickpass Identifier
    Install folder: C:\Program Files\Quickpass Software
    Installer staging: C:\QPInstall

    RMM Deployment: Exit 0 = Success, Exit 1 = Failure
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$CredProviderGUID  = '{67D6B25B-3419-4C60-A4B5-A7CE535AD300}'
$CredProviderBase  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$InstallFolder     = 'C:\Program Files\Quickpass Software'
$InstallerStaging  = 'C:\QPInstall'
$RegSoftware       = 'HKLM:\SOFTWARE\Quickpass Software'
$RegIdentifier     = 'HKLM:\SOFTWARE\Quickpass Identifier'
$ServiceName       = 'QuickpassServerAgent'

try {
    Write-Host "============================================================"
    Write-Host "[START] CyberQP Forensic Audit"
    Write-Host "[INFO] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "[INFO] Computer: $env:COMPUTERNAME"
    Write-Host "============================================================"

    # --- Phase 1: Current Installation ---
    Write-Host "`n[PHASE 1] Current Installation Status"
    Write-Host "------------------------------------------------------------"

    $serviceStatus = 'Missing'
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        $serviceStatus = $svc.Status.ToString()
        Write-Host "[DIAG] Service '$ServiceName': $serviceStatus"
    } catch {
        Write-Host "[DIAG] Service '$ServiceName': Not found"
    }

    $installFolderExists = Test-Path $InstallFolder
    Write-Host "[DIAG] Install folder: $(if ($installFolderExists) { 'PRESENT' } else { 'Missing' })"

    $isInstalled = ($serviceStatus -ne 'Missing') -or $installFolderExists

    # --- Phase 2: Remnant Detection ---
    Write-Host "`n[PHASE 2] Remnant / Legacy Detection"
    Write-Host "------------------------------------------------------------"

    $remnants = [System.Collections.Generic.List[string]]::new()

    if (Test-Path $InstallerStaging) {
        $remnants.Add('QPInstall Folder')
        Write-Host "[DIAG] Installer staging folder present: $InstallerStaging"
    }
    if (Test-Path $RegSoftware) {
        $remnants.Add('Software Registry Key')
        Write-Host "[DIAG] Registry key present: $RegSoftware"
    }
    if (Test-Path $RegIdentifier) {
        $remnants.Add('Identifier Registry Key')
        Write-Host "[DIAG] Registry key present: $RegIdentifier"
    }
    if (Test-Path "$CredProviderBase\$CredProviderGUID") {
        $remnants.Add('Credential Provider')
        Write-Host "[DIAG] Credential provider GUID present: $CredProviderGUID"
    }

    $wasEverPresent = $isInstalled -or ($remnants.Count -gt 0)
    $remnantsFound  = if ($remnants.Count -gt 0) { $remnants -join ', ' } else { $null }

    # --- Phase 3: Uninstall Forensics ---
    Write-Host "`n[PHASE 3] Uninstall Event Forensics (last 10 days)"
    Write-Host "------------------------------------------------------------"

    $uninstallDetected = $false
    $uninstallDate     = $null
    $uninstallUser     = $null

    try {
        $since = (Get-Date).AddDays(-10)
        $events = Get-WinEvent -FilterHashtable @{
            LogName      = 'Application'
            ProviderName = 'MsiInstaller'
            Id           = @(11724, 1034)
            StartTime    = $since
        } -ErrorAction SilentlyContinue

        if ($events) {
            $match = $events | Where-Object {
                $_.Message -match 'Quickpass|CyberQP|QuickPass'
            } | Sort-Object TimeCreated -Descending | Select-Object -First 1

            if ($match) {
                $uninstallDetected = $true
                $uninstallDate     = $match.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                # Attempt SID to NTAccount translation
                try {
                    $sidStr = ($match.Properties | Where-Object { $_.Value -match '^S-1-' } | Select-Object -First 1).Value
                    if ($sidStr) {
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                        $uninstallUser = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    } else {
                        $uninstallUser = 'SYSTEM'
                    }
                } catch {
                    $uninstallUser = 'Unknown'
                }
                Write-Host "[FOUND] Uninstall event detected: $uninstallDate by $uninstallUser"
            }
        }
    } catch {
        Write-Host "[WARN] Could not query Application event log: $($_.Exception.Message)"
    }

    if (-not $uninstallDetected) {
        Write-Host "[DIAG] No Quickpass/CyberQP uninstall events found in last 10 days"
    }

    # --- Output ---
    $result = [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        AuditTimestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        IsInstalled        = $isInstalled
        ServiceStatus      = $serviceStatus
        WasEverPresent     = $wasEverPresent
        RemnantsFound      = $remnantsFound
        UninstallDetected  = $uninstallDetected
        UninstallDate      = $uninstallDate
        UninstallUser      = $uninstallUser
    }

    Write-Host "============================================================"
    Write-Host "[COMPLETE] Audit finished"
    Write-Host "============================================================"
    Write-Output $result
    exit 0

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
