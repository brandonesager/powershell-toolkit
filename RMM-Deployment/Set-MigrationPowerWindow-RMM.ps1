<#
.SYNOPSIS
    Locks a machine awake for a migration window by exporting and replacing the active power scheme.

.DESCRIPTION
    Exports the current active power scheme to disk, saves the scheme GUID and export
    path to registry, then applies zero-timeout settings across all sleep, hibernate,
    and display categories. Run Restore-MigrationPowerWindow-RMM.ps1 after the migration
    to revert exactly to the pre-migration state.

    Handles both S3 and Modern Standby machines. Safe to run repeatedly — re-export
    is skipped if a backup already exists.

.OUTPUTS
    Confirmation of exported scheme, applied timeouts, and registry save path.

.NOTES
    Context:    RMM (SYSTEM)
    Version:    1.0 - 2026-03-09
    Pair:       Restore-MigrationPowerWindow-RMM.ps1
    .KEYWORDS   migration, power, sleep, standby, hibernate, awake, lock, window,
                proactive, remediation, Modern Standby, S3
#>

$ErrorActionPreference = "Stop"

$regKey    = "HKLM:\SOFTWARE\RMM\MigrationPowerWindow"
$exportDir = "C:\Windows\Temp"
$exportFile = Join-Path $exportDir "pre-migration-power.pow"

try {
    # Get active scheme GUID
    $schemeOutput = & powercfg /getactivescheme
    if ($schemeOutput -notmatch 'Power Scheme GUID:\s+([\w-]+)') {
        Write-Output "ERROR: Could not determine active power scheme."
        exit 1
    }
    $activeGuid = $Matches[1]

    # Skip re-export if backup already exists from a previous run
    if (Test-Path $exportFile) {
        Write-Output "INFO: Pre-migration backup already exists at $exportFile. Skipping re-export."
    } else {
        $null = & powercfg /export $exportFile $activeGuid
        if (-not (Test-Path $exportFile)) {
            Write-Output "ERROR: Power scheme export failed."
            exit 1
        }
        Write-Output "Exported active scheme ($activeGuid) to $exportFile"
    }

    # Save state to registry
    if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
    Set-ItemProperty -Path $regKey -Name "OriginalSchemeGuid" -Value $activeGuid
    Set-ItemProperty -Path $regKey -Name "ExportPath"         -Value $exportFile
    Set-ItemProperty -Path $regKey -Name "AppliedAt"          -Value (Get-Date).ToString('o')

    # Apply zero timeouts (AC and DC) for all sleep/display categories
    $settings = @(
        'standby-timeout-ac',
        'standby-timeout-dc',
        'hibernate-timeout-ac',
        'hibernate-timeout-dc',
        'monitor-timeout-ac',
        'monitor-timeout-dc',
        'disk-timeout-ac',
        'disk-timeout-dc'
    )
    foreach ($s in $settings) {
        $null = & powercfg /change $s 0
    }

    # Disable hibernate (frees hiberfil.sys, prevents S4 transitions)
    $null = & powercfg /h off

    # Verify sleep timeout applied
    $verify = & powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>&1
    $acLine = $verify | Where-Object { $_ -match 'Current AC Power Setting Index' }
    Write-Output ""
    Write-Output "=== Migration Power Window Applied ==="
    Write-Output "Original scheme : $activeGuid"
    Write-Output "Backup location : $exportFile"
    Write-Output "Registry key    : $regKey"
    Write-Output "AC sleep timeout: $(if ($acLine -match '0x(\w+)') { [Convert]::ToInt32($Matches[1],16) } else { 'unknown' }) seconds (0 = never)"
    Write-Output "Hibernate       : disabled"
    Write-Output ""
    Write-Output "Run Restore-MigrationPowerWindow-RMM.ps1 after migration to revert."

    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
