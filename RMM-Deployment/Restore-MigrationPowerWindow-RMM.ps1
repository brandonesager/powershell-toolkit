<#
.SYNOPSIS
    Restores the power scheme saved by Set-MigrationPowerWindow-RMM.ps1 after a migration window.

.DESCRIPTION
    Reads the original scheme GUID and export path from registry, re-imports the
    pre-migration power scheme, reactivates it, re-enables hibernate, and cleans up
    the registry key and backup file.

    Must be run after Set-MigrationPowerWindow-RMM.ps1 has been executed. Exits with
    an informative error if no backup state is found.

.OUTPUTS
    Confirmation of restored scheme and cleanup status.

.NOTES
    Context:    RMM (SYSTEM)
    Version:    1.0 - 2026-03-09
    Pair:       Set-MigrationPowerWindow-RMM.ps1
    .KEYWORDS   migration, power, sleep, standby, hibernate, restore, revert,
                Modern Standby, S3, power scheme
#>

$ErrorActionPreference = "Stop"

$regKey = "HKLM:\SOFTWARE\RMM\MigrationPowerWindow"

try {
    # Verify backup state exists
    if (-not (Test-Path $regKey)) {
        Write-Output "ERROR: No migration power window state found in registry. Was Set-MigrationPowerWindow-RMM.ps1 run first?"
        exit 1
    }

    $originalGuid = (Get-ItemProperty -Path $regKey -Name "OriginalSchemeGuid").OriginalSchemeGuid
    $exportFile   = (Get-ItemProperty -Path $regKey -Name "ExportPath").ExportPath
    $appliedAt    = (Get-ItemProperty -Path $regKey -Name "AppliedAt").AppliedAt

    if (-not (Test-Path $exportFile)) {
        Write-Output "ERROR: Backup file not found at $exportFile. Cannot restore."
        exit 1
    }

    Write-Output "Found migration state applied at: $appliedAt"
    Write-Output "Restoring scheme: $originalGuid"

    # Import original scheme (creates it if GUID was deleted, updates if it still exists)
    $null = & powercfg /import $exportFile $originalGuid

    # Reactivate it
    $null = & powercfg /setactive $originalGuid

    # Re-enable hibernate
    $null = & powercfg /h on

    # Verify active scheme
    $activeCheck = & powercfg /getactivescheme
    $restored = $activeCheck -match $originalGuid

    # Clean up
    Remove-Item $exportFile -Force -ErrorAction SilentlyContinue
    Remove-Item $regKey -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output ""
    Write-Output "=== Migration Power Window Restored ==="
    Write-Output "Active scheme   : $originalGuid $(if ($restored) { '(confirmed active)' } else { '(WARNING: verify manually)' })"
    Write-Output "Hibernate       : re-enabled"
    Write-Output "Backup file     : removed"
    Write-Output "Registry key    : removed"

    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
