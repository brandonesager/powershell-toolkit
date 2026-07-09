<#
.SYNOPSIS
    Reports whether the machine uses Modern Standby (S0ix) or traditional S3 sleep.

.DESCRIPTION
    Runs powercfg /a and checks for S0 Low Power Idle availability. Use to
    determine sleep architecture before running migration power window scripts
    or diagnosing sleep study reports.

.OUTPUTS
    One-line result: computer name and sleep architecture detected.

.NOTES
    Context:    RMM (SYSTEM)
    Version:    1.0
    .KEYWORDS   modern standby, S0ix, S3, sleep, power, connected standby,
                architecture, audit, migration
#>

$ErrorActionPreference = "Stop"

try {
    $output = & powercfg /a
    if ($output -match "Standby \(S0 Low Power Idle\)") {
        Write-Output "$env:COMPUTERNAME: Modern Standby enabled (S0ix)"
    } else {
        Write-Output "$env:COMPUTERNAME: Traditional S3 sleep (Modern Standby not available)"
    }
    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
