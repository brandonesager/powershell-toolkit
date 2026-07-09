<#
.SYNOPSIS
    Invoke-ExchangeSEUpgrade — STEP 2: runs the Exchange Server SE in-place upgrade on the target server (** WRITE — REQUIRES APPROVAL **).

.DESCRIPTION
    Launches the SE RTM in-place upgrade in unattended mode from the mounted ISO's Setup.exe,
    captures a run log, scans ExchangeSetup.log for [ERROR], and reports the exit code. Replaces
    the Exchange binaries (2019 -> SE), extends the AD schema inline, and requires a reboot. There
    is no uninstall or rollback; rollback means restore from the pre-upgrade backup. Run AFTER
    backup verification and after maintenance mode is entered. On success, reboot, then apply the
    May 2026 HU with Install-ExchangeSecurityUpdate.ps1.
    Client: Contoso (contoso.example.com).

    PRE-REQS (confirm first):
      - Exchange currently on 2019 CU14 (15.2.1544.x) or CU15 (15.2.1748.x).
      - Running account is a member of Organization Management AND Schema Admins AND Enterprise Admins.
      - Antivirus disabled or Exchange exclusions in place.
      - .NET 4.8+ installed; server rebooted clean.
    LICENSE SWITCH: matches the reseller-specified _DiagnosticDataOFF.

.KEYWORDS
    contoso, exchange, SE, in-place upgrade, setup, unattended, schema, RTM, write, upgrade
#>

# ===== operator MUST set this to the mounted SE RTM ISO drive's Setup.exe =====
$SetupExe = 'E:\Setup.exe'    # change E: to the actual mounted ISO drive letter
# =============================================================================

if (-not (Test-Path $SetupExe)) { Write-Host "STOP: $SetupExe not found. Mount the SE RTM ISO and set the correct drive letter." -ForegroundColor Red; return }

# elevation guard
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'STOP: run from an ELEVATED prompt (Run as administrator).' -ForegroundColor Red; return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = "C:\ExchangeSetupLogs\Contoso-upgrade-run-$stamp.txt"
New-Item -ItemType Directory -Path (Split-Path $runlog) -Force | Out-Null

Write-Host "Launching SE in-place upgrade from $SetupExe ..." -ForegroundColor Cyan
Write-Host "This runs 60-180 minutes. Do not interrupt. Live log: C:\ExchangeSetupLogs\ExchangeSetup.log" -ForegroundColor Yellow

# explicit path (never bare 'setup.exe') to avoid PATH collision with the installed bin
& $SetupExe /Mode:Upgrade /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF 2>&1 | Tee-Object -FilePath $runlog
$code = $LASTEXITCODE

Write-Host "`nSetup exit code: $code" -ForegroundColor Cyan
Write-Host 'Scanning ExchangeSetup.log for [ERROR]...' -ForegroundColor Cyan
if (Test-Path 'C:\ExchangeSetupLogs\ExchangeSetup.log') {
    Select-String -Path 'C:\ExchangeSetupLogs\ExchangeSetup.log' -Pattern '\[ERROR\]' | Select-Object -Last 20 | ForEach-Object { Write-Host $_.Line -ForegroundColor Red }
}

if ($code -eq 0) {
    Write-Host "`nUpgrade reported success. REBOOT now, then apply the May 2026 HU (Install-ExchangeSecurityUpdate.ps1)." -ForegroundColor Green
} else {
    Write-Host "`nUpgrade did NOT return success. Do NOT reboot blindly. Review $runlog and ExchangeSetup.log before any further action." -ForegroundColor Red
}
Write-Host "Run log: $runlog" -ForegroundColor Green
