<#
.SYNOPSIS
    Install-ExchangeSecurityUpdate — STEP 3: applies the current Exchange SE security HU on the target server (** WRITE — REQUIRES APPROVAL **).

.DESCRIPTION
    Installs the May 2026 Exchange SE Hotfix Update (KB5081755, build 15.2.2562.41) passively with
    no auto-reboot, then reports the installer exit code (3010 = success, reboot required). SE RTM
    ships at build 15.2.2562.17, which is unpatched, so this HU keeps the server off a known-
    vulnerable build. Handles both .msp (msiexec) and self-extracting .exe packages. Always run
    from an elevated prompt; running the package by double-click can break OWA/ECP. After reboot,
    confirm build 15.2.2562.41 and run Test-ExchangePostUpgradeHybrid.ps1.

.NOTES
    Created: 2026-05-29
    Category: Environment-Specific
    Context: ELEVATED prompt on the upgraded server, AFTER SE RTM is installed and rebooted.
    Approval: ** WRITE — REQUIRES APPROVAL **  Do NOT run without explicit go-ahead.
    Operator: set $Package to the downloaded HU file (.exe or .msp). Confirm filename from the Exchange Team release.
    Next: Test-ExchangePostUpgradeHybrid.ps1 after reboot.
    Ref: https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates#exchange-server-se
         https://learn.microsoft.com/troubleshoot/exchange/client-connectivity/exchange-security-update-issues

.KEYWORDS
    exchange, security update, hotfix, HU, KB5081755, SE, patch, 15.2.2562.41, write, upgrade
#>

# ===== operator MUST set this to the downloaded HU package =====
$Package = 'C:\Contoso-ExchangeDiag\ExchangeSE-2026May-HU-KB5081755.exe'   # set actual path/filename
# ==============================================================

if (-not (Test-Path $Package)) { Write-Host "STOP: $Package not found. Download KB5081755 first." -ForegroundColor Red; return }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'STOP: run from an ELEVATED prompt.' -ForegroundColor Red; return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = "C:\ExchangeSetupLogs\Contoso-su-install-$stamp.log"
New-Item -ItemType Directory -Path (Split-Path $log) -Force | Out-Null

Write-Host "Installing $([IO.Path]::GetFileName($Package)) (passive, no auto-reboot)..." -ForegroundColor Cyan
$ext = [IO.Path]::GetExtension($Package).ToLower()
if ($ext -eq '.msp') {
    $p = Start-Process msiexec.exe -ArgumentList "/update `"$Package`" /passive /norestart /log `"$log`"" -Wait -PassThru
} else {
    # self-extracting / exe installer
    $p = Start-Process $Package -ArgumentList '/passive /norestart' -Wait -PassThru
}
Write-Host "Installer exit code: $($p.ExitCode)  |  Log: $log" -ForegroundColor Cyan
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
    Write-Host "Non-zero exit. 3010 = success (reboot required); anything else, review the log BEFORE rebooting." -ForegroundColor Red
}

Write-Host 'After reboot, confirm build is 15.2.2562.41 and run Test-ExchangePostUpgradeHybrid.ps1.' -ForegroundColor Green
Write-Host 'REBOOT REQUIRED now.' -ForegroundColor Yellow
