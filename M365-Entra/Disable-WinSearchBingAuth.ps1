#!ps
#maxlength=10000
#timeout=60000

<#
.SYNOPSIS
    Disable Windows Search Bing and Cortana consent in HKCU to stop AAD token-refresh noise.

.DESCRIPTION
    Sets BingSearchEnabled=0 and CortanaConsent=0 in the current user's Search registry key.
    Stops Windows Search from silently requesting Bing tokens, which triggers AAD events
    1097 / 1098 (AADSTS65002) every 1-3 minutes and the "Work or school account problem"
    toast on Entra-joined devices.

    User-scope only (HKCU). Reversible. Restarts explorer.exe to apply immediately.
    Includes a verification query to confirm the events stop within 5 minutes.

    Run in the logged-in user's session via SYSTEM remote session, PowerShell ISE,
    or a user-context RMM shell session. Not effective in SYSTEM context
    (HKCU under SYSTEM is not the user's hive).

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: User session (SYSTEM remote session or interactive)

    Note: HKLM policy overrides take precedence. If BingSearchEnabled keeps reverting,
    check HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search for a GPO value.

.KEYWORDS
    Bing, Windows Search, Cortana, HKCU, AAD, 1097, 1098, AADSTS65002, toast, work account
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Continue'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'

if (-not (Test-Path $key)) {
    New-Item -Path $key -Force | Out-Null
    Write-Output "Search key created."
}

Write-Output "`n=== BEFORE ==="
Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
    Select-Object BingSearchEnabled, CortanaConsent | Format-List

Set-ItemProperty -Path $key -Name 'BingSearchEnabled' -Type DWord -Value 0 -Force
Set-ItemProperty -Path $key -Name 'CortanaConsent'    -Type DWord -Value 0 -Force

Write-Output "`n=== AFTER ==="
Get-ItemProperty -Path $key | Select-Object BingSearchEnabled, CortanaConsent | Format-List

# Check for HKLM policy override
$hklmPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
if (Test-Path $hklmPolicy) {
    $pv = (Get-ItemProperty $hklmPolicy -ErrorAction SilentlyContinue).BingSearchEnabled
    if ($null -ne $pv) {
        Write-Output "WARNING: HKLM policy BingSearchEnabled=$pv -- GPO will override this HKCU setting."
        Write-Output "Coordinate with domain admin to adjust GPO if needed."
    }
}

Write-Output "`nRestarting explorer.exe to apply..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
    Start-Process explorer.exe
}

Write-Output ""
Write-Output "Done. Wait 5 minutes, then verify AAD events 1097/1098 stopped:"
Write-Output ""
Write-Output "  Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 50 |"
Write-Output "    Where-Object { `$_.Id -in 1097,1098 -and `$_.TimeCreated -gt (Get-Date).AddMinutes(-5) } |"
Write-Output "    Measure-Object | Select-Object -ExpandProperty Count"
Write-Output ""
Write-Output "(Expected result: 0)"
