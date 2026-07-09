<#
.SYNOPSIS
    Attempts to repair the RMM (ITSPlatform) agent on an endpoint.

.DESCRIPTION
    Three-step repair sequence:
      Step 1: Starts ITSPlatformManager if it is stopped.
      Step 2: Locates platform-watchdog.exe (C:\temp first, then ITSPlatform install
              dir) and runs the healthcheckandrestore action.
      Step 3: Waits 90 seconds for the agent to register, then verifies EndpointID
              is populated and both core services are running.

    If platform-watchdog.exe is not found, the script exits 1 and directs the
    operator to perform a full nuke and reinstall (Invoke-CWRMMAgentNuke.ps1).

    Exit 0 — repair succeeded, EndpointID populated.
    Exit 1 — repair failed; proceed to full nuke + reinstall.

.NOTES
    Context:  RMM (SYSTEM, PS 5.1)
    Platform: Windows 10/11/Server 2019+
    PS 5.1 compatible.

.KEYWORDS
    ITSPlatform, SAAZ, RMM, agent repair, platform-watchdog, healthcheckandrestore
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# Step 1 -- start ITSPlatformManager if stopped
$mgr = Get-Service ITSPlatformManager -ErrorAction SilentlyContinue
if ($mgr -and $mgr.Status -ne 'Running') {
    Write-Output "Starting ITSPlatformManager..."
    Start-Service ITSPlatformManager -ErrorAction SilentlyContinue
    Start-Sleep 5
    $mgr.Refresh()
    Write-Output "ITSPlatformManager: $($mgr.Status)"
} else {
    Write-Output "ITSPlatformManager: $($mgr.Status)"
}

# Step 2 -- run watchdog healthcheck and restore
# Look in C:\temp first (manual drop), then fall back to ITSPlatform install dir
$watchdogPath = $null
if (Test-Path "C:\temp\platform-watchdog.exe") {
    $watchdogPath = "C:\temp\platform-watchdog.exe"
    Write-Output "Watchdog found in C:\temp"
} else {
    $found = Get-ChildItem "C:\Program Files (x86)\ITSPlatform" -Filter "platform-watchdog.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $watchdogPath = $found.FullName
        Write-Output "Watchdog found in ITSPlatform: $watchdogPath"
    }
}
if (-not $watchdogPath) {
    Write-Output "ERROR: platform-watchdog.exe not found in C:\temp or ITSPlatform dir."
    Write-Output "Proceed to full nuke + reinstall: Invoke-CWRMMAgentNuke.ps1"
    exit 1
}

Write-Output "Running watchdog restore: $watchdogPath"
$proc = Start-Process -FilePath $watchdogPath -ArgumentList "action=healthcheckandrestore" -Wait -PassThru
Write-Output "Watchdog exit code: $($proc.ExitCode)"

# Step 3 -- wait and verify EndpointID
Write-Output "Waiting 90 seconds for agent to register..."
Start-Sleep 90

$ep = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\SAAZOD" -Name EndpointID -ErrorAction SilentlyContinue
$endpointId = if ($ep -and $ep.EndpointID) { $ep.EndpointID } else { 'MISSING' }
Write-Output "EndpointID: $endpointId"

$svc = Get-Service ITSPlatform, ITSPlatformManager -ErrorAction SilentlyContinue
foreach ($s in $svc) { Write-Output "$($s.Name): $($s.Status)" }

if ($endpointId -ne 'MISSING') {
    Write-Output "Repair succeeded."
    exit 0
} else {
    Write-Output "EndpointID still missing. Watchdog restore failed."
    Write-Output "Proceed to full nuke + reinstall: Invoke-CWRMMAgentNuke.ps1"
    exit 1
}
