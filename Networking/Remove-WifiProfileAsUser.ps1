<#
.SYNOPSIS
    Delete a per-user Wi-Fi profile from the currently signed-in user's profile store,
    bridging from SYSTEM context via a one-shot Scheduled Task.

.DESCRIPTION
    Per-user WLAN profiles (those not in the all-users machine store) cannot be deleted
    from the SYSTEM account directly. netsh wlan delete profile executed as SYSTEM only
    targets machine-wide profiles. This script creates a temporary Scheduled Task that
    runs as the currently signed-in interactive user, executes the netsh command, then
    immediately unregisters itself.

    Use cases:
      - Force a workstation to forget a stale Wi-Fi network so it reconnects fresh
      - Remove a profile that was saved with wrong credentials (repeated auth failures)
      - Clear a per-user profile before domain re-join or profile rebuild

    Waits up to 20 seconds for the task to complete, decodes the result code, then
    removes the task. Exits with a non-zero code if the profile was not found or the
    task failed.

.PARAMETER ProfileName
    Name of the Wi-Fi profile to delete. Must match exactly (case-insensitive per netsh).

.NOTES
    Created: 2026-05-29
    Category: Networking
    Context: RMM shell (SYSTEM, PS 5.1)

.KEYWORDS
    Wi-Fi, WLAN, profile, delete, forget, netsh, Scheduled Task, user context, SYSTEM
#>
#!ps
#maxlength=100000
#timeout=120000
#Requires -Version 5.1

param(
    [Parameter(Mandatory)]
    [string]$ProfileName
)

$ErrorActionPreference = 'Stop'

Write-Output "Remove-WifiProfileAsUser"
Write-Output ("Host      : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("Profile   : {0}" -f $ProfileName)
Write-Output ""

# --- Find interactive user ---
$activeUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $activeUser) {
    Write-Output "ABORT: No interactive user signed in. User must be logged on for per-user profile deletion."
    exit 1
}
Write-Output ("Active user: {0}" -f $activeUser)

# --- Create one-shot task ---
$taskName = "RemoveWifi-{0}-{1}" -f ($ProfileName -replace '[^A-Za-z0-9]',''), [guid]::NewGuid().ToString('N').Substring(0,8)

$action    = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument ("wlan delete profile name=`"{0}`"" -f $ProfileName)
$principal = New-ScheduledTaskPrincipal -UserId $activeUser -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
$task      = New-ScheduledTask -Action $action -Principal $principal -Settings $settings

Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
Write-Output ("Registered task: {0}" -f $taskName)

Start-ScheduledTask -TaskName $taskName
Write-Output "Task started. Waiting up to 20 seconds..."

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 500
    $info = Get-ScheduledTaskInfo -TaskName $taskName
} while (($info.LastRunTime -eq [datetime]::MinValue -or $info.LastTaskResult -eq 267009) -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $taskName
$code = $info.LastTaskResult

switch ($code) {
    0           { Write-Output ("Result: SUCCESS - profile '{0}' deleted from {1}'s store." -f $ProfileName, $activeUser) }
    2147942402  { Write-Output ("Result: PROFILE NOT FOUND - no '{0}' in {1}'s WLAN profile store." -f $ProfileName, $activeUser) }
    267009      { Write-Output "Result: TIMED OUT waiting for task to complete." }
    default     { Write-Output ("Result: FAILED (LastTaskResult = 0x{0:X8} / {0})" -f $code) }
}

# --- Cleanup ---
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Output ("Task {0} removed." -f $taskName)

Write-Output ""
Write-Output "=== Done ==="
if ($code -eq 0) {
    Write-Output ("User {0} can now reconnect to the Wi-Fi network with fresh credentials." -f $activeUser)
    exit 0
} elseif ($code -eq 2147942402) {
    Write-Output "Verify the profile name with: netsh wlan show profiles (run as the user)."
    exit 2
} else {
    exit 1
}
