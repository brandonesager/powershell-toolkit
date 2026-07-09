#timeout=60000
#maxlength=10000

<#
.SYNOPSIS
    Removes a named Wi-Fi profile from the currently signed-in user's profile store.
.DESCRIPTION
    Runs from RMM shell (SYSTEM). Bridges SYSTEM to the interactive
    user context via a one-shot Scheduled Task, because per-user WLAN profiles cannot
    be deleted from the SYSTEM account directly. The task runs netsh under the user's
    interactive session, waits up to 20 seconds for completion, reports the result,
    and self-deletes the task.
.PARAMETER ProfileName
    The exact name of the Wi-Fi profile to remove (case-sensitive, matches netsh output).
.NOTES
    Category: System-Maintenance
    PS 5.1 compatible.
    Context: RMM shell (SYSTEM).
    References:
      https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wlan
      https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile
.KEYWORDS
    wifi, wlan, wireless, profile, remove, forget, SSID, scheduled task
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProfileName
)

$User = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $User) {
    Write-Output 'No interactive user signed in. Aborting.'
    exit 1
}

Write-Output "Active user: $User"
Write-Output "Target Wi-Fi profile: $ProfileName"

$TaskName = "ForgetWifi-$ProfileName-$([guid]::NewGuid().ToString('N'))"
$Action    = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument "wlan delete profile name=`"$ProfileName`""
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$Settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
$Task      = New-ScheduledTask -Action $Action -Principal $Principal -Settings $Settings

Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 500
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
} while (($info.LastRunTime -eq [datetime]::MinValue -or $info.LastTaskResult -eq 267009) `
         -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $TaskName
$code = $info.LastTaskResult
switch ($code) {
    0           { Write-Output "Result: SUCCESS (profile '$ProfileName' deleted from $User)" }
    2147942402  { Write-Output "Result: PROFILE NOT FOUND (no '$ProfileName' in $User's store)" }
    default     { Write-Output ("Result: FAILED (LastTaskResult = 0x{0:X8} / {0})" -f $code) }
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
