#!ps
#maxlength=20000
#timeout=60000

<#
.SYNOPSIS
    Read-only Intune sync health check: dmwappushservice, enrollment GUIDs, EnterpriseMgmt tasks, OMADM events.

.DESCRIPTION
    Runs in SYSTEM context via RMM shell. Captures:
    - dmwappushservice status and start type (required for Intune sync).
    - Enrollment GUIDs with UPN (healthy = 1 entry; 2+ = orphan conflict).
    - EnterpriseMgmt scheduled tasks: PushLaunch, Schedule, Login -- last run time and result code.
    - Last 20 events from DeviceManagement-Enterprise-Diagnostics-Provider/Admin.
    - OMADM cached last-session info (LastConnectTime, LastSessionHR) per GUID.

    Counterpart: Repair-IntuneEnrollmentOrphans.ps1 for write operations.

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: Commands/SYSTEM

.KEYWORDS
    Intune, sync, dmwappushservice, EnterpriseMgmt, PushLaunch, OMADM, enrollment, diagnostic
#>

#Requires -Version 5.1

Write-Output "=== Intune Sync Health -- $(Get-Date) ==="

Write-Output "`n--- dmwappushservice (required for Intune sync) ---"
Get-Service -Name dmwappushservice -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | Write-Output

Write-Output "`n--- Enrollment GUIDs (HKLM\SOFTWARE\Microsoft\Enrollments) ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            GUID            = $_.PSChildName
            UPN             = $p.UPN
            ProviderID      = $p.ProviderID
            EnrollmentType  = $p.EnrollmentType
            EnrollmentState = $p.EnrollmentState
        }
    } | Where-Object { $_.UPN } | Format-List | Out-String | Write-Output

Write-Output "`n--- EnterpriseMgmt scheduled tasks ---"
Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -match '^(PushLaunch|Schedule)' -or $_.TaskName -eq 'Login' } |
    ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo
        [PSCustomObject]@{
            TaskName      = $_.TaskName
            State         = $_.State
            LastRun       = $info.LastRunTime
            LastResultHex = ('0x{0:X}' -f $info.LastTaskResult)
            NextRun       = $info.NextRunTime
        }
    } | Format-Table -AutoSize | Out-String | Write-Output

Write-Output "`n--- DeviceManagement-Enterprise-Diagnostics-Provider/Admin (last 20) ---"
Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' `
    -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName,
        @{N='Msg';E={($_.Message -split "`r?`n" | Select-Object -First 1)}} |
    Format-Table -Wrap -AutoSize | Out-String | Write-Output

Write-Output "`n--- OMADM cached last-session info ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $g    = $_.PSChildName
        $sess = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$g" -ErrorAction SilentlyContinue
        if ($sess) {
            [PSCustomObject]@{
                GUID            = $g
                LastConnectTime = $sess.LastConnectTime
                LastSessionHR   = $sess.LastSessionHR
            }
        }
    } | Format-List | Out-String | Write-Output

Write-Output "=== END ==="
