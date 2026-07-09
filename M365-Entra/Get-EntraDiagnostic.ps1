#!ps
#maxlength=100000
#timeout=300000

<#
.SYNOPSIS
    Entra join state diagnostic: dsregcmd, MDM enrollments, AAD operational events.

.DESCRIPTION
    Runs in SYSTEM context via RMM shell. Captures:
    - Full dsregcmd /status output (Device State + Diagnostics sections valid in SYSTEM).
    - MDM enrollment GUIDs from registry with UPN, ProviderID, EnrollmentType, EnrollmentState.
    - Last 50 events from Microsoft-Windows-AAD/Operational log.
    - Last 50 events from Microsoft-Windows-User Device Registration/Admin log.
    - IdentityStore cache keys.
    - HKLM CDJ AAD registration hints.
    Writes full detail to a temp file and prints a concise summary to stdout.

    Note: PRT state (AzureAdPrt, Attempt Status) is only valid in user context.
    Run dsregcmd /status in the user's interactive session for SSO state.

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: Commands/SYSTEM

.KEYWORDS
    Entra, dsregcmd, MDM, enrollment, AAD, 0x8018000a, WorkplaceJoined, AzureAdJoined, diagnostic
#>

#Requires -Version 5.1

$ticket = '0000'   # Replace with active ticket number before running
$date   = Get-Date -Format 'yyyyMMdd-HHmmss'
$out    = "C:\Windows\Temp\entra-diag-$ticket-$date.txt"

"ENTRA DIAGNOSTIC -- $(Get-Date)" | Out-File -FilePath $out -Encoding UTF8

"`n=== DSREGCMD /STATUS ===" | Add-Content $out
(dsregcmd /status) | Add-Content $out

$user = (Get-CimInstance Win32_ComputerSystem).UserName
"`n=== LOGGED-IN USER ===" | Add-Content $out
$user | Add-Content $out

"`n=== HKLM CDJ AAD ===" | Add-Content $out
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD' -ErrorAction SilentlyContinue |
    Select-Object * | Format-List | Out-String | Add-Content $out

"`n=== MDM ENROLLMENTS ===" | Add-Content $out
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            GUID           = $_.PSChildName
            UPN            = $p.UPN
            ProviderID     = $p.ProviderID
            EnrollmentType = $p.EnrollmentType
            EnrollmentState= $p.EnrollmentState
            AADResourceID  = $p.AADResourceID
        }
    } | Format-List | Out-String | Add-Content $out

"`n=== AAD OPERATIONAL LOG (last 50) ===" | Add-Content $out
Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName,
        @{N='Msg';E={($_.Message -split "`r?`n" | Select-Object -First 1)}} |
    Format-Table -Wrap -AutoSize | Out-String | Add-Content $out

"`n=== USER DEVICE REGISTRATION LOG (last 50) ===" | Add-Content $out
Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName,
        @{N='Msg';E={($_.Message -split "`r?`n" | Select-Object -First 1)}} |
    Format-Table -Wrap -AutoSize | Out-String | Add-Content $out

"`n=== IDENTITYSTORE CACHE ===" | Add-Content $out
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache' -ErrorAction SilentlyContinue |
    Select-Object Name | Out-String | Add-Content $out

Write-Output "Full diagnostic: $out"
Write-Output ""

# Inline summary
Write-Output "=== DEVICE STATE SUMMARY ==="
$sys     = (dsregcmd /status) | Out-String
$joined  = [regex]::Match($sys, 'AzureAdJoined\s*:\s*(\S+)').Groups[1].Value
$djoined = [regex]::Match($sys, 'DomainJoined\s*:\s*(\S+)').Groups[1].Value
$wjoined = [regex]::Match($sys, 'WorkplaceJoined\s*:\s*(\S+)').Groups[1].Value
$tname   = [regex]::Match($sys, 'TenantName\s*:\s*(\S+)').Groups[1].Value
$tid     = [regex]::Match($sys, 'TenantId\s*:\s*(\S+)').Groups[1].Value
Write-Output "AzureAdJoined   : $joined"
Write-Output "DomainJoined    : $djoined"
Write-Output "WorkplaceJoined : $wjoined  (should be NO on AzureAdJoined=YES; YES=pre-join WPJ conflict)"
Write-Output "TenantName      : $tname"
Write-Output "TenantId        : $tid"
Write-Output "LoggedInUser    : $user"

Write-Output ""
Write-Output "=== MDM ENROLLMENT COUNT ==="
$enrollments = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UPN })
Write-Output "Enrollments with UPN: $($enrollments.Count)  (1=healthy; 2+=orphan blocking new join, 0x8018000a)"
foreach ($e in $enrollments) {
    $p = Get-ItemProperty $e.PSPath -ErrorAction SilentlyContinue
    Write-Output ("  {0}  UPN={1}  State={2}  Type={3}" -f $e.PSChildName, $p.UPN, $p.EnrollmentState, $p.EnrollmentType)
}

Write-Output ""
Write-Output "=== AAD OPERATIONAL ERRORS (last 10) ==="
$aadErrs = @(Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 300 -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -match 'Error|Critical' })
if ($aadErrs.Count -eq 0) {
    Write-Output "No errors in last 300 events."
} else {
    $aadErrs | Select-Object -First 10 TimeCreated, Id,
        @{N='Msg';E={($_.Message -split "`r?`n" | Select-Object -First 1)}} |
        Format-Table -AutoSize | Out-String | Write-Output
}

Write-Output "=== USER DEVICE REGISTRATION ERRORS (last 10) ==="
$udrErrs = @(Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -MaxEvents 300 -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -match 'Error|Critical' })
if ($udrErrs.Count -eq 0) {
    Write-Output "No errors in last 300 events."
} else {
    $udrErrs | Select-Object -First 10 TimeCreated, Id,
        @{N='Msg';E={($_.Message -split "`r?`n" | Select-Object -First 1)}} |
        Format-Table -AutoSize | Out-String | Write-Output
}

Write-Output ""
Write-Output "PRT state (AzureAdPrt, Attempt Status) requires user context."
Write-Output "Run dsregcmd /status in an interactive CMD session as the logged-in user."
