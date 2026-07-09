<#
.SYNOPSIS
    Correlates MSI installer activity with recent reboots.
.DESCRIPTION
    Queries MsiInstaller events from Application log and Cisco-related
    install logs to identify which MSI package triggered a reboot.
    Designed to complement Get-RebootCauseEvents.ps1 when msiexec.exe
    is identified as the reboot initiator.
.NOTES
    Context: RMM (SYSTEM)
.KEYWORDS
    diagnostic, event-log, reboot, msi, cisco
#>

$ErrorActionPreference = "Stop"

$scriptName = "RMM-Get-MsiRebootCorrelation"
$hoursBack = 1

try {
    #1 Register event source if needed and log execution
    $source = $scriptName
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        New-EventLog -LogName Application -Source $source -ErrorAction SilentlyContinue
    }
    Write-EventLog -LogName Application -Source $source -EventId 1000 -EntryType Information -Message "Script executed via RMM. Checking MSI activity for the last $hoursBack hours."

    $cutoff = (Get-Date).AddHours(-$hoursBack)

    Write-Output "=== MSI INSTALLER ACTIVITY (Last $hoursBack hours) ==="
    Write-Output "Computer: $env:COMPUTERNAME"
    Write-Output ""

    #2 Get all MsiInstaller events
    $msiEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'MsiInstaller'
        StartTime    = $cutoff
    } -ErrorAction SilentlyContinue

    if ($msiEvents) {
        Write-Output "MsiInstaller Events: $($msiEvents.Count)"
        Write-Output ""
        foreach ($evt in $msiEvents) {
            $msg = ($evt.Message -split "`n")[0] -replace '\s+', ' '
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
            Write-Output "[$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] ID=$($evt.Id)"
            Write-Output "  $msg"
            Write-Output ""
        }
    }
    else {
        Write-Output "No MsiInstaller events found in Application log."
        Write-Output ""
    }

    #3 Find Cisco-related install logs
    Write-Output "=== CISCO INSTALL LOGS (Last $hoursBack hours) ==="
    Write-Output ""

    $searchPaths = @("$env:ProgramData\Cisco", "$env:TEMP", "$env:SystemRoot\Temp")
    $ciscoLogs = [System.Collections.Generic.List[object]]::new()

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $found = Get-ChildItem $searchPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff }
            if ($found) {
                foreach ($f in $found) { $ciscoLogs.Add($f) }
            }
        }
    }

    if ($ciscoLogs.Count -gt 0) {
        $ciscoLogs | Sort-Object LastWriteTime -Descending | ForEach-Object {
            Write-Output "  $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  $($_.Length) bytes  $($_.FullName)"
        }
    }
    else {
        Write-Output "  No recent Cisco install logs found."
    }

    Write-Output ""

    #4 Check for recent reboot event to correlate
    Write-Output "=== REBOOT CORRELATION ==="
    Write-Output ""

    $rebootEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 1074
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue

    if ($rebootEvents) {
        foreach ($r in $rebootEvents) {
            $process = ''
            if ($r.Properties.Count -ge 1) { $process = $r.Properties[0].Value }
            if ($process -match 'msiexec') {
                Write-Output "REBOOT at $($r.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) triggered by $process"

                # Find the closest MSI event before the reboot
                if ($msiEvents) {
                    $closest = $msiEvents | Where-Object { $_.TimeCreated -le $r.TimeCreated } |
                        Sort-Object TimeCreated -Descending | Select-Object -First 3
                    if ($closest) {
                        Write-Output "  Nearest MSI events before reboot:"
                        foreach ($c in $closest) {
                            $cmsg = ($c.Message -split "`n")[0] -replace '\s+', ' '
                            if ($cmsg.Length -gt 250) { $cmsg = $cmsg.Substring(0, 250) + '...' }
                            Write-Output "    [$($c.TimeCreated.ToString('HH:mm:ss'))] $cmsg"
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Output "No msiexec-initiated reboots found in the last $hoursBack hours."
    }

    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
