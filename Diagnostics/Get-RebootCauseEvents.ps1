<#
.SYNOPSIS
    Retrieves recent reboot cause events from the System event log.
.DESCRIPTION
    Queries Event IDs 41, 1074, 6005, 6006, 6008 from the System log
    to identify planned restarts, unexpected shutdowns, and kernel power
    failures. Writes an Application event log entry to confirm execution.
.NOTES
    Context: RMM (SYSTEM)
    Created: 2026-02-23
.KEYWORDS
    diagnostic, event-log, reboot, shutdown
#>

$ErrorActionPreference = "Stop"

$scriptName = "RMM-Get-RebootCauseEvents"
$hoursBack = 2

try {
    #1 Register event source if needed and log execution
    $source = $scriptName
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        New-EventLog -LogName Application -Source $source -ErrorAction SilentlyContinue
    }
    Write-EventLog -LogName Application -Source $source -EventId 1000 -EntryType Information -Message "Script executed via RMM. Checking reboot events for the last $hoursBack hours."

    $cutoff = (Get-Date).AddHours(-$hoursBack)

    #2 Pull reboot-related events
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 41, 1074, 6005, 6006, 6008
        StartTime = $cutoff
    } -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Output "No reboot events found in the last $hoursBack hours."
        Write-Output "Computer: $env:COMPUTERNAME"
        exit 0
    }

    #3 Summarize counts by event ID
    $idMap = @{
        41   = 'Kernel-Power (unexpected power loss)'
        1074 = 'User/process initiated restart/shutdown'
        6005 = 'Event Log service started (boot)'
        6006 = 'Event Log service stopped (clean shutdown)'
        6008 = 'Unexpected shutdown (previous shutdown was not clean)'
    }

    Write-Output "=== REBOOT EVENT SUMMARY (Last $hoursBack hours) ==="
    Write-Output "Computer: $env:COMPUTERNAME"
    Write-Output ""

    $grouped = $events | Group-Object -Property Id | Sort-Object Name
    foreach ($g in $grouped) {
        $label = $idMap[[int]$g.Name]
        if (-not $label) { $label = "Event $($g.Name)" }
        Write-Output "  Event $($g.Name) - $label : $($g.Count)"
    }

    Write-Output ""
    Write-Output "=== EVENT DETAILS (newest first) ==="
    Write-Output ""

    #4 Output each event with key details
    foreach ($evt in $events) {
        $msg = ($evt.Message -split "`n")[0..2] -join ' ' -replace '\s+', ' '
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }

        Write-Output "[$($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] ID=$($evt.Id) Source=$($evt.ProviderName)"

        if ($evt.Id -eq 1074) {
            $process = ''
            $reason = ''
            if ($evt.Properties.Count -ge 1) { $process = $evt.Properties[0].Value }
            if ($evt.Properties.Count -ge 3) { $reason = $evt.Properties[2].Value }
            if ($process) { Write-Output "  Process: $process" }
            if ($reason) { Write-Output "  Reason: $reason" }

            # For msiexec-initiated reboots, find the MSI install that triggered it
            if ($process -match 'msiexec') {
                $msiWindow = 120 # seconds before the reboot event
                $msiStart = $evt.TimeCreated.AddSeconds(-$msiWindow)
                $msiEvents = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Application'
                    ProviderName = 'MsiInstaller'
                    StartTime = $msiStart
                    EndTime   = $evt.TimeCreated
                } -MaxEvents 5 -ErrorAction SilentlyContinue
                if ($msiEvents) {
                    Write-Output "  --- MSI activity in the 2 minutes before reboot ---"
                    foreach ($m in $msiEvents) {
                        $msiMsg = ($m.Message -split "`n")[0] -replace '\s+', ' '
                        if ($msiMsg.Length -gt 250) { $msiMsg = $msiMsg.Substring(0, 250) + '...' }
                        Write-Output "  [$($m.TimeCreated.ToString('HH:mm:ss'))] $msiMsg"
                    }
                }
            }

            # For winlogon/SYSTEM reboots, check for Windows Update activity
            if ($process -match 'winlogon' -and $evt.Properties.Count -ge 5) {
                $user = $evt.Properties[4].Value
                if ($user -match 'SYSTEM|NT AUTHORITY') {
                    $wuEvents = Get-WinEvent -FilterHashtable @{
                        LogName   = 'System'
                        ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
                        StartTime = $evt.TimeCreated.AddSeconds(-300)
                        EndTime   = $evt.TimeCreated
                    } -MaxEvents 5 -ErrorAction SilentlyContinue
                    if ($wuEvents) {
                        Write-Output "  --- Windows Update activity in the 5 minutes before reboot ---"
                        foreach ($w in $wuEvents) {
                            $wuMsg = ($w.Message -split "`n")[0] -replace '\s+', ' '
                            if ($wuMsg.Length -gt 250) { $wuMsg = $wuMsg.Substring(0, 250) + '...' }
                            Write-Output "  [$($w.TimeCreated.ToString('HH:mm:ss'))] $wuMsg"
                        }
                    }
                }
            }
        }

        Write-Output "  $msg"
        Write-Output ""
    }

    exit 0
}
catch {
    Write-Output "ERROR: $_"
    exit 1
}
