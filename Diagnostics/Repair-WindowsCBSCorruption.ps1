<#
.SYNOPSIS
    Diagnose and repair CRITICAL_PROCESS_DIED BSOD caused by Windows Search/CBS corruption

.DESCRIPTION
    Automated repair workflow for Windows component store corruption manifesting as
    BSOD stop codes 0xEF (CRITICAL_PROCESS_DIED) or 0xC000021A (STATUS_SYSTEM_PROCESS_TERMINATED).

    This script performs progressive repair in four phases:
    1. Diagnostics - Component store health, BSOD events, CBS packages
    2. DISM/SFC Repair - RestoreHealth then system file checker
    3. Re-register Windows Apps - Refresh shell components including CBS
    4. Reset Windows Search - Delete index, reset registry, restart service

    Designed for RMM deployment: PS 5.1 compatible, SYSTEM context, non-interactive.

.NOTES
    Date: 2026-01-22

    Exit Codes:
    0   = All repairs succeeded
    1   = All repairs failed
    112 = Partial success (some repairs worked, restart and monitor)


.EXAMPLE
    .\Repair-WindowsCBSCorruption.ps1

    Runs full repair sequence and writes log to $env:TEMP\CBS-Repair-{timestamp}.log
#>

#region Initialization
$ErrorActionPreference = 'Continue'
$Script:ExitCode = 0
$Script:RepairsAttempted = 0
$Script:RepairsSucceeded = 0
$Script:LogPath = "$env:TEMP\CBS-Repair-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry = "[$Timestamp] [$Level] $Message"
    Write-Output $Entry
    Add-Content -Path $Script:LogPath -Value $Entry -ErrorAction SilentlyContinue
}
#endregion

#region Phase 1: Diagnostics
Write-Log "========== WINDOWS CBS CORRUPTION REPAIR =========="
Write-Log "Machine: $env:COMPUTERNAME"
Write-Log "Log file: $Script:LogPath"

# Check recent BSOD events
Write-Log "--- Phase 1: Diagnostics ---"
Write-Log "Checking for recent BSOD events..."
try {
    $BSODEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 1001
        ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
    } -MaxEvents 5 -ErrorAction SilentlyContinue

    if ($BSODEvents) {
        Write-Log "Found $($BSODEvents.Count) recent BSOD event(s):" 'WARN'
        foreach ($Event in $BSODEvents) {
            $Message = $Event.Message -replace "`r`n", " " -replace "\s+", " "
            Write-Log "  - $($Event.TimeCreated): $($Message.Substring(0, [Math]::Min(200, $Message.Length)))"
        }
    } else {
        Write-Log "No recent BSOD events found in System log"
    }
} catch {
    Write-Log "Could not query BSOD events: $($_.Exception.Message)" 'WARN'
}

# Check Windows Search service status
Write-Log "Checking Windows Search service..."
$WSearch = Get-Service -Name WSearch -ErrorAction SilentlyContinue
if ($WSearch) {
    Write-Log "Windows Search status: $($WSearch.Status), StartType: $($WSearch.StartType)"
} else {
    Write-Log "Windows Search service not found" 'WARN'
}

# Check CBS packages
Write-Log "Checking CBS and Search packages..."
try {
    $CBSPackages = Get-AppxPackage -AllUsers -Name '*CBS*' -ErrorAction SilentlyContinue
    $SearchPackages = Get-AppxPackage -AllUsers -Name '*Search*' -ErrorAction SilentlyContinue

    if ($CBSPackages) {
        foreach ($Pkg in $CBSPackages) {
            Write-Log "CBS Package: $($Pkg.Name) v$($Pkg.Version) - Status: $($Pkg.Status)"
        }
    } else {
        Write-Log "No CBS packages found" 'WARN'
    }

    if ($SearchPackages) {
        foreach ($Pkg in $SearchPackages) {
            Write-Log "Search Package: $($Pkg.Name) v$($Pkg.Version) - Status: $($Pkg.Status)"
        }
    }
} catch {
    Write-Log "Could not query AppX packages: $($_.Exception.Message)" 'ERROR'
}

# Check component store health (quick check)
Write-Log "Checking component store health..."
try {
    $DISMCheck = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" `
        -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\dism-check.txt" -ErrorAction Stop
    $CheckOutput = Get-Content "$env:TEMP\dism-check.txt" -Raw -ErrorAction SilentlyContinue

    if ($CheckOutput -match 'repairable|corrupted') {
        Write-Log "Component store shows corruption - repair needed" 'WARN'
    } elseif ($CheckOutput -match 'healthy|No component store corruption') {
        Write-Log "Component store appears healthy"
    } else {
        Write-Log "DISM CheckHealth output: $CheckOutput"
    }
} catch {
    Write-Log "DISM CheckHealth failed: $($_.Exception.Message)" 'WARN'
}
#endregion

#region Phase 2: DISM/SFC Repair
Write-Log "--- Phase 2: Component Store Repair ---"
$Script:RepairsAttempted++

# Run DISM RestoreHealth
Write-Log "Running DISM /RestoreHealth (this may take several minutes)..."
try {
    $DISMRestore = Start-Process -FilePath "dism.exe" `
        -ArgumentList "/Online /Cleanup-Image /RestoreHealth /NoRestart" `
        -Wait -PassThru -NoNewWindow -ErrorAction Stop

    if ($DISMRestore.ExitCode -eq 0) {
        Write-Log "DISM RestoreHealth completed successfully"
        $Script:RepairsSucceeded++
    } else {
        Write-Log "DISM RestoreHealth returned exit code: $($DISMRestore.ExitCode)" 'WARN'
    }
} catch {
    Write-Log "DISM RestoreHealth failed: $($_.Exception.Message)" 'ERROR'
}

# Run SFC
Write-Log "Running SFC /scannow..."
$Script:RepairsAttempted++
try {
    $SFC = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" `
        -Wait -PassThru -NoNewWindow -ErrorAction Stop

    if ($SFC.ExitCode -eq 0) {
        Write-Log "SFC completed - no integrity violations or all repaired"
        $Script:RepairsSucceeded++
    } else {
        Write-Log "SFC returned exit code: $($SFC.ExitCode)" 'WARN'
    }
} catch {
    Write-Log "SFC failed: $($_.Exception.Message)" 'ERROR'
}
#endregion

#region Phase 3: Re-register Windows Apps
Write-Log "--- Phase 3: Re-register Windows Apps ---"
$Script:RepairsAttempted++

Write-Log "Re-registering all Windows apps (including CBS)..."
try {
    $Packages = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    $TotalPackages = ($Packages | Measure-Object).Count
    $RegisteredCount = 0
    $FailedCount = 0

    foreach ($Package in $Packages) {
        $ManifestPath = "$($Package.InstallLocation)\AppXManifest.xml"
        if (Test-Path $ManifestPath) {
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register $ManifestPath -ErrorAction SilentlyContinue
                $RegisteredCount++
            } catch {
                $FailedCount++
            }
        }
    }

    Write-Log "Re-registered $RegisteredCount of $TotalPackages packages ($FailedCount failed)"
    if ($RegisteredCount -gt 0) {
        $Script:RepairsSucceeded++
    }
} catch {
    Write-Log "AppX re-registration failed: $($_.Exception.Message)" 'ERROR'
}
#endregion

#region Phase 4: Reset Windows Search
Write-Log "--- Phase 4: Reset Windows Search ---"
$Script:RepairsAttempted++

# Stop Windows Search service
Write-Log "Stopping Windows Search service..."
try {
    Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} catch {
    Write-Log "Could not stop WSearch: $($_.Exception.Message)" 'WARN'
}

# Delete search index
$SearchIndexPath = "$env:ProgramData\Microsoft\Search\Data\Applications\Windows"
if (Test-Path $SearchIndexPath) {
    Write-Log "Deleting search index at: $SearchIndexPath"
    try {
        Remove-Item -Path "$SearchIndexPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Search index deleted"
    } catch {
        Write-Log "Could not fully delete search index: $($_.Exception.Message)" 'WARN'
    }
}

# Reset search via registry
Write-Log "Resetting search setup flag..."
try {
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Search"
    if (Test-Path $RegPath) {
        Set-ItemProperty -Path $RegPath -Name "SetupCompletedSuccessfully" -Value 0 -Type DWord -ErrorAction Stop
        Write-Log "Search setup flag reset"
    }
} catch {
    Write-Log "Could not reset search registry: $($_.Exception.Message)" 'WARN'
}

# Start Windows Search service
Write-Log "Starting Windows Search service..."
try {
    Set-Service -Name WSearch -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WSearch -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $WSearchAfter = Get-Service -Name WSearch -ErrorAction SilentlyContinue
    if ($WSearchAfter -and $WSearchAfter.Status -eq 'Running') {
        Write-Log "Windows Search service started successfully"
        $Script:RepairsSucceeded++
    } else {
        Write-Log "Windows Search service status: $($WSearchAfter.Status)" 'WARN'
    }
} catch {
    Write-Log "Could not start Windows Search: $($_.Exception.Message)" 'ERROR'
}
#endregion

#region Summary and Exit
Write-Log "========== REPAIR SUMMARY =========="
Write-Log "Repairs attempted: $Script:RepairsAttempted"
Write-Log "Repairs succeeded: $Script:RepairsSucceeded"

# Determine exit code
if ($Script:RepairsSucceeded -eq $Script:RepairsAttempted) {
    Write-Log "All repairs completed successfully"
    Write-Log "ACTION REQUIRED: Restart the computer to complete repairs"
    $Script:ExitCode = 0
} elseif ($Script:RepairsSucceeded -gt 0) {
    Write-Log "Partial success - some repairs completed" 'WARN'
    Write-Log "ACTION REQUIRED: Restart and monitor for BSOD recurrence"
    $Script:ExitCode = 112
} else {
    Write-Log "Repairs failed - manual intervention may be required" 'ERROR'
    Write-Log "Recommend: In-place upgrade repair (requires Windows 11 ISO)"
    $Script:ExitCode = 1
}

Write-Log "Log saved to: $Script:LogPath"
Write-Log "Exit code: $Script:ExitCode"

exit $Script:ExitCode
#endregion
