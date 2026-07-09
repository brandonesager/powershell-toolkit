<#
.SYNOPSIS
    Diagnose cloud storage sync failure caused by KB5074109 (Jan 2026 Windows update)

.DESCRIPTION
    Checks whether KB5074109 (broke cloud storage sync) is installed and whether
    KB5078127 (OOB fix) has been applied. Collects Windows version, Dropbox/OneDrive
    install status/version, and process state.

    Designed for RMM (PowerShell 5.1, SYSTEM context).

.NOTES

.KEYWORDS
    diagnose, KB5074109, KB5078127, Windows Update, cloud storage, sync, Dropbox, OneDrive
#>

$ErrorActionPreference = "Stop"

try {
    # --- Windows version ---
    $os = Get-CimInstance Win32_OperatingSystem
    $build = $os.BuildNumber
    $version = $os.Caption
    Write-Output "=== WINDOWS ==="
    Write-Output "OS: $version"
    Write-Output "Build: $($os.Version) ($build)"

    # --- KB checks ---
    Write-Output ""
    Write-Output "=== WINDOWS UPDATES ==="

    $badKB = Get-HotFix -Id "KB5074109" -ErrorAction SilentlyContinue
    $fixKB = Get-HotFix -Id "KB5078127" -ErrorAction SilentlyContinue

    if ($null -ne $badKB) {
        Write-Output "KB5074109 (broken update): INSTALLED on $($badKB.InstalledOn)"
    } else {
        Write-Output "KB5074109 (broken update): NOT INSTALLED"
    }

    if ($null -ne $fixKB) {
        Write-Output "KB5078127 (OOB fix):      INSTALLED on $($fixKB.InstalledOn)"
    } else {
        Write-Output "KB5078127 (OOB fix):      NOT INSTALLED"
    }

    # --- Cloud storage processes ---
    Write-Output ""
    Write-Output "=== CLOUD STORAGE PROCESSES ==="

    $processes = @()
    foreach ($name in @("Dropbox", "OneDrive")) {
        $proc = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $proc) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            Write-Output "$name: RUNNING (PID $($proc.Id), $memMB MB)"
            $processes += $name
        } else {
            Write-Output "$name: NOT RUNNING"
        }
    }

    # --- Verdict ---
    Write-Output ""
    Write-Output "=== VERDICT ==="

    $hasBadKB = $null -ne $badKB
    $hasFixKB = $null -ne $fixKB

    if ($hasBadKB -and -not $hasFixKB) {
        Write-Output "CONFIRMED: KB5074109 installed without KB5078127 fix."
        Write-Output "ACTION: Install KB5078127 via Windows Update, then reboot."
        if ($processes.Count -gt 0) {
            Write-Output "AFFECTED: $($processes -join ', ') may experience sync failures."
        }
        exit 1
    } elseif ($hasBadKB -and $hasFixKB) {
        Write-Output "Fix already applied. KB5074109 + KB5078127 both present."
        Write-Output "Cloud storage issue may have a different root cause."
        exit 0
    } else {
        Write-Output "KB5074109 not installed. Windows Update is not the cause."
        Write-Output "Investigate cloud storage-specific issues."
        exit 0
    }
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
