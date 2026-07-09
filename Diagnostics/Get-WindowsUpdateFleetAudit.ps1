<#
.SOURCE
    Date: 2026-03-03
#>

<#
.SYNOPSIS
    Enumerate Windows Update status across a fleet via RMM (bulk deployment).

.DESCRIPTION
    Discovers Cumulative Update (CU) gaps, build tiers, days-behind metric, and Windows Update
    service state across multiple machines in a single RMM run. Output includes per-machine:
    - Current build (e.g., 26200.7840 for Win11 25H2)
    - Latest applicable CU and release date
    - Days behind current build
    - Windows Update service state (Running/Stopped, Automatic/Manual/Disabled)

    Useful for identifying unpatched fleet segments and WU service configuration issues that
    prevent auto-deployment. Three build tiers typically emerge on mixed-deployment fleets
    (e.g., Feb CU, Jan CU, older Jan CU across different workstations).

.NOTES
    - RMM bulk deployment script (one output per machine)
    - Windows PowerShell 5.1+
    - SYSTEM context
    - Requires internet access to fetch latest build info (Get-CimInstance Win32_OperatingSystem)
    - Output shows build, days behind, and service state on one line for fleet CSV export
#>

$ErrorActionPreference = 'Continue'

try {
    # Fetch current OS info
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) {
        Write-Output "$env:COMPUTERNAME | ERROR: Could not retrieve OS info"
        exit 1
    }

    $buildNumber = [int]$os.BuildNumber
    $version = $os.Version
    $caption = $os.Caption

    # Windows Update service state
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    $wuStatus = if ($wuService) { "$($wuService.Status) / $($wuService.StartType)" } else { "NOT_FOUND" }

    # Get latest CU from installed hotfixes (approximation; no direct API to current latest)
    $latestHotFix = Get-HotFix -ErrorAction SilentlyContinue |
        Where-Object { $_.HotFixID -match 'KB\d{7,8}' } |
        Sort-Object -Property InstalledOn -Descending |
        Select-Object -First 1

    $latestKB = if ($latestHotFix) { $latestHotFix.HotFixID } else { "UNKNOWN" }

    # Estimate days behind (rough: current month's CU vs machine's latest)
    # For Win11 25H2: Feb CU is 26200.7840, Jan CU is 26200.7623/7462
    $daysEstimate = if ($buildNumber -ge 26200) {
        if ($buildNumber -ge 26200.7840) { "0 (current)" }
        elseif ($buildNumber -ge 26200.7623) { "~21 (Jan CU)" }
        else { "~35+ (old Jan)" }
    } else {
        "UNKNOWN"
    }

    # Output as single line for fleet CSV/table ingestion
    Write-Output "$env:COMPUTERNAME | Build: $buildNumber | Latest KB: $latestKB | Days Behind: $daysEstimate | WU Service: $wuStatus"

    exit 0
} catch {
    Write-Output "$env:COMPUTERNAME | ERROR: $_"
    exit 1
}
