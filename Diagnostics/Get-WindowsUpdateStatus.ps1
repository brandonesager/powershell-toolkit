#Requires -Version 5.1

<#
.SYNOPSIS
    Get-WindowsUpdateStatus - Reports current Windows version and pending Windows Updates.

.DESCRIPTION
    Reads OS version from registry (HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion) and
    queries the Windows Update Agent COM API for pending non-hidden software updates. Outputs
    a single STATUS header line plus an OS line and the pending-update list. Read-only; does
    not install, download, or change configuration.

    Exit codes:
      0  Up to date (zero pending updates)
      1  Pending updates found
      2  Query failure (registry or WUA)

.NOTES
    Category: Diagnostics
    Context: RMM (SYSTEM), SYSTEM remote session, RMM shell
    - No third-party modules. Uses WUA COM only.
    - Search call can take 30-90s on stale endpoints, budget timeouts accordingly.
    - Windows Update is managed on an RMM cadence. Use this script for
      reporting, not as a precursor to manual install except when explicitly requested.

.KEYWORDS
    WindowsUpdate, RMM, SYSTEM, version, build, pending, diagnostic, WUA, patch
#>

[CmdletBinding()]
param()

try {
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $versionLine = "$($os.ProductName) $($os.DisplayVersion) Build $($os.CurrentBuild).$($os.UBR) ($($os.EditionID))"
} catch {
    Write-Output "STATUS: ERROR registry read failed: $($_.Exception.Message)"
    exit 2
}

try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $count    = $result.Updates.Count
} catch {
    Write-Output "STATUS: ERROR WUA search failed: $($_.Exception.Message)"
    Write-Output "OS: $versionLine"
    exit 2
}

if ($count -eq 0) {
    Write-Output "STATUS: UP_TO_DATE"
    Write-Output "OS: $versionLine"
    Write-Output "Pending: 0"
    exit 0
}

Write-Output "STATUS: PENDING_UPDATES ($count)"
Write-Output "OS: $versionLine"
Write-Output "Pending: $count"
$i = 0
foreach ($u in $result.Updates) {
    $i++
    $kb = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
    if (-not $kb) { $kb = '(no KB)' }
    Write-Output ("  [{0}] {1}  {2}" -f $i, $kb, $u.Title)
}
exit 1
