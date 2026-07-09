<#
.SYNOPSIS
    Analyzes local user profiles for size, activity, and sync status.

.DESCRIPTION
    RMM-safe. Reports profile size excluding cloud sync reparse points
    (Egnyte, OneDrive, PCShare). Identifies loaded profiles, last logon,
    and flags large profiles for cleanup triage.

.NOTES
    Target: PS 5.1 (RMM toolbox)
    Context: SYSTEM — uses Win32_ComputerSystem for logged-in user

.EXAMPLE
    # Run via RMM toolbox — no parameters required
    .\Get-UserProfileAnalysis.ps1
#>

#region --- Logged-in user detection ---
$loggedInUser = (Get-WmiObject Win32_ComputerSystem).UserName
# Strip domain prefix if present
if ($loggedInUser -match '\\') { $loggedInUser = $loggedInUser.Split('\')[1] }
#endregion

#region --- Profile discovery ---
$profiles = Get-WmiObject Win32_UserProfile |
    Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' }
#endregion

#region --- Profile analysis ---
$results = foreach ($p in $profiles) {
    $username = Split-Path $p.LocalPath -Leaf
    $loaded   = $p.Loaded

    # Last use time
    $lastUse = $null
    if ($p.LastUseTime) {
        try { $lastUse = [Management.ManagementDateTimeConverter]::ToDateTime($p.LastUseTime) }
        catch { $lastUse = $null }
    }
    $daysAgo = if ($lastUse) { [math]::Round((New-TimeSpan -Start $lastUse -End (Get-Date)).TotalDays, 1) } else { 'Unknown' }

    # Profile size — exclude reparse points (cloud sync junctions)
    $sizeGB = 'Error'
    try {
        $bytes = (Get-ChildItem -Path $p.LocalPath -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) } |
            Measure-Object -Property Length -Sum).Sum
        $sizeGB = [math]::Round($bytes / 1GB, 2)
    } catch { }

    # Detect cloud sync presence
    $hasEgnyte   = Test-Path "$($p.LocalPath)\Egnyte"
    $hasOneDrive = Test-Path "$($p.LocalPath)\OneDrive*"
    $syncFlag    = @()
    if ($hasEgnyte)   { $syncFlag += 'Egnyte' }
    if ($hasOneDrive) { $syncFlag += 'OneDrive' }
    $syncNote = if ($syncFlag) { $syncFlag -join ',' } else { 'None' }

    # Status label
    $status = if ($username -eq $loggedInUser) { 'ACTIVE' }
              elseif ($loaded) { 'LOADED' }
              elseif ($daysAgo -ne 'Unknown' -and $daysAgo -gt 90) { 'STALE' }
              else { 'Inactive' }

    [PSCustomObject]@{
        Username   = $username
        Status     = $status
        SizeGB     = $sizeGB
        LastUseDays = $daysAgo
        CloudSync  = $syncNote
        Path       = $p.LocalPath
    }
}
#endregion

#region --- Output ---
Write-Output "=== USER PROFILE ANALYSIS ==="
Write-Output "Logged-in user: $loggedInUser"
Write-Output "Scan time: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Output ""

$results | Sort-Object SizeGB -Descending | ForEach-Object {
    Write-Output "[$($_.Status)] $($_.Username)"
    Write-Output "  Size (excl. cloud sync): $($_.SizeGB) GB"
    Write-Output "  Last use: $($_.LastUseDays) days ago"
    Write-Output "  Cloud sync detected: $($_.CloudSync)"
    Write-Output "  Path: $($_.Path)"
    Write-Output ""
}

# Summary flags
$largeProfiles = $results | Where-Object { $_.SizeGB -ne 'Error' -and [double]$_.SizeGB -gt 10 }
$staleProfiles = $results | Where-Object { $_.Status -eq 'STALE' }

if ($largeProfiles) {
    Write-Output "=== FLAGS: LARGE PROFILES (>10 GB) ==="
    $largeProfiles | ForEach-Object { Write-Output "  $($_.Username): $($_.SizeGB) GB" }
    Write-Output ""
}
if ($staleProfiles) {
    Write-Output "=== FLAGS: STALE PROFILES (>90 days) ==="
    $staleProfiles | ForEach-Object { Write-Output "  $($_.Username): last used $($_.LastUseDays) days ago" }
    Write-Output ""
}

Write-Output "NOTE: Sizes exclude Egnyte/OneDrive reparse points. Actual disk use may differ."
Write-Output "NOTE: To remove a stale profile: Get-WmiObject Win32_UserProfile | Where-Object {`$_.LocalPath -like '*username*'} | Remove-WmiObject"
#endregion
