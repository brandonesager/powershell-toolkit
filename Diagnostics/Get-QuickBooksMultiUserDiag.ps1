#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Diagnose and fix QuickBooks multi-user H202 connectivity issues

.DESCRIPTION
    Checks QuickBooks Database Server Manager services, company file health,
    .ND file state, firewall rules, QB port availability, active SMB connections,
    and disk space. Optionally fixes service startup type to Automatic.

    Run from SYSTEM remote session (SYSTEM context) on the QB hosting server.

.PARAMETER Fix
    Apply fixes: set QuickBooksDB34 startup to Automatic

.PARAMETER CompanyPath
    Path to QB company file folder. Default: D:\Quickbooks\Company

.EXAMPLE
    .\Get-QuickBooksMultiUserDiag.ps1
    Diagnostic-only run with defaults

.EXAMPLE
    .\Get-QuickBooksMultiUserDiag.ps1 -Fix
    Run diagnostics and apply fixes

.EXAMPLE
    .\Get-QuickBooksMultiUserDiag.ps1 -CompanyPath 'E:\QB\Data'
    Diagnostic with custom company file path

.NOTES
    Category: Diagnostics

.KEYWORDS
    quickbooks, H202, multi-user, database server manager, QBDB, diagnose
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Fix,

    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$CompanyPath = 'D:\Quickbooks\Company'
)

$divider = '=' * 60
$issues = 0

# --- 1. QB Database Services ---
Write-Host "`n$divider"
Write-Host "1. QuickBooks Database Services"
Write-Host $divider

$qbServices = Get-Service QuickBooksDB* -ErrorAction SilentlyContinue
if (-not $qbServices) {
    Write-Host "ERROR: No QuickBooks Database services found"
    $issues++
}
else {
    $qbServices | ForEach-Object {
        $startType = $_.StartType
        $status = $_.Status
        $flag = ''

        if ($status -ne 'Running') {
            $flag = ' [NOT RUNNING]'
            $issues++
        }
        if ($startType -ne 'Automatic') {
            $flag += ' [STARTUP: Manual]'
            $issues++
        }

        Write-Host "  $($_.Name) — $status — StartType: $startType$flag"
    }
}

# --- 2. Fix Service Startup (if -Fix) ---
if ($Fix) {
    Write-Host "`n$divider"
    Write-Host "2. Applying Fixes"
    Write-Host $divider

    $db34 = Get-Service 'QuickBooksDB34' -ErrorAction SilentlyContinue
    if ($db34) {
        if ($db34.StartType -ne 'Automatic') {
            if ($PSCmdlet.ShouldProcess('QuickBooksDB34', 'Set StartupType to Automatic')) {
                Set-Service -Name 'QuickBooksDB34' -StartupType Automatic
                Write-Host "  QuickBooksDB34 startup changed to Automatic"
            }
        }
        else {
            Write-Host "  QuickBooksDB34 already set to Automatic — no change"
        }

        if ($db34.Status -ne 'Running') {
            if ($PSCmdlet.ShouldProcess('QuickBooksDB34', 'Start service')) {
                Start-Service -Name 'QuickBooksDB34'
                Write-Host "  QuickBooksDB34 started"
            }
        }
    }
    else {
        Write-Host "  QuickBooksDB34 service not found — skipping"
    }
}

# --- 3. Company File and .ND Files ---
Write-Host "`n$divider"
Write-Host "3. Company File and .ND Files ($CompanyPath)"
Write-Host $divider

$qbFiles = Get-ChildItem $CompanyPath -Recurse -Include *.QBW,*.QBB,*.ND -ErrorAction SilentlyContinue
if (-not $qbFiles) {
    Write-Host "  No QBW/ND files found in $CompanyPath"
    $issues++
}
else {
    $qbFiles | ForEach-Object {
        $sizeMB = [math]::Round($_.Length / 1MB, 2)
        $age = (New-TimeSpan -Start $_.LastWriteTime -End (Get-Date))
        $ageStr = if ($age.TotalHours -lt 24) { "$([math]::Round($age.TotalHours,1))h ago" } else { "$($age.Days)d ago" }
        Write-Host "  $($_.Name) — $sizeMB MB — Modified: $ageStr"
    }

    $ndFiles = $qbFiles | Where-Object { $_.Extension -eq '.ND' }
    $qbwFiles = $qbFiles | Where-Object { $_.Extension -eq '.QBW' }
    if ($qbwFiles -and -not $ndFiles) {
        Write-Host "  WARNING: Company file found but no .ND file — run Database Server Manager scan"
        $issues++
    }
}

# --- 4. Firewall Rules ---
Write-Host "`n$divider"
Write-Host "4. Firewall Rules"
Write-Host $divider

$fwRules = Get-NetFirewallRule -DisplayName '*QuickBooks*' -ErrorAction SilentlyContinue
if ($fwRules) {
    $fwRules | ForEach-Object {
        Write-Host "  $($_.DisplayName) — Enabled: $($_.Enabled) — $($_.Direction) — $($_.Action)"
    }
}
else {
    Write-Host "  No QuickBooks-specific firewall rules found"
}

# --- 5. QB Port Check ---
Write-Host "`n$divider"
Write-Host "5. QB Port Availability (localhost)"
Write-Host $divider

foreach ($port in @(8019, 56728)) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $open = $false
    try {
        $result = $tcp.ConnectAsync('localhost', $port).Wait(500)
        $open = $tcp.Connected
    }
    catch { }
    finally { $tcp.Close() }

    $status = if ($open) { 'LISTENING' } else { 'CLOSED' }
    $flag = if (-not $open) { ' [expected open for multi-user]' } else { '' }
    Write-Host "  Port $port — $status$flag"
    if (-not $open) { $issues++ }
}

# --- 6. Active SMB Connections to Company File ---
Write-Host "`n$divider"
Write-Host "6. Active SMB Connections"
Write-Host $divider

$smbFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like '*Quickbooks*' -or $_.Path -like '*.QBW*' -or $_.Path -like '*.QBB*'
}
if ($smbFiles) {
    $smbFiles | ForEach-Object {
        Write-Host "  $($_.ClientComputerName) — $($_.ClientUserName) — $($_.Path)"
    }
}
else {
    Write-Host "  No active QB file connections"
}

# --- 7. Disk Space ---
Write-Host "`n$divider"
Write-Host "7. Disk Space"
Write-Host $divider

$driveLetter = $CompanyPath.Substring(0, 2)
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$driveLetter'"
if ($disk) {
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
    $totalGB = [math]::Round($disk.Size / 1GB, 1)
    $usedPct = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
    $flag = if ($freeGB -lt 5) { ' [LOW SPACE]'; $issues++ } else { '' }
    Write-Host "  $driveLetter — $freeGB GB free / $totalGB GB total ($usedPct% used)$flag"
}

# --- Summary ---
Write-Host "`n$divider"
Write-Host "SUMMARY: $issues issue(s) found"
if (-not $Fix -and $issues -gt 0) {
    Write-Host "Run with -Fix to apply automatic remediations"
}
Write-Host $divider
