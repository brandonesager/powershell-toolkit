<#
.SYNOPSIS
    Set NLA (Network Location Awareness) to Automatic and start it.
.DESCRIPTION
    NLA (nlasvc) detects the network profile (Domain/Private/Public).
    On Win11 24H2, NLA defaults to Manual trigger-start. When NLA stops
    mid-session, Windows can lose DomainAuthenticated profile and apply
    Public firewall rules, blocking SMB (TCP 445) and dropping mapped drives.

    This script sets NLA to Automatic, starts it, and verifies the network
    profile returns to DomainAuthenticated. Optionally tests SMB connectivity
    to a specified file server.

    Deploy fleet-wide via RMM to fix Win11 24H2 machines with Manual NLA.
.PARAMETER FileServer
    Optional. Hostname or IP of file server to test SMB (TCP 445) connectivity.
    If omitted, SMB test is skipped.
.NOTES
    Context:  RMM (SYSTEM)
    Platform: Windows 11 24H2+
.SOURCE
    Date: 2026-02-23
.KEYWORDS
    NLA, Network Location Awareness, nlasvc, network profile, SMB, mapped drives, Win11
#>

param(
    [string]$FileServer = ""
)

$ErrorActionPreference = "Stop"

$hostname = $env:COMPUTERNAME
Write-Output "=== NLA FIX: $hostname ==="

# --- Current state ---
Write-Output "`n--- Pre-Fix State ---"
$nlaSvc = Get-Service -Name nlasvc -ErrorAction SilentlyContinue
if (-not $nlaSvc) {
    Write-Output "FATAL: nlasvc service not found"
    exit 1
}
Write-Output "  NLA Status: $($nlaSvc.Status) (StartType: $($nlaSvc.StartType))"

try {
    $profile = Get-NetConnectionProfile -ErrorAction Stop
    foreach ($p in $profile) {
        Write-Output "  Profile: $($p.Name) | Category: $($p.NetworkCategory) | NIC: $($p.InterfaceAlias)"
    }
} catch {
    Write-Output "  WARNING: Could not retrieve network profile: $_"
}

# --- Apply fix ---
Write-Output "`n--- Applying Fix ---"

try {
    Set-Service -Name nlasvc -StartupType Automatic -ErrorAction Stop
    Write-Output "  StartType set to Automatic"
} catch {
    Write-Output "  FATAL: Failed to set StartType: $_"
    exit 1
}

$nlaSvc = Get-Service -Name nlasvc
if ($nlaSvc.Status -ne 'Running') {
    try {
        Start-Service -Name nlasvc -ErrorAction Stop
        Start-Sleep -Seconds 3
        Write-Output "  NLA started"
    } catch {
        Write-Output "  WARNING: Start-Service failed — attempting Force restart..."
        try {
            Restart-Service -Name nlasvc -Force -ErrorAction Stop
            Start-Sleep -Seconds 5
            Write-Output "  NLA restarted via Force"
        } catch {
            Write-Output "  FATAL: Cannot start NLA: $_"
            exit 1
        }
    }
} else {
    Write-Output "  NLA already running (no restart needed)"
}

# --- Post-fix verification ---
Write-Output "`n--- Post-Fix State ---"
$nlaSvc = Get-Service -Name nlasvc
Write-Output "  NLA Status: $($nlaSvc.Status) (StartType: $($nlaSvc.StartType))"

Start-Sleep -Seconds 5

try {
    $profile = Get-NetConnectionProfile -ErrorAction Stop
    foreach ($p in $profile) {
        $category = $p.NetworkCategory
        $status = if ($category -eq 'DomainAuthenticated') { 'OK' } else { '** CHECK **' }
        Write-Output "  Profile: $($p.Name) | Category: $category | NIC: $($p.InterfaceAlias) | $status"
    }
} catch {
    Write-Output "  WARNING: Could not retrieve network profile: $_"
}

try {
    $fwProfile = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
    Write-Output "  Domain Firewall: Enabled=$($fwProfile.Enabled)"
} catch {
    Write-Output "  WARNING: Could not check firewall profile: $_"
}

if ($FileServer) {
    try {
        $smb = Test-NetConnection -ComputerName $FileServer -Port 445 -WarningAction SilentlyContinue -ErrorAction Stop
        $status = if ($smb.TcpTestSucceeded) { 'OK' } else { 'FAILED' }
        Write-Output "  SMB to ${FileServer}:445: $status"
    } catch {
        Write-Output "  WARNING: SMB test failed: $_"
    }
}

Write-Output "`n=== END: $hostname ==="
exit 0
