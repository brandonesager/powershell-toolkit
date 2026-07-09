<#
.SYNOPSIS
    Enable server-side RDP keep-alive on an RDS Session Host to prevent NAT/firewall
    idle-reaping of disconnected or idle RDS sessions.

.DESCRIPTION
    When a TCP-level idle timeout on a NAT/firewall or ISP kills the underlying connection,
    RDP surfaces it to the user as an idle disconnect even though no Microsoft idle-timeout
    policy has fired. Server-side RDP keep-alive sends periodic TCP keep-alive packets
    that prevent this reaping.

    Writes KeepAliveEnable = 1 and KeepAliveInterval = <N> (minutes) under:
      HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services

    This is the Computer GPO registry path, which takes effect on new sessions immediately
    and on existing sessions at next reconnect. No reboot required.

    Runs gpupdate /target:computer /force and creates a transcript in
    C:\ProgramData\RMM\ for audit.

.PARAMETER KeepAliveInterval
    Keep-alive interval in minutes. Default 1 (recommended: keeps firewalls with
    60-second idle timeouts from reaping the connection).

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1 on Session Host)

.KEYWORDS
    RDP, keep-alive, KeepAliveEnable, KeepAliveInterval, NAT, firewall, idle disconnect,
    RDS, session host, TCP
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [int]$KeepAliveInterval = 1
)

$ErrorActionPreference = 'Stop'

$key     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$logDir  = 'C:\ProgramData\RMM'
$logPath = Join-Path $logDir ("Set-RDPKeepAlive-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null

Write-Output "Set-RDPKeepAlive"
Write-Output ("Host             : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp        : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("KeepAliveInterval: {0} minute(s)" -f $KeepAliveInterval)
Write-Output ("Log              : {0}" -f $logPath)
Write-Output ""

# Create key if absent
if (-not (Test-Path $key)) { New-Item $key -Force | Out-Null }

# --- Before ---
Write-Output "=== Before ==="
$before = Get-ItemProperty $key
Write-Output ("  KeepAliveEnable   : {0}" -f $before.KeepAliveEnable)
Write-Output ("  KeepAliveInterval : {0}" -f $before.KeepAliveInterval)

# --- Apply ---
Write-Output ""
Write-Output "=== Applying ==="
New-ItemProperty $key -Name 'KeepAliveEnable'   -Value 1                  -PropertyType DWord -Force | Out-Null
New-ItemProperty $key -Name 'KeepAliveInterval' -Value $KeepAliveInterval -PropertyType DWord -Force | Out-Null
Write-Output ("  Set KeepAliveEnable = 1")
Write-Output ("  Set KeepAliveInterval = {0}" -f $KeepAliveInterval)

# --- After ---
Write-Output ""
Write-Output "=== After ==="
$after = Get-ItemProperty $key
Write-Output ("  KeepAliveEnable   : {0}" -f $after.KeepAliveEnable)
Write-Output ("  KeepAliveInterval : {0}" -f $after.KeepAliveInterval)

# --- gpupdate ---
Write-Output ""
Write-Output "=== Refreshing computer policy ==="
& gpupdate /target:computer /force 2>&1 | Out-String | Write-Output

Write-Output ""
Write-Output "=== Done ==="
Write-Output "New RDS sessions inherit KeepAlive immediately."
Write-Output "Existing sessions pick up the setting on their next reconnect."
Write-Output ("Log: {0}" -f $logPath)

Stop-Transcript | Out-Null
