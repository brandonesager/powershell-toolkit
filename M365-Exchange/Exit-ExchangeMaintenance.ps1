<#
.SYNOPSIS
    Exit-ExchangeMaintenance — STEP 4: returns the Exchange server to service after the SE upgrade (** WRITE — REQUIRES APPROVAL **).

.DESCRIPTION
    Reverse of Enter-ExchangeMaintenance.ps1. DAG-aware: sets ServerWideOffline -> Active,
    and on a DAG member runs StopDagServerMaintenance (resumes the cluster node, re-enables copy
    activation, sets DatabaseCopyAutoActivationPolicy Unrestricted), then sets HubTransport ->
    Active and restarts MSExchangeTransport. Verifies component state, copy status, and queues.
    Run AFTER SE RTM + the May 2026 HU are installed, the server has rebooted, and post-upgrade
    validation looks clean.

.NOTES
    Created: 2026-05-29
    Category: Environment-Specific
    Context: Exchange Management Shell on the upgraded server.
    Approval: ** WRITE — REQUIRES APPROVAL **  Do NOT run without explicit go-ahead.
    Operator: set $Server before running.
    Reverse of: Enter-ExchangeMaintenance.ps1
    Ref: https://learn.microsoft.com/exchange/high-availability/manage-ha/manage-dags#performing-maintenance-on-dag-members

.KEYWORDS
    exchange, maintenance mode, exit, DAG, StopDagServerMaintenance, HubTransport, ServerWideOffline, write
#>

# ===== operator MUST set this =====
$Server = 'CHANGE_ME_SERVERNAME'
# ==================================

if ($Server -like 'CHANGE_ME*') { Write-Host 'STOP: edit $Server first.' -ForegroundColor Red; return }
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = "C:\Contoso-ExchangeDiag\MaintExit-$stamp.txt"
New-Item -ItemType Directory -Path (Split-Path $log) -Force | Out-Null
Start-Transcript -Path $log -Force | Out-Null

try {
    $isDag = [bool](Get-MailboxServer $Server).DatabaseAvailabilityGroup
    Write-Host "Server: $Server  |  DAG member: $isDag" -ForegroundColor Cyan

    Write-Host 'Setting ServerWideOffline -> Active...' -ForegroundColor Yellow
    Set-ServerComponentState $Server -Component ServerWideOffline -State Active -Requester Maintenance

    if ($isDag) {
        Write-Host 'Stopping DAG server maintenance (resumes node, re-enables copy activation)...' -ForegroundColor Yellow
        $sm = Join-Path $env:ExchangeInstallPath 'Scripts\StopDagServerMaintenance.ps1'
        & $sm -ServerName $Server
        Set-MailboxServer $Server -DatabaseCopyAutoActivationPolicy Unrestricted
    }

    Write-Host 'Setting HubTransport -> Active...' -ForegroundColor Yellow
    Set-ServerComponentState $Server -Component HubTransport -State Active -Requester Maintenance
    Restart-Service MSExchangeTransport

    Write-Host "`nVerification:" -ForegroundColor Cyan
    Get-ServerComponentState $Server | Format-Table Component, State, Requester -AutoSize
    if ($isDag) { Get-MailboxDatabaseCopyStatus -Server $Server | Format-Table Name, Status, CopyQueueLength, ReplayQueueLength -AutoSize }
    Get-Queue -Server $Server | Format-Table Identity, Status, MessageCount -AutoSize
    Write-Host "`nServer RETURNED to service. Watch mail flow and run post-upgrade validation if not already done." -ForegroundColor Green
}
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
finally { Stop-Transcript | Out-Null; Write-Host "Log: $log" -ForegroundColor Green }
