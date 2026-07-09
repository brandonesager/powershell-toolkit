<#
.SYNOPSIS
    Enter-ExchangeMaintenance — STEP 1: places the Exchange server into maintenance mode before the SE upgrade (** WRITE — REQUIRES APPROVAL **).

.DESCRIPTION
    Takes the target server out of service safely before the upgrade. DAG-aware: on a DAG member
    it drains transport, redirects queued messages to a healthy peer, blocks copy activation, and
    pauses the cluster node; on a single server it drains transport only (and requires an explicit
    downtime-acknowledgement flag because there is no failover). Modifies live mail routing.
    Reverse with Exit-ExchangeMaintenance.ps1.

    WHAT IT CHANGES: HubTransport component -> Draining; restarts MSExchangeTransport; (DAG)
    Redirect-Message, StartDagServerMaintenance, DatabaseCopyAutoActivationPolicy Blocked;
    ServerWideOffline -> Inactive.

.NOTES
    Created: 2026-05-29
    Category: Environment-Specific
    Context: Exchange Management Shell on the server being upgraded.
    Approval: ** WRITE — REQUIRES APPROVAL **  Do NOT run without explicit go-ahead.
    Operator: set $Server, $TargetServer (DAG), $IUnderstandSingleServerMailWillStop (single server) before running.
    Reverse: Exit-ExchangeMaintenance.ps1
    Ref: https://learn.microsoft.com/exchange/high-availability/manage-ha/manage-dags#performing-maintenance-on-dag-members

.KEYWORDS
    exchange, maintenance mode, DAG, drain, HubTransport, ServerWideOffline, StartDagServerMaintenance, upgrade, write
#>

# ===== operator MUST set these before running =====
$Server       = 'CHANGE_ME_SERVERNAME'          # the server being upgraded (NetBIOS name)
$TargetServer = 'CHANGE_ME_OTHER.contoso.example.com'     # DAG only: FQDN of another healthy member to redirect mail to. Leave as-is if single server.
$IUnderstandSingleServerMailWillStop = $false   # SINGLE server ONLY: set $true to confirm you accept TOTAL mail downtime (no failover) during the window
# ==================================================

if ($Server -like 'CHANGE_ME*') { Write-Host 'STOP: edit $Server first.' -ForegroundColor Red; return }
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = "C:\Contoso-ExchangeDiag\MaintEnter-$stamp.txt"
New-Item -ItemType Directory -Path (Split-Path $log) -Force | Out-Null
Start-Transcript -Path $log -Force | Out-Null

try {
    $isDag = [bool](Get-MailboxServer $Server).DatabaseAvailabilityGroup
    Write-Host "Server: $Server  |  DAG member: $isDag" -ForegroundColor Cyan

    if (-not $isDag -and -not $IUnderstandSingleServerMailWillStop) {
        throw 'SINGLE server detected. This takes mail flow COMPLETELY down with no failover. Confirm the client approved the downtime window, then set $IUnderstandSingleServerMailWillStop = $true to proceed.'
    }

    Write-Host 'Draining HubTransport...' -ForegroundColor Yellow
    Set-ServerComponentState $Server -Component HubTransport -State Draining -Requester Maintenance
    Restart-Service MSExchangeTransport

    if ($isDag) {
        if ($TargetServer -like 'CHANGE_ME*') { throw 'DAG member but $TargetServer not set. Set a healthy peer FQDN and re-run.' }
        Write-Host "Redirecting queued mail to $TargetServer..." -ForegroundColor Yellow
        Redirect-Message -Server $Server -Target $TargetServer -Confirm:$false
        Write-Host 'Starting DAG server maintenance (pauses cluster node, moves active copies)...' -ForegroundColor Yellow
        $sm = Join-Path $env:ExchangeInstallPath 'Scripts\StartDagServerMaintenance.ps1'
        & $sm -ServerName $Server -MoveComment 'SE upgrade' -PauseClusterNode
        Set-MailboxServer $Server -DatabaseCopyAutoActivationPolicy Blocked
    }

    Write-Host 'Setting ServerWideOffline -> Inactive...' -ForegroundColor Yellow
    Set-ServerComponentState $Server -Component ServerWideOffline -State Inactive -Requester Maintenance

    Write-Host "`nVerification:" -ForegroundColor Cyan
    Get-ServerComponentState $Server | Format-Table Component, State, Requester -AutoSize
    Get-Queue -Server $Server | Format-Table Identity, Status, MessageCount, NextHopDomain -AutoSize
    if ($isDag) { Get-MailboxDatabaseCopyStatus -Server $Server | Format-Table Name, Status, ActivationSuspended -AutoSize }
    Write-Host "`nMaintenance mode ENTERED. Proceed with the upgrade once queues are empty." -ForegroundColor Green
}
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
finally { Stop-Transcript | Out-Null; Write-Host "Log: $log" -ForegroundColor Green }
