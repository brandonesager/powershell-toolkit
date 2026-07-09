<#
.SYNOPSIS
    Test-ExchangeBackupReadiness — STEP 0 read-only backup verification before the Contoso Exchange upgrade.

.DESCRIPTION
    Confirms a recent Exchange-aware (VSS) full backup of all mailbox databases AND a Windows
    System State backup exist BEFORE the upgrade window. There is no uninstall path for an Exchange
    version upgrade, so restore from backup is the only rollback. Reports database backup
    timestamps, flags databases with no or stale (>3 day) full backups, checks DAG copy health,
    reads Windows Server Backup history, and verifies VSS writer state. A third-party backup
    product (Veeam, etc.) updates LastFullBackup if VSS-aware but will not appear in wbadmin;
    confirm the actual backup tool with the site contact.
    Client: Contoso (contoso.example.com).

.KEYWORDS
    contoso, exchange, backup, verification, VSS, system state, wbadmin, DAG, rollback, upgrade, preflight, gate
#>

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir   = 'C:\Contoso-ExchangeDiag'
try   { New-Item -ItemType Directory -Path $dir -Force | Out-Null; $log = Join-Path $dir "BackupVerify-$stamp.txt" }
catch { $dir = $env:TEMP; $log = Join-Path $dir "BackupVerify-$stamp.txt" }
Start-Transcript -Path $log -Force | Out-Null

function Section($t){ Write-Host "`n======================  $t  ======================" -ForegroundColor Cyan }
function Try-Run($l,$sb){ Write-Host "`n--- $l ---" -ForegroundColor Yellow; try { & $sb } catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red } }

Write-Host "Contoso backup verification | $(Get-Date) | Host: $env:COMPUTERNAME" -ForegroundColor Green

Section '1. Mailbox database backup timestamps (VSS-aware)'
Try-Run 'Get-MailboxDatabase backup status' {
    Get-MailboxDatabase -Status | Format-List Name, Server, LastFullBackup, LastIncrementalBackup, LastDifferentialBackup, BackupInProgress, SnapshotLastFullBackup
}
Try-Run 'Flag databases with no full backup or stale (>3 days)' {
    Get-MailboxDatabase -Status | ForEach-Object {
        $age = if ($_.LastFullBackup) { (New-TimeSpan -Start $_.LastFullBackup -End (Get-Date)).Days } else { 'NEVER' }
        [pscustomobject]@{ Database = $_.Name; LastFullBackup = $_.LastFullBackup; AgeDays = $age; Status = if ($age -eq 'NEVER' -or $age -gt 3) { 'CHECK' } else { 'OK' } }
    } | Format-Table -AutoSize
}

Section '2. Database copy health (DAG safety before maintenance)'
Try-Run 'Get-MailboxDatabaseCopyStatus' {
    Get-MailboxDatabaseCopyStatus * | Format-Table Name, Status, CopyQueueLength, ReplayQueueLength, ContentIndexState -AutoSize
}

Section '3. Windows Server Backup history (System State)'
Try-Run 'wbadmin get versions' { wbadmin get versions }
Try-Run 'Windows Server Backup summary (if WSB role present)' {
    if (Get-Module -ListAvailable -Name WindowsServerBackup) {
        Import-Module WindowsServerBackup -ErrorAction Stop
        Get-WBSummary | Format-List LastBackupTime, LastSuccessfulBackupTime, NextBackupTime, NumberOfVersions
    } else { Write-Host 'WindowsServerBackup module not installed; backup is likely a third-party product. Confirm with the site contact.' }
}

Section '4. VSS writer health (failed writers break backups)'
Try-Run 'vssadmin list writers (state should be Stable / No error)' {
    vssadmin list writers | Select-String -Pattern 'Writer name', 'State', 'Last error'
}

Write-Host "`n======================  DONE  ======================" -ForegroundColor Green
Write-Host "GATE: do NOT start the upgrade unless a full mailbox DB backup AND a System State backup are confirmed recent." -ForegroundColor Green
Write-Host "Saved to: $log" -ForegroundColor Green
Stop-Transcript | Out-Null
