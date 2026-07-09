<#
.SYNOPSIS
    Invoke-ExchangeHealthChecker — Downloads and runs Microsoft's Exchange Health Checker against the Contoso on-prem server (read-only).

.DESCRIPTION
    Downloads Microsoft's official Exchange Health Checker (https://aka.ms/ExchangeHealthChecker)
    and runs it read-only. Run BEFORE the upgrade for a baseline and AFTER each node upgrade plus
    security update. It reports CU/SU level, missing updates, TLS/cert config, .NET version, and
    required manual actions that Get-ExchangeServer alone does not surface. If the server has no
    internet, download HealthChecker.ps1 elsewhere and copy it into the work folder.
    Client: Contoso (contoso.example.com).

.KEYWORDS
    contoso, exchange, health checker, healthchecker, baseline, assessment, CU, SU, TLS, upgrade, diagnostic
#>

$ErrorActionPreference = 'Stop'
$work = 'C:\Contoso-ExchangeDiag\HealthChecker'
try   { New-Item -ItemType Directory -Path $work -Force | Out-Null }
catch { $work = Join-Path $env:TEMP 'HealthChecker'; New-Item -ItemType Directory -Path $work -Force | Out-Null }

$hc = Join-Path $work 'HealthChecker.ps1'

Write-Host "Downloading Health Checker to $hc ..." -ForegroundColor Cyan
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://aka.ms/ExchangeHealthChecker' -OutFile $hc -UseBasicParsing
} catch {
    Write-Host "Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "If the server has no internet, download HealthChecker.ps1 on another machine from https://aka.ms/ExchangeHealthChecker and copy it to $work" -ForegroundColor Yellow
    return
}

Write-Host "Running Health Checker (read-only, ~1-3 min) ..." -ForegroundColor Cyan
try {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    & $hc -OutputFilePath $work
    Write-Host "`nHealth Checker complete. Reports in: $work" -ForegroundColor Green
    Get-ChildItem $work -Filter 'HealthChecker-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 4 Name, LastWriteTime, Length | Format-Table -AutoSize
} catch {
    Write-Host "Health Checker run error: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "Open the .html report or email the .txt to user1@contoso.com" -ForegroundColor Green
