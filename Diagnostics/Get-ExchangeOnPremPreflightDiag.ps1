<#
.SYNOPSIS
    Read-only pre-flight and symptom diagnostic for Exchange Server 2019 / SE upgrade readiness.
.DESCRIPTION
    Checks Exchange version and CU level, Windows Server version, .NET Framework,
    disk free space, DAG/database state, hybrid configuration, service health,
    transport queues, back pressure, certificates, transport rules/agents, size
    limits, message tracking DEFER events, and Exchange Online connector state.
    Writes a timestamped transcript to -OutputDir and also echoes a tail to stdout.
    Run inside Exchange Management Shell (EMS) on or connected to the on-prem server.
    EXO sections (Section 14) error harmlessly when only in on-prem EMS; run those
    separately inside Connect-ExchangeOnline.
.PARAMETER OutputDir
    Directory where the transcript file is written. Created if it does not exist.
    Falls back to $env:TEMP if the specified path is not writable.
.NOTES
    Category: Diagnostics
    PS 5.1 compatible.
    Run context: Exchange Management Shell (on-prem), read-only.
.KEYWORDS
    Exchange, on-premises, upgrade, preflight, SE, CU, hybrid, back pressure, transport
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = 'C:\ExchangeDiag'
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

try {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $log = Join-Path $OutputDir "ExchangeDiag-$stamp.txt"
    Start-Transcript -Path $log -Force | Out-Null
} catch {
    $OutputDir = $env:TEMP
    $log = Join-Path $OutputDir "ExchangeDiag-$stamp.txt"
    Start-Transcript -Path $log -Force | Out-Null
    Write-Host "Specified output dir not writable; redirected to $log" -ForegroundColor Yellow
}

function Section($t) {
    Write-Host "`n========================  $t  ========================" -ForegroundColor Cyan
}
function Try-Run($label, $sb) {
    Write-Host "`n--- $label ---" -ForegroundColor Yellow
    try { & $sb } catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
}

Write-Host "Exchange on-prem diagnostic  |  $(Get-Date)  |  Host: $env:COMPUTERNAME" -ForegroundColor Green

# ===================== PRE-FLIGHT (upgrade readiness) =====================
Section '1. Exchange version / CU  (need CU14 15.2.1544.x or CU15 15.2.1748.x for in-place)'
Try-Run 'Get-ExchangeServer' {
    Get-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion,ServerRole,Site
}
Try-Run 'ExSetup build (true SU level)' {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup').MsiProductMajor
    (Get-Command ExSetup.exe -ErrorAction Stop).FileVersionInfo.ProductVersion
}

Section '2. Windows Server version  (SE RTM supports 2019/2022/2025 in-place)'
Try-Run 'OS caption / build' {
    (Get-CimInstance Win32_OperatingSystem) | Format-List Caption,Version,BuildNumber,OSArchitecture
}

Section '3. .NET Framework  (528040+=4.8 min, 533320+=4.8.1)'
Try-Run '.NET release' {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
}

Section '4. Disk free  (30+ GB free on binary + DB/log drives; low disk = back pressure)'
Try-Run 'All fixed drives' {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
        Select-Object DeviceID,
            @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}},
            @{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},
            @{N='Free%';E={[math]::Round($_.FreeSpace/$_.Size*100,1)}} |
        Format-Table -AutoSize
}

Section '5. DAG vs single server'
Try-Run 'Get-DatabaseAvailabilityGroup' {
    Get-DatabaseAvailabilityGroup | Format-List Name,Servers,WitnessServer
}
Try-Run 'Mailbox databases' {
    Get-MailboxDatabase -Status | Format-List Name,Server,EdbFilePath,LogFolderPath,DatabaseSize,Mounted
}

Section '6. Hybrid configuration'
Try-Run 'Get-HybridConfiguration'    { Get-HybridConfiguration | Format-List }
Try-Run 'IntraOrganizationConnector' {
    Get-IntraOrganizationConnector | Format-List Name,TargetAddressDomains,DiscoveryEndpoint,Enabled
}
Try-Run 'OAuth / AuthConfig' {
    Get-AuthConfig | Format-List CurrentCertificateThumbprint,ServiceName,Realm
}
Try-Run 'Accepted domains' {
    Get-AcceptedDomain | Format-Table Name,DomainName,DomainType,Default -AutoSize
}

Section '7. Service health'
Try-Run 'Exchange services' {
    Get-Service *Exchange* | Format-Table Name,Status,StartType -AutoSize
}
Try-Run 'Test-ServiceHealth' {
    Test-ServiceHealth | Format-List Role,RequiredServicesRunning,ServicesNotRunning
}
Try-Run 'Server component state' {
    Get-ServerComponentState -Identity $env:COMPUTERNAME |
        Where-Object State -ne 'Active' | Format-Table Component,State,Requester -AutoSize
    Write-Host '(only NON-active components shown; empty = all active)'
}

# ===================== SYMPTOM: randomly blocking email replies =====================
Section '8. Transport queues  (held/retry counts; large = active hold)'
Try-Run 'Get-Queue' {
    Get-Queue | Format-Table Identity,DeliveryType,Status,MessageCount,NextHopDomain,LastError -AutoSize
}

Section '9. Back pressure  (TOP suspect - resource thresholds)'
Try-Run 'Resource meter' {
    [xml]$bp = Get-ExchangeDiagnosticInfo -Process EdgeTransport -Component ResourceThrottling
    $bp.Diagnostics.Components.ResourceThrottling.ResourceTracker.ResourceMeter |
        Format-Table Resource,CurrentResourceUse,PreviousResourceUse,Pressure -AutoSize
}
Try-Run 'Back pressure events 15004/15006/15007 (last 7d)' {
    Get-EventLog -LogName Application -After (Get-Date).AddDays(-7) -ErrorAction Stop |
        Where-Object { $_.EventID -in 15004,15006,15007 } |
        Select-Object -First 20 TimeGenerated,EventID,Message | Format-List
}

Section '10. Certificates / TLS  (2nd suspect - hybrid connector cert mismatch)'
Try-Run 'Exchange certificates' {
    Get-ExchangeCertificate |
        Format-Table Thumbprint,Services,NotAfter,@{N='Subject';E={$_.Subject}} -AutoSize
}
Try-Run 'Send connectors' {
    Get-SendConnector |
        Format-List Name,Enabled,SmartHosts,TlsCertificateName,TlsDomain,CloudServicesMailEnabled,AddressSpaces
}
Try-Run 'Receive connectors' {
    Get-ReceiveConnector | Format-Table Name,Enabled,TlsCertificateName,Fqdn,Bindings -AutoSize
}
Try-Run 'Cert/TLS events 12014 (last 7d)' {
    Get-EventLog -LogName Application -After (Get-Date).AddDays(-7) -ErrorAction Stop |
        Where-Object { $_.EventID -eq 12014 } |
        Select-Object -First 10 TimeGenerated,Message | Format-List
}

Section '11. Transport rules / agents  (silent defer or drop)'
Try-Run 'Transport rules' {
    Get-TransportRule |
        Format-Table Name,State,Priority,RuleErrorAction,StopRuleProcessing -AutoSize
}
Try-Run 'Transport agents' {
    Get-TransportAgent | Format-Table Identity,Enabled,Priority -AutoSize
}

Section '12. Size / throttling limits  (inconsistent blocks on large replies)'
Try-Run 'Org transport config' {
    Get-TransportConfig | Format-List MaxSendSize,MaxReceiveSize,MaxRecipientEnvelopeLimit
}
Try-Run 'Connector size limits' {
    Get-SendConnector | Format-Table Name,MaxMessageSize -AutoSize
    Get-ReceiveConnector | Format-Table Name,MaxMessageSize -AutoSize
}

Section '13. Recent DEFER events in message tracking (last 24h, grouped)'
Try-Run 'Message tracking DEFER' {
    Get-MessageTrackingLog -EventId DEFER -Start (Get-Date).AddHours(-24) -ResultSize Unlimited |
        Group-Object Source | Sort-Object Count -Descending |
        Format-Table Count,Name -AutoSize
}

# ===================== EXO SIDE (run only inside Connect-ExchangeOnline) =====================
Section '14. Exchange Online connectors  (errors here are normal if NOT in an EXO session)'
Try-Run 'EXO inbound connector' {
    Get-InboundConnector | Format-List Name,Enabled,TlsSenderCertificateName,SenderDomains
}
Try-Run 'EXO outbound connector' {
    Get-OutboundConnector | Format-List Name,Enabled,SmartHosts,TlsDomain,TlsSettings
}

Write-Host "`n========================  DONE  ========================" -ForegroundColor Green
Write-Host "Output saved to: $log" -ForegroundColor Green
Stop-Transcript | Out-Null
