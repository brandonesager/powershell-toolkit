<#
.SYNOPSIS
    Test-ExchangePostUpgradeHybrid — Read-only post-upgrade and hybrid coexistence validation for the Exchange server.

.DESCRIPTION
    Confirms the SE upgrade landed cleanly and hybrid coexistence with Exchange Online is intact.
    Checks build (expect SE 15.2.2562.17 RTM, 15.2.2562.41 after May26HU), service health,
    component state, mail flow/queues, hybrid OAuth (Test-OAuthConnectivity AutoD + EWS),
    hybrid configuration objects, connectors and certificate expiry, and recent app-log errors.
    Read-only: no HCW changes are made; if a check fails, decide separately whether a scoped HCW
    re-run is needed. Run AFTER SE RTM + the May 2026 HU are installed and the server has rebooted
    and exited maintenance mode.
    Client: Contoso (contoso.example.com).

.KEYWORDS
    contoso, exchange, post-upgrade, validation, hybrid, OAuth, free/busy, connectors, build, mail flow, SE, diagnostic
#>

# ---- operator sets this ----
$TestMailbox = 'CHANGE_ME@contoso.example.com'
# ----------------------------
if ($TestMailbox -like 'CHANGE_ME*') { Write-Warning 'TestMailbox not set: the OAuth tests in Section 4 will fail. Set a real on-prem mailbox SMTP to validate hybrid OAuth, then re-run.' }

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir   = 'C:\Contoso-ExchangeDiag'
try   { New-Item -ItemType Directory -Path $dir -Force | Out-Null; $log = Join-Path $dir "PostUpgrade-$stamp.txt" }
catch { $dir = $env:TEMP; $log = Join-Path $dir "PostUpgrade-$stamp.txt" }
Start-Transcript -Path $log -Force | Out-Null

function Section($t){ Write-Host "`n======================  $t  ======================" -ForegroundColor Cyan }
function Try-Run($l,$sb){ Write-Host "`n--- $l ---" -ForegroundColor Yellow; try { & $sb } catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red } }

Write-Host "Contoso post-upgrade validation | $(Get-Date) | Host: $env:COMPUTERNAME" -ForegroundColor Green

Section '1. Build confirmation (expect SE: 15.2.2562.17 RTM, 15.2.2562.41 after May26HU)'
Try-Run 'Get-ExchangeServer' { Get-ExchangeServer | Format-List Name, Edition, AdminDisplayVersion }
Try-Run 'ExSetup true build' { (Get-Command ExSetup.exe -ErrorAction Stop).FileVersionInfo.ProductVersion }

Section '2. Service health'
Try-Run 'Test-ServiceHealth' { Test-ServiceHealth | Format-List Role, RequiredServicesRunning, ServicesNotRunning }
Try-Run 'Exchange services not running' { Get-Service *Exchange* | Where-Object Status -ne 'Running' | Format-Table Name, Status -AutoSize; Write-Host '(empty = all running)' }
Try-Run 'Component state not active' { Get-ServerComponentState -Identity $env:COMPUTERNAME | Where-Object State -ne 'Active' | Format-Table Component, State, Requester -AutoSize; Write-Host '(empty = all active)' }

Section '3. Mail flow / queues'
Try-Run 'Get-Queue' { Get-Queue | Format-Table Identity, DeliveryType, Status, MessageCount, NextHopDomain, LastError -AutoSize }

Section '4. Hybrid OAuth (must stay healthy for free/busy, MailTips)'
Try-Run 'Get-AuthConfig' { Get-AuthConfig | Format-List CurrentCertificateThumbprint, ServiceName, Realm }
Try-Run 'Test-OAuthConnectivity AutoD' { Test-OAuthConnectivity -Service AutoD -TargetUri 'https://outlook.office365.com/autodiscover/autodiscover.svc' -Mailbox $TestMailbox | Format-List Service, ResultType, Detail }
Try-Run 'Test-OAuthConnectivity EWS' { Test-OAuthConnectivity -Service EWS -TargetUri 'https://outlook.office365.com/ews/exchange.asmx' -Mailbox $TestMailbox | Format-List Service, ResultType, Detail }

Section '5. Hybrid configuration objects (unchanged by a clean in-place upgrade)'
Try-Run 'Get-HybridConfiguration' { Get-HybridConfiguration | Format-List }
Try-Run 'Get-IntraOrganizationConnector' { Get-IntraOrganizationConnector | Format-List Name, TargetAddressDomains, DiscoveryEndpoint, Enabled }
Try-Run 'Get-OrganizationRelationship' { Get-OrganizationRelationship | Format-List Name, DomainNames, FreeBusyAccessEnabled, TargetAutodiscoverEpr }

Section '6. Connectors and certificates (TLS for hybrid mail flow)'
Try-Run 'Send connectors' { Get-SendConnector | Format-List Name, Enabled, SmartHosts, TlsCertificateName, TlsDomain, CloudServicesMailEnabled }
Try-Run 'Exchange certs + expiry' { Get-ExchangeCertificate | Format-Table Thumbprint, Services, NotAfter, Subject -AutoSize }

Section '7. Recent errors since upgrade'
Try-Run 'App-log errors last 2h' { Get-EventLog -LogName Application -EntryType Error -After (Get-Date).AddHours(-2) -ErrorAction Stop | Select-Object -First 25 TimeGenerated, Source, EventID, Message | Format-List }

Write-Host "`n======================  DONE  ======================" -ForegroundColor Green
Write-Host "Manual checks still required: OWA login, ECP login, Outlook send/receive, free/busy lookup of a cloud mailbox from an on-prem mailbox, and one inbound + one outbound external test message." -ForegroundColor Green
Write-Host "Saved to: $log" -ForegroundColor Green
Stop-Transcript | Out-Null
