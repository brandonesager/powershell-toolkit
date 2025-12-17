# PowerShell Automation Portfolio

A collection of production-ready PowerShell scripts for Microsoft 365 administration, security analysis, and enterprise IT operations. These scripts demonstrate practical solutions developed through 7+ years of MSP experience managing multi-tenant environments.

## About

**Author:** Brandon Sager
**Background:** Tier 2 Remote Services Engineer managing 7,000+ endpoints across Microsoft 365, Active Directory, and hybrid Azure environments.

## Script Categories

### Security & Compliance

| Script | Description |
|--------|-------------|
| [Get-EmailBreachAnalysis.ps1](Get-EmailBreachAnalysis.ps1) | BEC detection tool analyzing .eml files with Entra ID sign-in correlation via Microsoft Graph |
| [Investigate-EntraConsentGrant.ps1](Investigate-EntraConsentGrant.ps1) | OAuth consent grant attack investigation with geolocation enrichment and remediation steps |
| [Get-InboxRuleAnalysis.ps1](Get-InboxRuleAnalysis.ps1) | Security analysis of inbox rules for forwarding, redirection, and hidden deletion patterns |
| [Get-Microsoft365SecurityIncidents.ps1](Get-Microsoft365SecurityIncidents.ps1) | Multi-source M365 account compromise investigation (Message Trace, Sign-in Logs, Unified Audit) |

### System Diagnostics

| Script | Description |
|--------|-------------|
| [Invoke-WorkstationStabilityDiagnostic.ps1](Invoke-WorkstationStabilityDiagnostic.ps1) | 900+ line comprehensive diagnostic with freeze, shutdown, hardware, and policy analysis modes |
| [Clear-RMMDiskSpace.ps1](Clear-RMMDiskSpace.ps1) | Production disk cleanup with 40 operations, WhatIf mode, and RMM exit codes |
| [Get-RMMPrinterDiagnostics.ps1](Get-RMMPrinterDiagnostics.ps1) | PDF rendering issue diagnostics with auto-remediation for Konica Minolta printers |
| [Get-TaskSchedulerAudit.ps1](Get-TaskSchedulerAudit.ps1) | Scheduled task security audit with risk scoring and auto-disable recommendations |
| [Get-SystemStorageStatus.ps1](Get-SystemStorageStatus.ps1) | Storage health reporting with SMART status and volume analysis |

### Microsoft 365 Administration

| Script | Description |
|--------|-------------|
| [Initialize-Microsoft365UserOnboarding.ps1](Initialize-Microsoft365UserOnboarding.ps1) | M365 onboarding with auto-discovery of shared mailboxes based on office location |
| [Restore-MailboxItemsWithStats.ps1](Restore-MailboxItemsWithStats.ps1) | Mailbox item recovery with before/after statistics and role assignment |
| [New-ExchangeMigrationBatch.ps1](New-ExchangeMigrationBatch.ps1) | Exchange Online migration batch creation with automatic license assignment |
| [Set-EntraConditionalAccessExclusion.ps1](Set-EntraConditionalAccessExclusion.ps1) | CA policy analysis with minimal-update exclusion command generation |

### Active Directory

| Script | Description |
|--------|-------------|
| [Initialize-ADUserOnboarding.ps1](Initialize-ADUserOnboarding.ps1) | AD user creation with group mirroring, role-based assignment, and Azure AD Connect sync |
| [Get-HybridAdInactiveUsers.ps1](Get-HybridAdInactiveUsers.ps1) | Cross-references on-prem AD with Exchange Online audit logs for true inactivity detection |

## Key Features

- **RMM Integration**: Scripts designed for ConnectWise RMM deployment with proper exit codes and logging
- **Graph API**: Modern authentication using Microsoft Graph PowerShell SDK
- **Idempotent Operations**: Safe to re-run without side effects
- **Comprehensive Logging**: Audit trails and transcript logging throughout
- **Error Handling**: Proper try/catch blocks with meaningful error messages

## Requirements

Most scripts require:
- PowerShell 5.1+ (some require PowerShell 7.0+ for Graph compatibility)
- Appropriate Microsoft 365 admin roles
- Common modules:
  - `ExchangeOnlineManagement`
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Reports`

## Usage

Each script includes comment-based help. Use `Get-Help` for documentation:

```powershell
Get-Help .\Get-EmailBreachAnalysis.ps1 -Full
```

## License

MIT License - Free to use and modify.

---

*Scripts developed through real-world MSP operations managing enterprise Microsoft 365 tenants and hybrid Active Directory environments.*
