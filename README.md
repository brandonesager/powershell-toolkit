# PowerShell Automation Toolkit

PowerShell scripts for Microsoft 365 security, hybrid identity, fleet diagnostics, and RMM automation. 239 scripts, 47,000+ lines, developed independently on personal time.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Scripts](https://img.shields.io/badge/Scripts-239-orange)

## About

**Brandon Sager** | Systems Engineer | [LinkedIn](https://linkedin.com/in/brandonesager)

These scripts tackle the problems systems engineers hit every day: BEC investigations, orphaned mailbox permissions, SMB session drops, Windows Hello failures after motherboard replacements, fleet-wide printer queue rebuilds. I build and maintain the library independently on personal time, for my own automation practice.

## Categories

| Category | Scripts | Scope |
|-|-|-|
| [Diagnostics](Diagnostics/) | 94 | Read-only diagnostics: storage, network, GPO, printer, event log, performance |
| [RMM-Deployment](RMM-Deployment/) | 35 | SYSTEM-context deployment scripts, exit-code driven for RMM policies |
| [M365-Exchange](M365-Exchange/) | 25 | Exchange Online and on-prem Exchange Server administration |
| [M365-Entra](M365-Entra/) | 22 | Entra ID management, hybrid identity, user lifecycle automation |
| [System-Maintenance](System-Maintenance/) | 20 | SFC/DISM, disk cleanup, update management, scheduled maintenance |
| [ActiveDirectory](ActiveDirectory/) | 11 | On-prem AD operations and hybrid sync |
| [M365-Security](M365-Security/) | 11 | BEC investigation, consent grant attacks, conditional access, compliance |
| [Applications](Applications/) | 10 | Application install, configuration, and repair |
| [M365-SharePoint](M365-SharePoint/) | 5 | SharePoint Online administration and IRM remediation |
| [Backup-Recovery](Backup-Recovery/) | 2 | Backup verification and recovery tooling |
| [Networking](Networking/) | 2 | DNS, DHCP, connectivity testing |
| [Utilities](Utilities/) | 2 | General-purpose helpers |

## Highlights

| Script | What it does |
|-|-|
| [M365-Security/Investigate-EntraConsentGrant.ps1](M365-Security/Investigate-EntraConsentGrant.ps1) | OAuth consent grant attack investigation with geolocation enrichment |
| [M365-Security/Get-Microsoft365SecurityIncidents.ps1](M365-Security/Get-Microsoft365SecurityIncidents.ps1) | Multi-source M365 compromise investigation: Message Trace, sign-in logs, Unified Audit |
| [M365-Entra/Initialize-Microsoft365UserOnboarding.ps1](M365-Entra/Initialize-Microsoft365UserOnboarding.ps1) | Hybrid AD/M365 onboarding as a single-run job with auto-discovery |
| [M365-Exchange/Initialize-SMTPOAuthRelay.ps1](M365-Exchange/Initialize-SMTPOAuthRelay.ps1) | OAuth SMTP relay configuration end to end |
| [Diagnostics/Invoke-WorkstationStabilityDiagnostic.ps1](Diagnostics/Invoke-WorkstationStabilityDiagnostic.ps1) | Full workstation stability workup with structured output for RMM |

## Conventions

- Target PowerShell 5.1 unless the header says otherwise
- Comment-based help on every script: `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.KEYWORDS`
- Execution context noted per script: RMM (SYSTEM), interactive, or cloud (Graph/Exchange Online)
- Read-only diagnostics separated from scripts that change state

## License

MIT
