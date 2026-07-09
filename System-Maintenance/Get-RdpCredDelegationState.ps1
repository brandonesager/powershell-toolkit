<#
.SYNOPSIS
    Read all policy layers that control RDP saved credential persistence on a Windows
    workstation. Diagnoses why "Remember me" does not persist in mstsc.

.DESCRIPTION
    Two registry paths gate credential saving in Remote Desktop:
      1. HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving
         If = 1, the "Remember me" checkbox is greyed out globally.
      2. HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly
         If absent or 0, credentials are not delegated to NTLM-only targets (legacy servers,
         Win7/2008 R2 hosts not joined to the same domain or without Kerberos).

    On Windows 11, the default behavior refuses saved credentials to NTLM-only targets
    unless explicitly allowed via CredentialsDelegation policy. This is the most common
    cause of mstsc "Remember me" failing for connections to older servers.

    Also reads:
      - gpresult output filtered for RDP/CredentialsDelegation matches
      - Existing TERMSRV/* saved credentials in the SYSTEM credential store (diagnostic only)

    Read-only. Pair with Set-RdpCredDelegationNtlmOnly.ps1 to apply the fix.

.PARAMETER TargetServer
    Hostname or IP of the RDP target. Used to filter gpresult output and check for
    specific TERMSRV SPN entries.

.NOTES
    Created: 2026-05-29
    Category: System-Maintenance
    Context: RMM shell (SYSTEM, PS 5.1, RMM RMM shell)

.KEYWORDS
    RDP, mstsc, saved credentials, Remember me, NTLM, CredentialsDelegation,
    AllowSavedCredentialsWhenNTLMOnly, DisablePasswordSaving, Win11
#>
#!ps
#maxlength=100000
#timeout=120000
#Requires -Version 5.1

param(
    [string]$TargetServer = ''
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("===== {0} =====" -f $t) }
function W   { param($t) Write-Output $t }

function Read-PolicyKey {
    param([string]$Path, [string]$Label)
    W ("=== {0}" -f $Label)
    W ("    {0}" -f $Path)
    if (Test-Path $Path) {
        $props = Get-ItemProperty $Path
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { W ("  {0,-50} = {1}" -f $_.Name, $_.Value) }
        } else { W "  (key exists but no values)" }
        $subs = Get-ChildItem $Path
        foreach ($sub in $subs) {
            W ("  --- subkey: {0} ---" -f $sub.PSChildName)
            Get-ItemProperty $sub.PSPath | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object { W ("    {0,-30} = {1}" -f $_.Name, $_.Value) }
            }
        }
    } else { W "  (key not present)" }
}

W "Get-RdpCredDelegationState"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($TargetServer) { W ("TargetServer: {0}" -f $TargetServer) }
W ""

$tsPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$cdPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'

Read-PolicyKey -Path $tsPath -Label 'Terminal Services policy (DisablePasswordSaving etc.)'
Write-Output ""
Read-PolicyKey -Path $cdPath -Label 'CredentialsDelegation policy'

Sec "SYSTEM CREDENTIAL STORE (TERMSRV entries)"
$creds = & cmdkey /list 2>&1 | Select-String -Pattern 'TERMSRV'
if ($creds) { $creds | ForEach-Object { W ("  {0}" -f $_.Line.Trim()) } }
else { W "  No TERMSRV entries in SYSTEM credential store (expected - user hive not visible from SYSTEM)." }
if ($TargetServer) {
    $specific = & cmdkey /list 2>&1 | Select-String -Pattern $TargetServer
    if ($specific) { $specific | ForEach-Object { W ("  Match: {0}" -f $_.Line.Trim()) } }
}

Sec "GPRESULT - TERMINAL SERVICES / CREDENTIALS DELEGATION (computer scope)"
$tmp = Join-Path $env:TEMP "rdpcred-gpresult.html"
& gpresult /h $tmp /scope computer /f 2>&1 | Out-Null
if (Test-Path $tmp) {
    $html    = Get-Content $tmp -Raw
    $pattern = '(?i)(Terminal Services|CredentialsDelegation|DisablePasswordSaving|AllowSavedCredentials).{0,400}'
    $matches  = [regex]::Matches($html, $pattern)
    if ($matches.Count -gt 0) {
        foreach ($m in $matches) {
            $clean = ($m.Value -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim()
            W ("  ..." + $clean.Substring(0, [Math]::Min(250, $clean.Length)))
        }
    } else { W "  No Terminal Services / CredentialsDelegation policy strings in RSoP." }
    Remove-Item $tmp -Force
} else { W "  gpresult HTML not generated." }

Sec "DIAGNOSIS"
$disableSave = (Get-ItemProperty $tsPath -Name 'DisablePasswordSaving').DisablePasswordSaving
$allowNTLM   = (Get-ItemProperty $cdPath -Name 'AllowSavedCredentialsWhenNTLMOnly').AllowSavedCredentialsWhenNTLMOnly

if ($disableSave -eq 1) {
    W "DisablePasswordSaving = 1."
    W "The 'Remember me' checkbox is blocked globally by GPO."
    W "Identify the source GPO (see gpresult above). Scope it out for this PC or add a per-SPN exception."
} elseif ($allowNTLM -ne 1) {
    W "DisablePasswordSaving is not 1. The 'Remember me' UI should appear."
    W "Most likely cause: no AllowSavedCredentialsWhenNTLMOnly policy."
    W "Win11 default refuses to delegate saved credentials to NTLM-only targets."
    if ($TargetServer) {
        W ("Fix: Run Set-RdpCredDelegationNtlmOnly.ps1 with -TargetSPN 'TERMSRV/{0}'" -f $TargetServer)
    } else {
        W "Fix: Run Set-RdpCredDelegationNtlmOnly.ps1 with -TargetSPN 'TERMSRV/<server>'"
    }
} else {
    W "AllowSavedCredentialsWhenNTLMOnly = 1 and DisablePasswordSaving is not 1."
    W "Policy gates appear open. Check cmdkey /list as the affected user for existing TERMSRV/* entries."
}

W ""
W "===== END Get-RdpCredDelegationState ====="
