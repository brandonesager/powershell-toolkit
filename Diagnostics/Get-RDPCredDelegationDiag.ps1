#!ps
#maxlength=30000
#timeout=90000

<#
.SYNOPSIS
    Read-only diagnostic for RDP saved-credentials and credential-delegation policy.
.DESCRIPTION
    Checks the two Group Policy paths that block mstsc "Remember me" from persisting:
    Terminal Services DisablePasswordSaving and CredentialsDelegation NTLM allowances.
    Also runs gpresult scoped to computer and filters for TS/CredDelegation entries.
    Optionally filters the cmdkey list to a specific TERMSRV target.
    Run via RMM RMM shell (SYSTEM); read-only.
.PARAMETER TargetHost
    Optional. Hostname or IP of the RDP target to filter in the cmdkey list and
    the Recommendation section's TERMSRV SPN. Default is empty (show all TERMSRV entries).
.NOTES
    Category: Diagnostics
    PS 5.1 compatible.
    Context: RMM RMM shell (SYSTEM), read-only.
.KEYWORDS
    RDP, mstsc, credential delegation, DisablePasswordSaving, CredentialsDelegation, saved credentials
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetHost = ''
)

function Read-PolicyKey {
    param([string]$Path, [string]$Label)
    Write-Output "=== $Label ($Path) ==="
    if (Test-Path $Path) {
        $props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { Write-Output ("  {0,-50} = {1}" -f $_.Name, $_.Value) }
        } else { Write-Output "  (key exists but no values)" }
        $subs = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        if ($subs) {
            foreach ($sub in $subs) {
                Write-Output ""
                Write-Output "  --- subkey: $($sub.PSChildName) ---"
                Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $_.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS' } |
                            ForEach-Object { Write-Output ("    {0,-30} = {1}" -f $_.Name, $_.Value) }
                    }
            }
        }
    } else {
        Write-Output "  (key not present)"
    }
    Write-Output ""
}

Read-PolicyKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
               -Label 'TS - DisablePasswordSaving etc.'
Read-PolicyKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
               -Label 'CredentialsDelegation'
Read-PolicyKey -Path 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client' `
               -Label 'HKCU TS Client (SYSTEM hive — user hive will differ)'

$termsrvPattern = if ($TargetHost) { "TERMSRV|$([regex]::Escape($TargetHost))" } else { 'TERMSRV' }
Write-Output "=== Saved TERMSRV credentials visible in SYSTEM hive ==="
cmdkey /list 2>&1 | Select-String -Pattern $termsrvPattern
Write-Output ""

Write-Output "=== gpresult /scope computer — filtered for Terminal Services / Credentials Delegation ==="
$tmp = Join-Path $env:TEMP "rdp-creddelegation-gpresult.html"
& gpresult /h $tmp /scope computer /f 2>&1 | Out-Null
if (Test-Path $tmp) {
    $html = Get-Content $tmp -Raw
    $rdpMatches = [regex]::Matches($html,
        '(?i)(Terminal Services|CredentialsDelegation|DisablePasswordSaving|AllowSavedCredentials).{0,400}')
    foreach ($m in $rdpMatches) {
        $clean = ($m.Value -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim()
        Write-Output ("  ..." + $clean.Substring(0, [Math]::Min(300, $clean.Length)))
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
} else {
    Write-Output "  (gpresult could not generate HTML report)"
}
Write-Output ""

Write-Output "=== Recommendation ==="
$tsPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$cdPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
$disableSave = (Get-ItemProperty -Path $tsPath -Name 'DisablePasswordSaving' -ErrorAction SilentlyContinue).DisablePasswordSaving
$allowNTLM   = (Get-ItemProperty -Path $cdPath -Name 'AllowSavedCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue).AllowSavedCredentialsWhenNTLMOnly
$spnNote     = if ($TargetHost) { "TERMSRV/$TargetHost" } else { "TERMSRV/<target>" }

if ($disableSave -eq 1) {
    Write-Output "  DisablePasswordSaving=1 is set. mstsc credential save is blocked globally."
    Write-Output "  Identify the GPO source in the gpresult output above. Either scope it out"
    Write-Output "  for this machine or add a per-target NTLM exception via CredentialsDelegation."
} elseif ($disableSave -ne 1 -and -not $allowNTLM) {
    Write-Output "  DisablePasswordSaving is not 1. The save UI should work."
    Write-Output "  Most likely cause: NTLM delegation policy is not configured."
    Write-Output "  Fix: enable CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly=1"
    Write-Output "  and add $spnNote to the SPN list."
} else {
    Write-Output "  Both gates appear open. Verify cmdkey /list as the affected user (user hive) and re-test."
}

Write-Output ""
Write-Output "=== Done ==="
