<#
.SYNOPSIS
    Idempotent: set Egnyte Connect HKCU Run key and ZoneMap trusted-site entries for a Contoso user.

.DESCRIPTION
    Fixes recurring Egnyte Z: drive disconnection at reboot caused by missing autorun entry
    and incomplete trusted-site configuration. Targets the Contoso tenant domain (contoso.egnyte.com).

    Operations:
    1. Verify Egnyte is installed at the expected path.
    2. Set HKCU Run key value "Egnyte Connect" with --auto-login argument.
       Cleans up legacy "EgnyteClient" value name if present from prior fix scripts.
    3. For each entry in RequiredTrustedSites: write Zone=2 (Trusted) under both
       Domains and EscDomains in HKCU ZoneMap (idempotent).
    4. Detect HKLM policy overrides that would revert user zone settings.
    5. Flush DNS cache and test TCP/443 to contoso.egnyte.com.
    6. Print before/after state for both Run key and ZoneMap.

    Correct values for Contoso (confirmed from registry):
    - Tenant domain: contoso.egnyte.com
    - Autorun name: "Egnyte Connect" (NOT "EgnyteClient")
    - Autorun args: --auto-login (NOT --auto-silent)

    Run via RMM RMM shell or SYSTEM remote session in the logged-in user's context
    (HKU\{SID} targets require knowing the SID, or run as the user via user session).

.PARAMETER TenantDomain
    Egnyte tenant domain. Defaults to contoso.egnyte.com.

.PARAMETER UserSid
    SID of the target user. If empty, the script targets HKCU (current user).
    Required when running as SYSTEM via RMM shell.

.PARAMETER SkipZoneMap
    Switch. Skip ZoneMap trusted-site changes. Use when only the autorun fix is needed.

.EXAMPLE
    # From user session (SYSTEM remote session):
    .\Set-EgnyteAutorunAndTrustedSites.ps1

    # From RMM shell (SYSTEM context), targeting a specific user:
    .\Set-EgnyteAutorunAndTrustedSites.ps1 -UserSid 'S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxx-xxxx'

.NOTES
    Category: Environment-Specific/Contoso
    Context: User session or Commands/SYSTEM (with -UserSid)

    Known Contoso fact: *.egnyte.com (https=2) is typically present in Domains from the
    original Egnyte setup script. EscDomains and EgnyteDrive entries are often missing.

.KEYWORDS
    Egnyte, autorun, HKCU Run, ZoneMap, trusted sites, contoso.egnyte.com, Z drive, Contoso
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TenantDomain = 'contoso.egnyte.com',
    [string]$UserSid      = '',
    [switch]$SkipZoneMap
)

$ErrorActionPreference = 'Stop'
$exePath      = 'C:\Program Files (x86)\Egnyte Connect\EgnyteClient.exe'
$autorunName  = 'Egnyte Connect'
$autorunData  = "`"$exePath`" --auto-login"

# Resolve registry base: HKU\{SID} if SYSTEM running with a SID param, else HKCU
if ($UserSid) {
    $runKey = "Registry::HKU\$UserSid\Software\Microsoft\Windows\CurrentVersion\Run"
    $zmBase = "Registry::HKU\$UserSid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
} else {
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $zmBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
}

# Standard trusted site entries for Egnyte
$requiredSites = @(
    @{ Domain = 'egnyte.com';              Protocol = 'https'; Zone = 2 },
    @{ Domain = 'EgnyteDrive';             Protocol = 'file';  Zone = 2 },
    @{ Domain = 'login.microsoftonline.com'; Protocol = 'https'; Zone = 2 }
)

function Write-ZoneMapState {
    param([string]$Base)
    foreach ($sub in @('Domains', 'EscDomains')) {
        $sp = "$Base\$sub"
        Write-Output "  ${sub}:"
        if (Test-Path $sp) {
            Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    Write-Output "    $($_.Name) = $($_.Value)"
                }
            }
        } else { Write-Output '    (key missing)' }
    }
}

Write-Output "=== Egnyte Fix: Autorun + Trusted Sites ==="
Write-Output "Machine   : $env:COMPUTERNAME"
Write-Output "Time      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Domain    : $TenantDomain"
if ($UserSid) { Write-Output "SID       : $UserSid" }

# Verify Egnyte installed
if (-not (Test-Path $exePath)) {
    Write-Output "ERROR: Egnyte not found at $exePath"
    exit 1
}

Write-Output "`n--- BEFORE ---"
Write-Output "Run key ($runKey):"
if (Test-Path $runKey) {
    (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
} else { Write-Output "  MISSING" }
Write-Output "ZoneMap:"
Write-ZoneMapState -Base $zmBase

# Autorun
Write-Output "`n--- Applying Autorun ---"
if ($PSCmdlet.ShouldProcess($runKey, "Set '$autorunName'")) {
    if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null; Write-Output "Run key: CREATED" }
    Set-ItemProperty -Path $runKey -Name $autorunName -Value $autorunData -Type String
    $verify = (Get-ItemProperty $runKey -Name $autorunName -ErrorAction Stop).$autorunName
    if ($verify -eq $autorunData) {
        Write-Output "Autorun '$autorunName': SET and VERIFIED"
    } else {
        Write-Output "ERROR: verification mismatch. Expected: $autorunData  Got: $verify"
        exit 1
    }
    # Clean up legacy entry
    try {
        Remove-ItemProperty -Path $runKey -Name 'EgnyteClient' -ErrorAction Stop
        Write-Output "Cleaned legacy 'EgnyteClient' Run entry."
    } catch {}
}

# Trusted sites
if (-not $SkipZoneMap) {
    Write-Output "`n--- Applying Trusted Sites ---"
    foreach ($ts in $requiredSites) {
        foreach ($sub in @('Domains', 'EscDomains')) {
            $kp = "$zmBase\$sub\$($ts.Domain)"
            if ($PSCmdlet.ShouldProcess($kp, "Set Zone=$($ts.Zone) for $($ts.Protocol)")) {
                if (-not (Test-Path $kp)) { New-Item -Path $kp -Force | Out-Null }
                Set-ItemProperty -Path $kp -Name $ts.Protocol -Value $ts.Zone -Type DWord
                $check = (Get-ItemProperty $kp -Name $ts.Protocol -ErrorAction Stop).$($ts.Protocol)
                Write-Output "SET: $sub\$($ts.Domain)\$($ts.Protocol) = $check"
            }
        }
    }
}

# Policy override check
Write-Output "`n--- Policy Check ---"
$gpPaths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'
)
$gpFound = $false
foreach ($gp in $gpPaths) {
    if (Test-Path $gp) {
        Write-Output "WARNING: Policy at $gp may override user zone settings."
        $gpFound = $true
    }
}
if (-not $gpFound) { Write-Output "No policy overrides detected." }

# AFTER state
Write-Output "`n--- AFTER ---"
Write-Output "Run key:"
(Get-ItemProperty $runKey -ErrorAction SilentlyContinue).PSObject.Properties |
    Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
Write-Output "ZoneMap:"
Write-ZoneMapState -Base $zmBase

# Connectivity
Write-Output "`n--- Connectivity ---"
Clear-DnsClientCache -ErrorAction SilentlyContinue
Write-Output "DNS cache flushed."
try {
    $dns = Resolve-DnsName $TenantDomain -ErrorAction Stop
    $ips = @($dns | Where-Object { $_.Type -eq 1 }) | ForEach-Object { $_.IPAddress }
    Write-Output "DNS: $TenantDomain -> $($ips -join ', ')"
} catch { Write-Output "DNS: FAILED -- $($_.Exception.Message)" }
$tcp = Test-NetConnection -ComputerName $TenantDomain -Port 443 -WarningAction SilentlyContinue
Write-Output "TCP/443: IP=$($tcp.RemoteAddress) Success=$($tcp.TcpTestSucceeded)"

Write-Output "`n=== Fix Complete ==="
Write-Output "Next: restart Egnyte Connect in the user's interactive session to mount Z:."
