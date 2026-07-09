<#
.SYNOPSIS
    Read all four RDS idle-timeout precedence layers plus RDGW CAP timeouts. Identifies
    the effective disconnect source.

.DESCRIPTION
    RDS idle disconnects have four policy layers, evaluated in precedence order:
      1. Computer GPO  - HKLM\SOFTWARE\Policies\...\Terminal Services (highest)
      2. User GPO      - HKU\<SID>\Software\Policies\...\Terminal Services
      3. Local WinStation - HKLM\SYSTEM\...\WinStations\RDP-Tcp
      4. AD user Sessions tab (IADsTSUserEx attributes)  (lowest, rarely set)

    Additionally, RDGW Connection Authorization Policy (CAP) IdleTimeout overrides
    all of the above from the gateway side. Zero means unlimited in all cases.

    Separately, server-side RDP keep-alive state (KeepAliveEnable / KeepAliveInterval)
    is reported because NAT/firewall TCP-idle-reaping can mimic a policy disconnect.

    Also pulls RDS Collection configuration via the RemoteDesktop module if available.
    Read-only. No writes.

.PARAMETER UserName
    SamAccountName of the user to check User GPO layer. If empty, attempts to
    auto-detect from logged-on sessions.

.NOTES
    Created: 2026-05-29
    Category: Diagnostics
    Context: RMM shell (SYSTEM, PS 5.1 on Session Host)

.KEYWORDS
    RDS, RDP, idle timeout, disconnect, MaxIdleTime, KeepAlive, CAP, RDGW,
    WinStation, GPO, session timeout
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$UserName = ''
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec { param($t) Write-Output ""; Write-Output ("==== {0} ====" -f $t) }
function W   { param($t) Write-Output $t }
function Fmt-Timeout {
    param($ms)
    if ($null -eq $ms) { return '(not set)' }
    if ($ms -eq 0)     { return '0 (unlimited)' }
    "{0} ms ({1:N1} min)" -f $ms, ($ms / 60000)
}
function Read-TSKey {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try { Get-ItemProperty $Path } catch { $null }
}

W "Get-RDSIdleTimeoutLayers"
W ("Host {0}   Generated {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# --- Host ---
Sec "HOST"
W ("Computer : {0}" -f $env:COMPUTERNAME)
W ("OS       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Caption)

# --- Active sessions ---
Sec "ACTIVE SESSIONS (quser)"
try { & quser 2>&1 | ForEach-Object { W $_ } } catch { W "quser unavailable" }

# --- Layer 1: Computer GPO ---
Sec "LAYER 1: COMPUTER GPO (HKLM Policies) -- HIGHEST PRECEDENCE"
$pcGpo = Read-TSKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
W ("MaxIdleTime          : {0}" -f (Fmt-Timeout $pcGpo.MaxIdleTime))
W ("MaxConnectionTime    : {0}" -f (Fmt-Timeout $pcGpo.MaxConnectionTime))
W ("MaxDisconnectionTime : {0}" -f (Fmt-Timeout $pcGpo.MaxDisconnectionTime))
W ("fResetBroken         : {0}" -f $(if ($null -eq $pcGpo.fResetBroken) { '(not set)' } else { $pcGpo.fResetBroken }))
W ("KeepAliveEnable      : {0}" -f $(if ($null -eq $pcGpo.KeepAliveEnable) { '(not set - keep-alive DISABLED)' } else { $pcGpo.KeepAliveEnable }))
W ("KeepAliveInterval    : {0}" -f $(if ($null -eq $pcGpo.KeepAliveInterval) { '(not set)' } else { "$($pcGpo.KeepAliveInterval) min" }))

# --- Layer 2: User GPO ---
Sec "LAYER 2: USER GPO (only if Computer GPO not set)"
$resolvedUser = $UserName
if (-not $resolvedUser) {
    $resolvedUser = Get-CimInstance Win32_LoggedOnUser |
        ForEach-Object { ($_.Antecedent -replace '.*Name="([^"]+)".*', '$1') } |
        Where-Object { $_ -match '\w' } | Select-Object -First 1
}
$userGpo = $null
if ($resolvedUser) {
    W ("User candidate: {0}" -f $resolvedUser)
    try {
        $sid     = (New-Object System.Security.Principal.NTAccount($resolvedUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $userGpo = Read-TSKey "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows NT\Terminal Services"
        W ("MaxIdleTime          : {0}" -f (Fmt-Timeout $userGpo.MaxIdleTime))
        W ("MaxConnectionTime    : {0}" -f (Fmt-Timeout $userGpo.MaxConnectionTime))
        W ("MaxDisconnectionTime : {0}" -f (Fmt-Timeout $userGpo.MaxDisconnectionTime))
    } catch {
        W ("Could not resolve SID for {0}: {1}" -f $resolvedUser, $_.Exception.Message)
    }
} else {
    W "No candidate user resolved from active sessions."
}

# --- Layer 3: Local WinStation ---
Sec "LAYER 3: LOCAL WINSTATION (RDP-Tcp)"
$ws = Read-TSKey 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
W ("MaxIdleTime              : {0}" -f (Fmt-Timeout $ws.MaxIdleTime))
W ("MaxConnectionTime        : {0}" -f (Fmt-Timeout $ws.MaxConnectionTime))
W ("MaxDisconnectionTime     : {0}" -f (Fmt-Timeout $ws.MaxDisconnectionTime))
W ("fInheritMaxIdleTime      : {0}" -f $ws.fInheritMaxIdleTime)
W ("fInheritMaxSessionTime   : {0}" -f $ws.fInheritMaxSessionTime)
W ("fInheritMaxDisconnection : {0}" -f $ws.fInheritMaxDisconnectionTime)

# --- RDS Collection ---
Sec "RDS COLLECTION (Connection Broker)"
try {
    Import-Module RemoteDesktop -ErrorAction Stop
    $cb = (Get-RDServer -Role RDS-CONNECTION-BROKER | Select-Object -First 1).Server
    if (-not $cb) { $cb = $env:COMPUTERNAME }
    Get-RDSessionCollection -ConnectionBroker $cb | ForEach-Object {
        $cfg = Get-RDSessionCollectionConfiguration -ConnectionBroker $cb -CollectionName $_.CollectionName
        W ("Collection : {0}" -f $_.CollectionName)
        if ($cfg) {
            W ("  IdleSessionLimitMin          : {0}" -f $cfg.IdleSessionLimitMin)
            W ("  ActiveSessionLimitMin        : {0}" -f $cfg.ActiveSessionLimitMin)
            W ("  DisconnectedSessionLimitMin  : {0}" -f $cfg.DisconnectedSessionLimitMin)
            W ("  BrokenConnectionAction       : {0}" -f $cfg.BrokenConnectionAction)
        }
    }
} catch { W ("RemoteDesktop module unavailable or not a Session Host with broker: {0}" -f $_.Exception.Message) }

# --- RDGW CAP (if running on the gateway) ---
Sec "RDGW CONNECTION AUTHORIZATION POLICY (CAP)"
$gwSvc = Get-Service TSGateway
if ($gwSvc -and $gwSvc.Status -eq 'Running') {
    try {
        Import-Module RemoteDesktopServices -ErrorAction Stop
        $caps = Get-ChildItem 'RDS:\GatewayServer\CAP'
        foreach ($cap in $caps) {
            $base = "RDS:\GatewayServer\CAP\$($cap.Name)"
            $idle    = (Get-Item "$base\IdleTimeout").CurrentValue
            $session = (Get-Item "$base\SessionTimeout").CurrentValue
            W ("CAP: {0}   IdleTimeout: {1} min   SessionTimeout: {2} min" -f $cap.Name, $idle, $session)
            if ([int]$idle -gt 0) { W ("  >> IdleTimeout = {0} min - this overrides Session Host layer for gateway connections" -f $idle) }
        }
    } catch { W ("CAP query failed: {0}" -f $_.Exception.Message) }
} else {
    W "TSGateway service not running on this host. Run on the RDGW host to check CAP timeouts."
}

# --- Effective summary ---
Sec "EFFECTIVE SUMMARY"
$effective = $null
if ($null -ne $pcGpo.MaxIdleTime -and $pcGpo.MaxIdleTime -ne 0) {
    $effective = @{ Source='Computer GPO'; Value=$pcGpo.MaxIdleTime }
} elseif ($userGpo -and $null -ne $userGpo.MaxIdleTime -and $userGpo.MaxIdleTime -ne 0) {
    $effective = @{ Source='User GPO'; Value=$userGpo.MaxIdleTime }
} elseif ($null -ne $ws.MaxIdleTime -and $ws.MaxIdleTime -ne 0) {
    $effective = @{ Source='WinStation'; Value=$ws.MaxIdleTime }
}

if ($effective) {
    W ("Idle disconnect in effect from {0}: {1}" -f $effective.Source, (Fmt-Timeout $effective.Value))
} else {
    W "No idle-disconnect timeout at OS/GPO/WinStation layer (all unlimited)."
    W "If user still disconnects, cause is likely:"
    W "  - RDGW CAP IdleTimeout (check gateway host)"
    W "  - NAT/firewall TCP idle reaping (fix: Set-RDPKeepAlive.ps1)"
    W "  - AD user Sessions tab attribute (check via ADUC > Sessions tab)"
}

if (-not $pcGpo.KeepAliveEnable -or $pcGpo.KeepAliveEnable -eq 0) {
    W ""
    W ">> Server-side RDP keep-alive is DISABLED. Enable with Set-RDPKeepAlive.ps1"
    W "   if NAT/firewall idle-reaping is suspected."
}

W ""
W "===== END Get-RDSIdleTimeoutLayers ====="
