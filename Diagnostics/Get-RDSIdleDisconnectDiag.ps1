<#
.SYNOPSIS
    Diagnoses RDS idle-disconnect configuration on an RDS Session Host.

.DESCRIPTION
    Read-only. Reports every layer that can disconnect an idle or active RDS session,
    in precedence order:
      Layer 1: Computer GPO (HKLM Policies) - highest precedence
      Layer 2: Local WinStation (RDP-Tcp registry)
      Layer 3: User GPO (HKU hive for the specified user, if logged on)
      Layer 4: RDS Collection settings via the RemoteDesktop module (if available)

    Also runs gpresult /scope computer to surface session time limit policies in RSoP,
    and lists active sessions via quser.

    At the end, prints the effective idle-disconnect source and value.

.PARAMETER UserFilter
    Optional. SAM account name (or partial match) of the target user whose HKCU
    policy hive should be read. When omitted, the user-hive section is skipped.
    Example: -UserFilter "jsmith"

.NOTES
    Context:  RMM shell (SYSTEM, PS 5.1, RMM RMM shell on Session Host)
    Platform: Windows Server 2016+ with RDS Session Host role
    PS 5.1 compatible.

.KEYWORDS
    RDS, RDP, idle disconnect, MaxIdleTime, GPO, WinStation, session host, timeout, diagnostics
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$UserFilter = ''
)

$ErrorActionPreference = 'Continue'

function Show-Section($t) { Write-Output ""; Write-Output "==== $t ====" }
function Get-RegProps($path) {
    if (Test-Path $path) {
        try { Get-ItemProperty -Path $path -ErrorAction Stop } catch { $null }
    } else { $null }
}
function Format-Timeout($ms) {
    if ($null -eq $ms) { return "(not set)" }
    if ($ms -eq 0)     { return "0 (unlimited / disabled)" }
    "{0} ms ({1:N1} min)" -f $ms, ($ms / 60000)
}

Show-Section "Host"
Write-Output "Computer : $env:COMPUTERNAME"
Write-Output "Date     : $(Get-Date -Format 's')"
Write-Output "OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)"

Show-Section "Layer 1: Computer GPO (HKLM Policies)  -- HIGHEST PRECEDENCE"
$pcGpo = Get-RegProps 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
'MaxIdleTime         : ' + (Format-Timeout $pcGpo.MaxIdleTime)
'MaxConnectionTime   : ' + (Format-Timeout $pcGpo.MaxConnectionTime)
'MaxDisconnectionTime: ' + (Format-Timeout $pcGpo.MaxDisconnectionTime)
'fResetBroken (end vs disconnect): ' + $(if ($null -eq $pcGpo.fResetBroken) { '(not set)' } else { $pcGpo.fResetBroken })

Show-Section "Layer 2: Local WinStation (RDP-Tcp)"
$ws = Get-RegProps 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
'MaxIdleTime         : ' + (Format-Timeout $ws.MaxIdleTime)
'MaxConnectionTime   : ' + (Format-Timeout $ws.MaxConnectionTime)
'MaxDisconnectionTime: ' + (Format-Timeout $ws.MaxDisconnectionTime)
'fInheritMaxIdleTime : ' + $ws.fInheritMaxIdleTime
'fInheritMaxSessionTime : ' + $ws.fInheritMaxSessionTime
'fInheritMaxDisconnectionTime : ' + $ws.fInheritMaxDisconnectionTime

$userGpo = $null
if ($UserFilter) {
    Show-Section "Layer 3: User GPO (filtered to '$UserFilter')"
    $matchedUser = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue |
        ForEach-Object { ($_.Antecedent -replace '.*Name="([^"]+)".*','$1') } |
        Where-Object { $_ -match [regex]::Escape($UserFilter) } | Select-Object -First 1

    if ($matchedUser) {
        Write-Output "Logged-on match: $matchedUser"
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($matchedUser)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
            $userGpo = Get-RegProps "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows NT\Terminal Services"
            'MaxIdleTime         : ' + (Format-Timeout $userGpo.MaxIdleTime)
            'MaxConnectionTime   : ' + (Format-Timeout $userGpo.MaxConnectionTime)
            'MaxDisconnectionTime: ' + (Format-Timeout $userGpo.MaxDisconnectionTime)
        } catch {
            Write-Output "Could not resolve SID for '$matchedUser': $($_.Exception.Message)"
        }
    } else {
        Write-Output "No logged-on user matching '$UserFilter' - skip user-hive read."
    }
} else {
    Show-Section "Layer 3: User GPO"
    Write-Output "(Skipped -- no -UserFilter supplied)"
}

Show-Section "RDS Collection (Connection Broker)"
try {
    Import-Module RemoteDesktop -ErrorAction Stop
    $cb = (Get-RDServer -Role RDS-CONNECTION-BROKER -ErrorAction SilentlyContinue | Select-Object -First 1).Server
    if (-not $cb) { $cb = $env:COMPUTERNAME }
    Get-RDSessionCollection -ConnectionBroker $cb -ErrorAction Stop | ForEach-Object {
        $cfg = Get-RDSessionCollectionConfiguration -ConnectionBroker $cb -CollectionName $_.CollectionName -ErrorAction SilentlyContinue
        Write-Output ("Collection: {0}" -f $_.CollectionName)
        if ($cfg) {
            "  IdleSessionLimitMin        : $($cfg.IdleSessionLimitMin)"
            "  ActiveSessionLimitMin      : $($cfg.ActiveSessionLimitMin)"
            "  DisconnectedSessionLimitMin: $($cfg.DisconnectedSessionLimitMin)"
            "  AutomaticReconnectionEnabled: $($cfg.AutomaticReconnectionEnabled)"
            "  BrokenConnectionAction     : $($cfg.BrokenConnectionAction)"
        }
    }
} catch {
    Write-Output "RemoteDesktop module unavailable or no collection on this host: $($_.Exception.Message)"
}

Show-Section "Active sessions on this host"
try { quser } catch { Write-Output "quser unavailable" }

Show-Section "Resultant Set of Policy (Computer scope, Session Time Limits)"
$rsop = "$env:TEMP\rsop_$([int][double]::Parse((Get-Date -UFormat %s))).html"
Start-Process -FilePath gpresult -ArgumentList "/scope computer /h `"$rsop`" /f" -Wait -NoNewWindow
if (Test-Path $rsop) {
    $html = Get-Content $rsop -Raw
    $matches = [regex]::Matches($html, 'Set time limit for[^<]+|MaxIdleTime|MaxConnectionTime|MaxDisconnectionTime')
    if ($matches.Count) { $matches | Select-Object -ExpandProperty Value -Unique }
    else { "No Session Time Limit policies present in computer-scope RSoP." }
    Remove-Item $rsop -Force -ErrorAction SilentlyContinue
}

Show-Section "Summary"
Write-Output "Effective idle-disconnect (precedence: Computer GPO > User GPO > WinStation):"
$effective = $null
if ($null -ne $pcGpo.MaxIdleTime)                               { $effective = @{ Source='Computer GPO'; Value=$pcGpo.MaxIdleTime } }
elseif ($userGpo -and $null -ne $userGpo.MaxIdleTime)           { $effective = @{ Source='User GPO';     Value=$userGpo.MaxIdleTime } }
elseif ($null -ne $ws.MaxIdleTime)                              { $effective = @{ Source='WinStation';   Value=$ws.MaxIdleTime } }
if ($effective) {
    "  Source: $($effective.Source)"
    "  Value : " + (Format-Timeout $effective.Value)
} else {
    "  No idle-disconnect policy in effect at OS layer."
    "  If sessions still drop, check the RDS Collection settings above or RD Gateway Connection Authorization Policy timeouts."
}
