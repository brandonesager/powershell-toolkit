<#
.SYNOPSIS
    Workstation access investigation recon — Security log, RDP, VPN, ScreenConnect sessions.

.DESCRIPTION
    Collects evidence for unauthorized access investigations. Covers:
    - Security log status and retention window
    - Logon events 4624/4625/4672/4778/4779 (filtered to human accounts)
    - Terminal Services RDP events (LocalSessionManager 21/23/24/25, RemoteConnectionManager 1149)
    - VPN connection events (RASClient, SonicWall NetExtender.dbg)
    - ScreenConnect client Application log events
    - Audit policy state (Object Access, Logon/Logoff)
    - Drive mapping registry check (per all domain user profiles)
    - Object Access file events (4663) if auditing is enabled

    Run via Commands Tab (PS 5.1, SYSTEM context). Set $StartDate and $EndDate to the
    incident window before running.

.NOTES
    Context:    RMM Commands Tab (SYSTEM context, PS 5.1)
    Category:   Diagnostics
    Use case:   Security incident investigation, unauthorized access review

.SOURCE
    Date: 2026-03-06
#>

#!ps
#maxlength=100000
#timeout=300000

# == Configuration ==
# Set incident window before running
$StartDate = Get-Date -Date '2026-01-01 00:00:00'   # adjust to incident window start
$EndDate   = Get-Date -Date '2026-12-31 23:59:59'   # adjust to incident window end

Write-Output "============================================"
Write-Output "  Workstation Access Recon: $env:COMPUTERNAME"
Write-Output "  Window: $($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd'))"
Write-Output "  Run time: $(Get-Date)"
Write-Output "============================================"

# -- Security Log Status --
Write-Output "`n=== SECURITY LOG STATUS ==="
$secLog = Get-WinEvent -ListLog Security
Write-Output "Max size:     $([math]::Round($secLog.MaximumSizeInBytes / 1MB, 1)) MB"
Write-Output "Current size: $([math]::Round($secLog.FileSize / 1MB, 1)) MB"
Write-Output "Record count: $($secLog.RecordCount)"
Write-Output "Log mode:     $($secLog.LogMode)"
$oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
$newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
if ($oldest) { Write-Output "Oldest event: $($oldest.TimeCreated) (ID $($oldest.Id))" }
if ($newest) { Write-Output "Newest event: $($newest.TimeCreated) (ID $($newest.Id))" }

Write-Output "`n--- Event 1102: Log Cleared ---"
try {
    $cleared = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction Stop
    foreach ($e in $cleared) { Write-Output "  $($e.TimeCreated) | $($e.Message.Substring(0,[Math]::Min(200,$e.Message.Length)))" }
} catch { Write-Output "  No log-cleared events found (normal wrap)" }

# -- Audit Policy --
Write-Output "`n=== AUDIT POLICY ==="
Write-Output "--- Logon/Logoff ---"
auditpol /get /category:"Logon/Logoff" 2>&1
Write-Output "`n--- Object Access ---"
auditpol /get /category:"Object Access" 2>&1
Write-Output "`n--- Account Logon ---"
auditpol /get /category:"Account Logon" 2>&1

# -- Drive Mappings (all domain profiles) --
Write-Output "`n=== DRIVE MAPPINGS (all user profiles) ==="
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.SID -match '^S-1-5-21-' }
foreach ($p in $profiles) {
    $sid = $p.SID
    $username = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
    $netKey = "Registry::HKU\$sid\Network"
    if (Test-Path $netKey) {
        Get-ChildItem $netKey | ForEach-Object {
            $letter = $_.PSChildName
            $path   = (Get-ItemProperty $_.PSPath).RemotePath
            Write-Output "  $username : ${letter}: -> $path"
        }
    } else {
        Write-Output "  $username : No mapped drives in registry"
    }
}

# -- Local Accounts --
Write-Output "`n=== LOCAL ACCOUNTS ==="
Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name, Disabled, PasswordRequired, SID | Format-Table -AutoSize
Write-Output "--- Local Administrators ---"
net localgroup Administrators 2>&1

# -- Security Log: Logon Events --
Write-Output "`n=== SECURITY LOG: LOGON EVENTS ==="
Write-Output "--- Event 4624: Successful Logons ---"
try {
    $logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    $parsed = foreach ($e in $logons) {
        $xml = [xml]$e.ToXml()
        $data = $xml.Event.EventData.Data
        $logonType     = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $targetUser    = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $targetDomain  = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        $sourceIP      = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $logonProcess  = ($data | Where-Object { $_.Name -eq 'LogonProcessName' }).'#text'
        if ($targetUser -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-|ANONYMOUS LOGON)' -and
            $targetDomain -ne 'Window Manager' -and $targetDomain -ne 'Font Driver Host') {
            [PSCustomObject]@{
                Time      = $e.TimeCreated.ToString('MM/dd HH:mm:ss')
                Type      = $logonType
                User      = "$targetDomain\$targetUser"
                SourceIP  = $sourceIP
                Process   = ($logonProcess -replace '\s+$','')
            }
        }
    }
    if ($parsed) {
        $parsed | Sort-Object Time | Format-Table -AutoSize
        Write-Output "Logon Type Key: 2=Interactive, 3=Network, 7=Unlock, 10=RDP, 11=CachedInteractive"
    } else { Write-Output "No non-system logon events in window" }
} catch { Write-Output "Error or no events: $_" }

Write-Output "`n--- Event 4625: Failed Logons ---"
try {
    $failed = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    foreach ($e in $failed) {
        $xml = [xml]$e.ToXml(); $data = $xml.Event.EventData.Data
        $targetUser = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $sourceIP   = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $status     = ($data | Where-Object { $_.Name -eq 'Status' }).'#text'
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | User: $targetUser | IP: $sourceIP | Status: $status"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No failed logon events in window" }
    else { Write-Output "Error: $_" }
}

Write-Output "`n--- Event 4672: Special Privileges Assigned ---"
try {
    $privs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    $privUsers = foreach ($e in $privs) {
        $xml = [xml]$e.ToXml(); $data = $xml.Event.EventData.Data
        $subjectUser   = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $subjectDomain = ($data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
        if ($subjectUser -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
            [PSCustomObject]@{ Time = $e.TimeCreated.ToString('MM/dd HH:mm:ss'); User = "$subjectDomain\$subjectUser" }
        }
    }
    if ($privUsers) { $privUsers | Sort-Object Time | Format-Table -AutoSize }
    else { Write-Output "  No non-system privilege assignments in window" }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No events in window" }
    else { Write-Output "Error: $_" }
}

Write-Output "`n--- Events 4778/4779: Session Reconnect/Disconnect ---"
try {
    $sessions = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4778,4779; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    foreach ($e in $sessions) {
        $xml = [xml]$e.ToXml(); $data = $xml.Event.EventData.Data
        $acctName   = ($data | Where-Object { $_.Name -eq 'AccountName' }).'#text'
        $clientName = ($data | Where-Object { $_.Name -eq 'ClientName' }).'#text'
        $clientAddr = ($data | Where-Object { $_.Name -eq 'ClientAddress' }).'#text'
        $action = if ($e.Id -eq 4778) { 'Reconnect' } else { 'Disconnect' }
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | $action | User: $acctName | Client: $clientName ($clientAddr)"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No session reconnect/disconnect events in window" }
    else { Write-Output "Error: $_" }
}

# -- RDP / Terminal Services --
Write-Output "`n=== TERMINAL SERVICES: RDP SESSIONS ==="
Write-Output "--- LocalSessionManager: Events 21,23,24,25 ---"
try {
    $tsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,23,24,25; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    foreach ($e in $tsEvents) {
        $xml  = [xml]$e.ToXml()
        $user = ($xml.Event.UserData.EventXML.User)
        $addr = ($xml.Event.UserData.EventXML.Address)
        $desc = switch ($e.Id) { 21 {'Logon'} 23 {'Logoff'} 24 {'Disconnect'} 25 {'Reconnect'} }
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | Event $($e.Id) ($desc) | User: $user | Source: $addr"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No RDP session events in window" }
    else { Write-Output "Error: $_" }
}

Write-Output "`n--- RemoteConnectionManager: Event 1149 (Auth Succeeded) ---"
try {
    $rcm = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    foreach ($e in $rcm) {
        $xml    = [xml]$e.ToXml()
        $user   = ($xml.Event.UserData.EventXML.Param1)
        $domain = ($xml.Event.UserData.EventXML.Param2)
        $addr   = ($xml.Event.UserData.EventXML.Param3)
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | $domain\$user from $addr"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No RDP auth events in window" }
    else { Write-Output "Error: $_" }
}

# -- VPN / Remote Access --
Write-Output "`n=== VPN / REMOTE ACCESS ==="
Write-Output "--- RASClient Events (Application Log) ---"
try {
    $ras = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='RasClient'; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop
    foreach ($e in $ras) {
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | ID $($e.Id) | $($e.Message.Substring(0,[Math]::Min(200,$e.Message.Length)))"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No RASClient events in window" }
    else { Write-Output "Error: $_" }
}

Write-Output "`n--- SonicWall NetExtender Log ---"
$nePaths = @(
    'C:\Program Files\SonicWALL\SSL VPN\NetExtender\NetExtender.dbg',
    'C:\Program Files (x86)\SonicWALL\SSL VPN\NetExtender\NetExtender.dbg',
    'C:\Program Files\SonicWall\SSL VPN\NetExtender\NetExtender.dbg'
)
$neFound = $false
foreach ($nePath in $nePaths) {
    if (Test-Path $nePath) {
        $neFound = $true
        Write-Output "  Found: $nePath"
        $datePattern = $StartDate.ToString('yyyy.MM.dd') + '|' + $StartDate.ToString('MM/dd/yyyy') + '|' + $StartDate.ToString('yyyy-MM-dd')
        $neLines = Get-Content $nePath -Tail 500 | Where-Object { $_ -match $datePattern }
        if ($neLines) { $neLines | Select-Object -First 50 | ForEach-Object { Write-Output "  $_" } }
        else { Write-Output "  No entries matching date pattern found" }
        break
    }
}
if (-not $neFound) { Write-Output "  NetExtender.dbg not found (NetExtender may not be installed)" }

# -- ScreenConnect Session Events --
Write-Output "`n=== SCREENCONNECT SESSION EVENTS ==="
try {
    $scEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction Stop |
        Where-Object { $_.ProviderName -match 'ScreenConnect' }
    if ($scEvents) {
        foreach ($e in $scEvents) {
            Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | $($e.ProviderName) | ID $($e.Id) | $($e.Message.Substring(0,[Math]::Min(200,$e.Message.Length)))"
        }
        Write-Output "NOTE: ScreenConnect admin console session history goes back months — use it for windows outside Application log retention."
    } else {
        Write-Output "  No ScreenConnect events in Application log for this window"
        Write-Output "  Check ScreenConnect admin console Audit tab for long-term session history."
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No Application log events in window (unexpected)" }
    else { Write-Output "Error: $_" }
}

# -- File Access Events (if Object Access auditing is enabled) --
Write-Output "`n=== FILE ACCESS AUDIT EVENTS (4663) ==="
try {
    $fileAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$StartDate; EndTime=$EndDate} -MaxEvents 50 -ErrorAction Stop
    Write-Output "Found $($fileAccess.Count)+ object access events. Showing first 20:"
    foreach ($e in ($fileAccess | Select-Object -First 20)) {
        $xml  = [xml]$e.ToXml(); $data = $xml.Event.EventData.Data
        $subjectUser = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $objName     = ($data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'
        $accessMask  = ($data | Where-Object { $_.Name -eq 'AccessMask' }).'#text'
        Write-Output "  $($e.TimeCreated.ToString('MM/dd HH:mm:ss')) | User: $subjectUser | Object: $objName | Access: $accessMask"
    }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') { Write-Output "  No file access audit events — Object Access auditing is not enabled on this endpoint" }
    else { Write-Output "Error: $_" }
}

Write-Output "`n=== RECON COMPLETE ==="
Write-Output "Review notes:"
Write-Output "  - Security log oldest event determines how far back logon evidence reaches"
Write-Output "  - Object Access auditing must be enabled to get file-level events (4663)"
Write-Output "  - For network share file access, investigate the file server Security log"
Write-Output "  - ScreenConnect admin console Audit tab provides months of remote session history"
