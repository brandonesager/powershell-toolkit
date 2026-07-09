#!ps
#maxlength=100000
#timeout=300000
<#
.SYNOPSIS
    Repair-MFPScanToFolder — Check and fix all scan-to-folder prerequisites in one pass

.DESCRIPTION
    RMM shell all-in-one for Konica MFP scan-to-folder tickets. Checks local.mfp.scan
    account status, network profile, firewall rules, SMB signing, scan folder, NTFS
    permissions, and SMB share. Fixes what it can, flags what needs manual action.
    Optionally probes SMB auth with the stored password and auto-resets the local
    account on mismatch. Tails recent 4625 logon failures with sub-status decoding to
    surface Guest fall-through (MFP downgrading to anonymous SMB). Optionally pings the
    MFP and tests its web UI port. Reports hostname, IP, and password age for MFP
    address book verification. Idempotent: safe to run repeatedly.

.NOTES
    Date: 2026-04-03 (enhanced 2026-05-15 with auth probe, password reset, 4625 audit, MFP reachability)
    Category: Diagnostics
    Context: RMM shell (SYSTEM, #!ps)

.KEYWORDS
    scanner, MFP, SMB, scan-to-folder, firewall, Konica, diagnose, remediate, provision, 4625, guest, anonymous
#>

# === EDIT BEFORE PASTING (optional) ===
# Set $Password to enable SMB auth probe + auto-reset of local.mfp.scan on mismatch.
# Pull from your password manager: the local.mfp.scan account (shared across all MFPs).
# Leave empty to skip auth probe and password reset.
$Password = ''
# Set $MfpIp to ping the MFP and test its web UI port (80). Leave empty to skip.
$MfpIp = ''
# === END EDIT ===

$fixed = @()
$warn = @()
$authOk = $null
Write-Output "=== MFP SCAN-TO-FOLDER FIX ==="

Write-Output "`n[1] local.mfp.scan Account"
$acct = Get-LocalUser -Name 'local.mfp.scan' -EA SilentlyContinue
if (-not $acct) {
    $warn += "local.mfp.scan account MISSING — create manually with the stored password"
    Write-Output "  *** MISSING — cannot authenticate scan-to-folder ***"
} else {
    if (-not $acct.Enabled) {
        Enable-LocalUser -Name 'local.mfp.scan'
        $fixed += "local.mfp.scan: re-enabled"
        Write-Output "  FIXED: Account was disabled, now enabled"
    } else {
        Write-Output "  OK: Enabled"
    }
    Write-Output "  PasswordLastSet: $($acct.PasswordLastSet)"
    Write-Output "  LastLogon: $($acct.LastLogon)"
    Write-Output "  PasswordExpires: $(if ($acct.PasswordExpires) { $acct.PasswordExpires } else { '(never)' })"
    # Password expiration: detect and fix
    if ($acct.PasswordExpires) {
        if ($acct.PasswordExpires -lt (Get-Date)) {
            $warn += "local.mfp.scan password EXPIRED on $($acct.PasswordExpires) — reset with stored password"
            Write-Output "  *** EXPIRED on $($acct.PasswordExpires) — reset password from your password manager ***"
        } elseif ($acct.PasswordExpires -lt (Get-Date).AddDays(7)) {
            $warn += "local.mfp.scan password expires $($acct.PasswordExpires) — reset soon"
            Write-Output "  *** WARN: Expires $($acct.PasswordExpires) — reset password proactively ***"
        }
        Set-LocalUser -Name 'local.mfp.scan' -PasswordNeverExpires $true
        $fixed += "local.mfp.scan: set PasswordNeverExpires"
        Write-Output "  FIXED: Set PasswordNeverExpires (service account)"
    }
    # Stale logon check
    $daysSinceLogon = if ($acct.LastLogon) { [int]((Get-Date) - $acct.LastLogon).TotalDays } else { -1 }
    if ($daysSinceLogon -gt 14) {
        $warn += "local.mfp.scan last logon $daysSinceLogon days ago — possible password mismatch with MFP address book"
        Write-Output "  *** WARN: No logon in $daysSinceLogon days — verify MFP address book password matches your password manager ***"
    }
}

Write-Output "`n[1b] Recent Scans in C:\Scans"
$files = Get-ChildItem C:\Scans -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
if ($files) {
    $files | ForEach-Object { Write-Output "  $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) | $($_.Name)" }
} else {
    Write-Output "  (empty)"
}

Write-Output "`n[2] Network Profile"
$pub = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'}
if ($pub) {
    $pub | Set-NetConnectionProfile -NetworkCategory Private
    $fixed += "Network profile: Public -> Private"
    Write-Output "  FIXED: Set to Private"
} else {
    Write-Output "  OK: Private"
}

Write-Output "`n[3] Firewall Rules (File and Printer Sharing)"
$fwBefore = @(Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -EA SilentlyContinue | Where-Object {$_.Enabled -eq 'True'})
$fwDisabled = @(Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -EA SilentlyContinue | Where-Object {$_.Enabled -eq 'False'})
if ($fwDisabled.Count -gt 0) {
    Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
    $fixed += "Firewall: enabled $($fwDisabled.Count) rules"
    Write-Output "  FIXED: Enabled $($fwDisabled.Count) rules ($($fwBefore.Count + $fwDisabled.Count) total)"
} else {
    Write-Output "  OK: $($fwBefore.Count) rules enabled"
}

Write-Output "`n[4] SMB Signing"
$smb = Get-SmbServerConfiguration
if ($smb.RequireSecuritySignature) {
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
    $fixed += "SMB signing requirement disabled"
    Write-Output "  FIXED: Signing requirement disabled"
} else {
    Write-Output "  OK: Signing not required"
}

Write-Output "`n[5] Scans Folder"
if (-not (Test-Path C:\Scans)) {
    New-Item -Path C:\Scans -ItemType Directory | Out-Null
    $fixed += "Created C:\Scans"
    Write-Output "  FIXED: Created C:\Scans"
} else {
    Write-Output "  OK: C:\Scans exists"
}

Write-Output "`n[6] NTFS Permissions"
$acl = Get-Acl C:\Scans
$hasPerm = $acl.Access | Where-Object {$_.IdentityReference -match 'local\.mfp\.scan' -and $_.FileSystemRights -match 'Modify|FullControl'}
if (-not $hasPerm) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('local.mfp.scan','Modify','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    Set-Acl C:\Scans $acl
    $fixed += "NTFS: Added Modify for local.mfp.scan"
    Write-Output "  FIXED: Added Modify permission"
} else {
    Write-Output "  OK: local.mfp.scan has Modify"
}

Write-Output "`n[7] SMB Share"
$share = Get-SmbShare -Name 'Scans' -EA SilentlyContinue
if (-not $share) {
    New-SmbShare -Name 'Scans' -Path 'C:\Scans' -FullAccess 'local.mfp.scan' | Out-Null
    $fixed += "Created Scans SMB share"
    Write-Output "  FIXED: Share created"
} else {
    Write-Output "  OK: Scans share at $($share.Path)"
}

Write-Output "`n[8] SMB Auth Probe (local.mfp.scan)"
if (-not $Password) {
    Write-Output "  SKIPPED: `$Password not set. Edit script with the stored password and re-paste to enable."
} elseif (-not $acct) {
    Write-Output "  SKIPPED: local.mfp.scan account missing."
} else {
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('local.mfp.scan',$sec)
    try {
        New-PSDrive -Name MFPProbe -PSProvider FileSystem -Root "\\$env:COMPUTERNAME\Scans" -Credential $cred -EA Stop | Out-Null
        $probeFile = "MFPProbe:\authprobe-$(Get-Date -f yyyyMMddHHmmss).tmp"
        Set-Content -Path $probeFile -Value 'probe' -EA Stop
        Remove-Item $probeFile -EA SilentlyContinue
        Remove-PSDrive MFPProbe -EA SilentlyContinue
        Write-Output "  AUTH OK + WRITE OK — workstation side validated"
        $authOk = $true
    } catch {
        Write-Output "  AUTH FAILED: $($_.Exception.Message)"
        Remove-PSDrive MFPProbe -EA SilentlyContinue
        $authOk = $false
    }
}

Write-Output "`n[9] Local Account Password Reset (on mismatch)"
if (-not $Password -or -not $acct) {
    Write-Output "  SKIPPED"
} elseif ($authOk) {
    Write-Output "  SKIPPED: auth already OK, no reset needed"
} else {
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-LocalUser -Name 'local.mfp.scan' -Password $sec
    Set-LocalUser -Name 'local.mfp.scan' -PasswordNeverExpires $true
    $fixed += "local.mfp.scan: password reset to provided value, PasswordNeverExpires set"
    Write-Output "  FIXED: Password reset. Re-running probe..."
    $cred = New-Object System.Management.Automation.PSCredential('local.mfp.scan',$sec)
    try {
        New-PSDrive -Name MFPProbe2 -PSProvider FileSystem -Root "\\$env:COMPUTERNAME\Scans" -Credential $cred -EA Stop | Out-Null
        $probeFile = "MFPProbe2:\authprobe-$(Get-Date -f yyyyMMddHHmmss).tmp"
        Set-Content -Path $probeFile -Value 'probe' -EA Stop
        Remove-Item $probeFile -EA SilentlyContinue
        Remove-PSDrive MFPProbe2 -EA SilentlyContinue
        Write-Output "  POST-RESET AUTH OK — MFP address book should now match"
    } catch {
        Write-Output "  POST-RESET AUTH FAILED: $($_.Exception.Message)"
        Remove-PSDrive MFPProbe2 -EA SilentlyContinue
        $warn += "Auth still failing after password reset — investigate share/firewall/profile or MFP-side address book"
    }
}

Write-Output "`n[10] Recent 4625 Logon Failures (last 60 min)"
$evts = @(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625;StartTime=(Get-Date).AddMinutes(-60)} -EA SilentlyContinue)
if (-not $evts) {
    Write-Output "  None in last 60 min"
} else {
    $statusMap = @{
        '0xc000006a' = 'WRONG_PASSWORD'
        '0xc0000072' = 'ACCOUNT_DISABLED (Guest fall-through)'
        '0xc000006d' = 'LOGON_FAILURE'
        '0xc0000064' = 'NO_SUCH_USER'
        '0xc000006f' = 'INVALID_LOGON_HOURS'
        '0xc0000234' = 'ACCOUNT_LOCKED'
        '0xc0000071' = 'PASSWORD_EXPIRED'
    }
    $rows = $evts | ForEach-Object {
        $x = [xml]$_.ToXml()
        $user = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $sub = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'SubStatus'}).'#text'
        $src = ($x.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        $dec = if ($sub) { $statusMap[$sub.ToLower()] } else { '' }
        [pscustomobject]@{
            Time = $_.TimeCreated.ToString('HH:mm:ss')
            User = $user
            SubStatus = $sub
            Decoded = $dec
            Source = $src
        }
    } | Select-Object -First 10
    $rows | Format-Table -AutoSize
    if ($rows | Where-Object {$_.User -eq 'Guest'}) {
        Write-Output "  *** Guest fall-through detected — MFP address book User ID may be blank or wrong. Inspect MFP web UI. ***"
        $warn += "Guest fall-through in 4625 — MFP address book User ID likely blank/wrong"
    }
    if ($rows | Where-Object {$_.SubStatus -eq '0xc000006a'}) {
        Write-Output "  *** Wrong-password events detected — workstation local password and MFP address book password do not match ***"
    }
}

if ($MfpIp) {
    Write-Output "`n[11] MFP Reachability ($MfpIp)"
    $ping = Test-Connection -ComputerName $MfpIp -Count 2 -Quiet -EA SilentlyContinue
    Write-Output "  Ping: $(if($ping){'OK'}else{'FAIL'})"
    $webUi = Test-NetConnection -ComputerName $MfpIp -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue -EA SilentlyContinue
    Write-Output "  Web UI port 80: $(if($webUi){'OK'}else{'FAIL'})"
    if (-not $ping) {
        $warn += "MFP $MfpIp unreachable from workstation — check VLAN, switch port, MFP power"
    }
}

Write-Output "`n=== RESULT ==="
if ($fixed.Count -eq 0 -and $warn.Count -eq 0) {
    Write-Output "All checks passed. No changes needed."
} else {
    if ($fixed.Count -gt 0) {
        Write-Output "Fixed $($fixed.Count) item(s):"
        $fixed | ForEach-Object {Write-Output "  - $_"}
    }
    if ($warn.Count -gt 0) {
        Write-Output "Manual action needed ($($warn.Count)):"
        $warn | ForEach-Object {Write-Output "  - $_"}
    }
}
$ip = (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {$_.PrefixOrigin -eq 'Dhcp'}).IPAddress
Write-Output "`nHostname: $env:COMPUTERNAME"
Write-Output "IP: $ip"
