<#
.SYNOPSIS
    Server-side drive mapping diagnostics for GPP and login script troubleshooting

.DESCRIPTION
    Collects comprehensive drive mapping configuration from a file server or domain controller:
    - SMB shares (non-admin) with share permissions
    - NTFS ACLs on share paths
    - SMB server configuration (protocol versions, signing, encryption)
    - GPP drive maps (Drives.xml in SYSVOL)
    - Login scripts in NETLOGON with drive mapping commands
    - AD user logon script and home drive assignments

    Designed for troubleshooting scenarios where mapped drives are inconsistent, missing,
    or apply to only a subset of users. Identifies whether mapping is configured via GPP,
    login scripts, AD user properties, or not configured at all.

.PARAMETER ShareNames
    Array of share names to inspect (permissions + NTFS ACL). Defaults to common share names.
    Use when troubleshooting specific shares. Skips shares not found (non-fatal).

.EXAMPLE
    # Default scan (common shares: SYS, VOL1, Archive, Shared)
    .\Get-DriveMappingDiagnostics.ps1

.EXAMPLE
    # Scan specific shares
    .\Get-DriveMappingDiagnostics.ps1 -ShareNames 'Data','Finance','HR'

.NOTES
    Date: 2026-02-13

.KEYWORDS
    diagnose, SMB, share, GPO, GPP, drive mapping, login script, AD, server, SYSVOL, NETLOGON
#>

[CmdletBinding()]
param(
    [string[]]$ShareNames = @('SYS', 'VOL1', 'Archive', 'Shared')
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

$exitCode = 0

try {
    Write-Log "=== Server Drive Mapping Diagnostics — $env:COMPUTERNAME ==="

    # ── 1. SMB Shares (non-admin) ──
    Write-Log "--- SMB Shares (non-admin) ---"
    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notlike '*$' -and $_.Name -ne 'IPC$' }
        foreach ($s in $shares) {
            Write-Output "  $($s.Name) → $($s.Path)  ($($s.Description))"
        }

        # Share permissions for specified shares
        foreach ($shareName in $ShareNames) {
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            if ($share) {
                Write-Log "--- Share Permissions: $shareName ---"
                Write-Output "  Path: $($share.Path)"
                $access = Get-SmbShareAccess -Name $shareName
                foreach ($ace in $access) {
                    Write-Output "  $($ace.AccountName): $($ace.AccessRight) ($($ace.AccessControlType))"
                }
            } else {
                Write-Log "Share '$shareName' not found (skipped)" "WARN"
            }
        }
    } catch {
        Write-Log "SMB share check failed: $($_.Exception.Message)" "ERROR"
        $exitCode = 1
    }

    # ── 2. NTFS Permissions on Share Paths ──
    Write-Log "--- NTFS Permissions on Share Paths ---"
    try {
        foreach ($shareName in $ShareNames) {
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            if ($share) {
                Write-Output "  $shareName ($($share.Path)):"
                $acl = Get-Acl $share.Path
                foreach ($rule in $acl.Access) {
                    Write-Output "    $($rule.IdentityReference): $($rule.FileSystemRights) ($($rule.AccessControlType))"
                }
            }
        }
    } catch {
        Write-Log "NTFS permission check failed: $($_.Exception.Message)" "ERROR"
        $exitCode = 1
    }

    # ── 3. SMB Server Configuration ──
    Write-Log "--- SMB Server Configuration ---"
    try {
        $smbConfig = Get-SmbServerConfiguration
        Write-Output "  SMB1: $($smbConfig.EnableSMB1Protocol)"
        Write-Output "  SMB2: $($smbConfig.EnableSMB2Protocol)"
        Write-Output "  RequireSigning: $($smbConfig.RequireSecuritySignature)"
        Write-Output "  EnableSigning: $($smbConfig.EnableSecuritySignature)"
        Write-Output "  EncryptData: $($smbConfig.EncryptData)"
    } catch {
        Write-Log "SMB config check failed: $($_.Exception.Message)" "ERROR"
        $exitCode = 1
    }

    # ── 4. GPO Drive Mappings (Group Policy Preferences) ──
    Write-Log "--- GPO Drive Mappings (Drives.xml in SYSVOL) ---"
    try {
        $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
        if (Test-Path $sysvolPath) {
            $driveFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter 'Drives.xml' -ErrorAction SilentlyContinue
            if ($driveFiles) {
                foreach ($file in $driveFiles) {
                    Write-Output "  File: $($file.FullName)"
                    [xml]$xml = Get-Content $file.FullName
                    foreach ($drive in $xml.Drives.Drive) {
                        Write-Output "    Letter=$($drive.Properties.letter) Path=$($drive.Properties.path) Action=$($drive.Properties.action) Reconnect=$($drive.Properties.persistent) Label=$($drive.Properties.label)"
                        if ($drive.Filters.InnerXml) {
                            Write-Output "    Filter: $($drive.Filters.InnerXml)"
                        }
                    }
                }
            } else {
                Write-Log "No Drives.xml found in SYSVOL — drive mappings may use login scripts or AD user properties" "WARN"
            }
        } else {
            Write-Log "Cannot access SYSVOL: $sysvolPath" "ERROR"
            $exitCode = 1
        }
    } catch {
        Write-Log "GPO drive mapping check failed: $($_.Exception.Message)" "ERROR"
        $exitCode = 1
    }

    # ── 5. Login Scripts in NETLOGON ──
    Write-Log "--- Login Scripts in NETLOGON ---"
    try {
        $netlogon = "\\$env:COMPUTERNAME\NETLOGON"
        if (Test-Path $netlogon) {
            $scripts = Get-ChildItem $netlogon -Recurse -Include '*.bat','*.cmd','*.vbs','*.ps1','*.kix' -ErrorAction SilentlyContinue
            if ($scripts) {
                foreach ($script in $scripts) {
                    Write-Output "  $($script.Name) (Modified: $($script.LastWriteTime))"
                    $matches = Get-Content $script.FullName | Select-String -Pattern 'net use|map|drive' -SimpleMatch
                    if ($matches) {
                        foreach ($m in $matches) {
                            Write-Output "    Line $($m.LineNumber): $($m.Line.Trim())"
                        }
                    } else {
                        Write-Output "    (no drive mapping references found)"
                    }
                }
            } else {
                Write-Log "No scripts found in NETLOGON" "WARN"
            }
        } else {
            Write-Log "Cannot access NETLOGON: $netlogon" "ERROR"
            $exitCode = 1
        }
    } catch {
        Write-Log "NETLOGON check failed: $($_.Exception.Message)" "ERROR"
        $exitCode = 1
    }

    # ── 6. AD User Logon Script & Home Drive Assignments ──
    Write-Log "--- AD Users with Login Script Assignments ---"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $scriptUsers = Get-ADUser -Filter { ScriptPath -like '*' } -Properties ScriptPath, HomeDirectory, HomeDrive
        if ($scriptUsers) {
            foreach ($u in $scriptUsers) {
                Write-Output "  $($u.Name) ($($u.SamAccountName)): Script=$($u.ScriptPath) HomeDrive=$($u.HomeDrive) HomeDir=$($u.HomeDirectory)"
            }
        } else {
            Write-Output "  No users with ScriptPath assigned"
        }

        Write-Log "--- AD Users with Home Drive Mappings ---"
        $homeDriveUsers = Get-ADUser -Filter { HomeDrive -like '*' } -Properties HomeDrive, HomeDirectory
        if ($homeDriveUsers) {
            foreach ($u in $homeDriveUsers) {
                Write-Output "  $($u.Name) ($($u.SamAccountName)): $($u.HomeDrive) → $($u.HomeDirectory)"
            }
        } else {
            Write-Output "  No users with HomeDrive assigned"
        }
    } catch {
        Write-Log "AD module not available or query failed: $($_.Exception.Message)" "WARN"
        $exitCode = 112
    }

    Write-Log "=== Server diagnostics complete ==="

} catch {
    Write-Log "Unexpected error: $($_.Exception.Message)" "ERROR"
    $exitCode = 1
}

exit $exitCode
