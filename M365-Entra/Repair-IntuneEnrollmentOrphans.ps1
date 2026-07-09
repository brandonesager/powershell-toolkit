<#
.SYNOPSIS
    Recursive ACL-reset (takeown + bottom-up) and delete for all Intune enrollment GUIDs.

.DESCRIPTION
    Write companion to Get-IntuneEnrollmentOrphans.ps1 (read-only diagnostic).
    Removes all enrollment GUIDs and supporting registry keys that block Entra
    re-join (error 0x8018000a / 80190190). Process:

    1. Pre-cleanup snapshot: dsregcmd /status, enrollment GUID count.
    2. dsregcmd /leave.
    3. Enable NT privileges (SeRestorePrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege).
    4. For each enrollment GUID: enumerate subkeys depth-first, take ownership,
       reset ACL (Administrators + SYSTEM FullControl), delete bottom-up.
       Fallback: reg.exe delete, then WMI StdRegProv.
    5. Clear supporting keys: Enrollments/Context, Status, ValidNodePaths.
    6. Clear EnterpriseResourceManager/Tracked GUIDs.
    7. Clear PolicyManager AdmxInstalled and Providers GUIDs.
    8. Clear OMADM Provisioning accounts/logger/sessions.
    9. Clear NGC keys (certutil).
    10. Unregister EnterpriseMgmt scheduled tasks.
    11. Remove MDM certificates from LocalMachine\My.
    12. Post-cleanup verification + final dsregcmd state.

    Context: RMM shell (SYSTEM) or SYSTEM remote session (SYSTEM). PS 5.1.
    After success, reboot the endpoint before attempting Entra re-join.

.EXAMPLE
    Run via RMM shell:
    #!ps
    #maxlength=100000
    #timeout=300000
    (paste script content)

.NOTES
    Created: 2026-05-29
    Category: M365-Entra
    Context: Commands/SYSTEM

    Write companion: Get-IntuneEnrollmentOrphans.ps1 (read-only, run first to confirm orphan count).
    Root cause pattern: stale enrollment GUID with ACL locked to a purged Intune identity blocks
    dsregcmd /join with 0x8018000a. Standard Remove-Item fails; requires privilege escalation + ACL reset.

.KEYWORDS
    Intune, enrollment, orphan, registry, ACL, takeown, 0x8018000a, 80190190, Entra join, repair
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Continue'
$script:Results           = @()
$script:PrivilegesEnabled = $false

# ============================================================================
# PRIVILEGE ELEVATION
# ============================================================================

function Enable-Privileges {
    if ($script:PrivilegesEnabled) { return $true }
    try {
        $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong p, bool e, bool c, ref bool o);'
        $ntdll = Add-Type -Member $import -Name NtDll -PassThru -ErrorAction SilentlyContinue
        $null = $ntdll::RtlAdjustPrivilege(9,  $true, $false, [ref]$false)   # SeRestorePrivilege
        $null = $ntdll::RtlAdjustPrivilege(17, $true, $false, [ref]$false)   # SeBackupPrivilege
        $null = $ntdll::RtlAdjustPrivilege(18, $true, $false, [ref]$false)   # SeTakeOwnershipPrivilege
        $null = $ntdll::RtlAdjustPrivilege(19, $true, $false, [ref]$false)   # SeDebugPrivilege
        $script:PrivilegesEnabled = $true
        return $true
    } catch {
        Write-Output "WARNING: Could not enable all privileges: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# RECURSIVE KEY HELPERS
# ============================================================================

function Get-AllSubkeysRecursive {
    param([string]$KeyPath)
    $subkeys = @()
    try {
        $item      = Get-Item -Path "Registry::$KeyPath" -ErrorAction Stop
        $childNames = $item.GetSubKeyNames()
        foreach ($childName in $childNames) {
            $childPath = "$KeyPath\$childName"
            $subkeys  += $childPath
            $subkeys  += Get-AllSubkeysRecursive -KeyPath $childPath
        }
    } catch {
        $regQuery = $KeyPath -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\'
        $queryOut = reg query $regQuery 2>&1
        if ($LASTEXITCODE -eq 0) {
            $queryOut | Where-Object {
                $_ -match '^HKEY_LOCAL_MACHINE\\' -and
                $_ -ne "HKEY_LOCAL_MACHINE\$($KeyPath -replace '^HKEY_LOCAL_MACHINE\\', '')"
            } | ForEach-Object {
                $cp = $_.Trim()
                if ($cp -ne $KeyPath) { $subkeys += $cp }
            }
        }
    }
    return $subkeys
}

function Process-SingleKey {
    param([string]$KeyPath, [int]$MaxRetries = 2)
    $result = [PSCustomObject]@{ Success = $false; KeyPath = $KeyPath; Error = $null; Owner = $null; Method = $null }

    if (-not (Test-Path "Registry::$KeyPath" -ErrorAction SilentlyContinue)) {
        $result.Success = $true; $result.Method = 'AlreadyGone'; return $result
    }

    $parts = $KeyPath -split '\\', 2
    $hive  = $parts[0]
    $subk  = $parts[1]
    $regHive = switch ($hive) {
        'HKEY_LOCAL_MACHINE' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKEY_CURRENT_USER'  { [Microsoft.Win32.Registry]::CurrentUser }
        'HKEY_USERS'         { [Microsoft.Win32.Registry]::Users }
        default { $result.Error = "Unknown hive: $hive"; return $result }
    }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $key = $regHive.OpenSubKey($subk, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                   [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($null -eq $key) { throw 'Cannot open with TakeOwnership' }

            $acl   = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::All)
            $admin = [System.Security.Principal.NTAccount]'BUILTIN\Administrators'
            $acl.SetOwner($admin); $key.SetAccessControl($acl); $key.Close()

            $key = $regHive.OpenSubKey($subk, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                   ([System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                    [System.Security.AccessControl.RegistryRights]::ReadKey))
            if ($null -eq $key) { throw 'Cannot reopen after ownership change' }

            $acl2 = New-Object System.Security.AccessControl.RegistrySecurity
            $acl2.SetAccessRuleProtection($false, $false)
            $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                       [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $prop    = [System.Security.AccessControl.PropagationFlags]::None
            $allow   = [System.Security.AccessControl.AccessControlType]::Allow
            $fc      = [System.Security.AccessControl.RegistryRights]::FullControl

            $acl2.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($admin, $fc, $inherit, $prop, $allow)))
            $sys = [System.Security.Principal.NTAccount]'NT AUTHORITY\SYSTEM'
            $acl2.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($sys,   $fc, $inherit, $prop, $allow)))
            $acl2.SetOwner($admin); $key.SetAccessControl($acl2); $key.Close()

            Remove-Item -Path "Registry::$KeyPath" -Recurse -Force -ErrorAction Stop
            $result.Success = $true; $result.Method = 'PowerShell-ACLReset'; return $result
        } catch {
            $result.Error = $_.Exception.Message
        }
    }

    # Fallback: reg.exe
    try {
        $rp = $KeyPath -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\'
        $out = reg delete $rp /f 2>&1
        if ($LASTEXITCODE -eq 0) { $result.Success = $true; $result.Method = 'reg.exe'; $result.Error = $null; return $result }
        $result.Error = "reg.exe: $out"
    } catch { $result.Error = "reg.exe exception: $($_.Exception.Message)" }

    # Fallback: WMI
    try {
        $hNum = switch ($hive) { 'HKEY_LOCAL_MACHINE' { 2147483650 } 'HKEY_CURRENT_USER' { 2147483649 } 'HKEY_USERS' { 2147483651 } default { 0 } }
        if ($hNum -ne 0) {
            $wmi = [wmiclass]'\\.\root\default:StdRegProv'
            $wr  = $wmi.DeleteKey($hNum, $subk)
            if ($wr.ReturnValue -eq 0) { $result.Success = $true; $result.Method = 'WMI'; $result.Error = $null; return $result }
            $result.Error = "WMI ReturnValue: $($wr.ReturnValue)"
        }
    } catch { $result.Error = "WMI: $($_.Exception.Message)" }

    return $result
}

function Remove-RegistryKeyWithTakeover {
    param([string]$KeyPath, [int]$MaxRetries = 2)
    $normalizedPath = $KeyPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^Registry::', ''
    if (-not (Test-Path "Registry::$normalizedPath" -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{ Success = $true; KeyPath = $normalizedPath; Method = 'AlreadyGone'; Error = $null; Subkeys = 0 }
    }
    Enable-Privileges | Out-Null
    $allKeys = @()
    try { $allKeys = Get-AllSubkeysRecursive -KeyPath $normalizedPath } catch {}
    $allKeys = $allKeys | Sort-Object { ($_ -split '\\').Count } -Descending
    foreach ($sk in $allKeys) { Process-SingleKey -KeyPath $sk -MaxRetries $MaxRetries | Out-Null }
    $res = Process-SingleKey -KeyPath $normalizedPath -MaxRetries $MaxRetries
    $res | Add-Member -NotePropertyName Subkeys -NotePropertyValue $allKeys.Count -Force
    return $res
}

function Show-ResultsTable {
    param([array]$Results)
    Write-Output "`n=== DELETION SUMMARY ==="
    $ok   = 0; $fail = 0
    foreach ($r in $Results) {
        $label = if ($r.Success) { 'OK'; $ok++ } else { 'FAILED'; $fail++ }
        $detail = if ($r.Success) { $r.Method } else { ($r.Error -split "`n")[0].Substring(0, [Math]::Min(40, ($r.Error -split "`n")[0].Length)) }
        $short  = if ($r.KeyPath.Length -gt 55) { '...' + $r.KeyPath.Substring($r.KeyPath.Length - 52) } else { $r.KeyPath }
        Write-Output ("{0,-58} {1,-8} {2}" -f $short, $label, $detail)
    }
    Write-Output ""
    Write-Output "Deleted: $ok  |  Failed: $fail"
    $Results | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Output "`nFAILED: $($_.KeyPath)"
        Write-Output "  Error: $($_.Error)"
    }
    return $fail
}

# ============================================================================
# MAIN
# ============================================================================

try {
    Write-Output "============================================================"
    Write-Output "  REPAIR INTUNE ENROLLMENT ORPHANS"
    Write-Output "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "============================================================"

    Write-Output "`n=== PRE-CLEANUP STATE ==="
    dsregcmd /status 2>&1 | Select-String -Pattern 'AzureAdJoined|WorkplaceJoined|DeviceId|TenantId|PreReqResult' |
        ForEach-Object { Write-Output $_.Line.Trim() }
    $preGuids = @(reg query 'HKLM\SOFTWARE\Microsoft\Enrollments' 2>&1 |
        Where-Object { $_ -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' })
    Write-Output "Enrollment GUIDs found: $($preGuids.Count)"

    Write-Output "`n=== STEP 1: dsregcmd /leave ==="
    dsregcmd /leave 2>&1 | Select-Object -First 5 | ForEach-Object { Write-Output $_ }

    Write-Output "`n=== STEP 2: Enabling privileges ==="
    if (Enable-Privileges) { Write-Output 'Privileges enabled.' }

    $allResults = @()

    Write-Output "`n=== STEP 3: Clearing Enrollment GUIDs ==="
    $enrollList = reg query 'HKLM\SOFTWARE\Microsoft\Enrollments' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $guidLines = $enrollList | Where-Object { $_ -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' }
        foreach ($line in $guidLines) {
            $kp = $line.Trim() -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
            Write-Output "Processing: $kp"
            $r = Remove-RegistryKeyWithTakeover -KeyPath $kp
            $allResults += $r
            Write-Output "  $(if ($r.Success) { 'DELETED (' + $r.Method + ')' } else { 'FAILED: ' + $r.Error })"
        }
    } else { Write-Output 'Enrollments key already clean.' }

    Write-Output "`n=== STEP 4: Supporting Keys ==="
    @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Context',
      'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Status',
      'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\ValidNodePaths') | ForEach-Object {
        $r = Remove-RegistryKeyWithTakeover -KeyPath $_
        $allResults += $r
        Write-Output "$(if ($r.Success) { 'DELETED' } else { 'FAILED' }): $_"
    }

    Write-Output "`n=== STEP 5: EnterpriseResourceManager ==="
    $ermOut = reg query 'HKLM\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $ermOut | Where-Object { $_ -match '[0-9A-Fa-f]{8}-' } | ForEach-Object {
            $kp = $_.Trim() -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
            $r  = Remove-RegistryKeyWithTakeover -KeyPath $kp
            $allResults += $r
            Write-Output "$(if ($r.Success) { 'DELETED' } else { 'FAILED' }): $kp"
        }
    } else { Write-Output 'CLEAN: EnterpriseResourceManager' }

    Write-Output "`n=== STEP 6: PolicyManager ==="
    @('HKLM\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled',
      'HKLM\SOFTWARE\Microsoft\PolicyManager\Providers') | ForEach-Object {
        $pmOut = reg query $_ 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pmOut | Where-Object { $_ -match '[0-9A-Fa-f]{8}-' } | ForEach-Object {
                $kp = $_.Trim() -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
                $r  = Remove-RegistryKeyWithTakeover -KeyPath $kp
                $allResults += $r
            }
        }
    }
    Write-Output 'PolicyManager processed.'

    Write-Output "`n=== STEP 7: OMADM Provisioning ==="
    @('HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts',
      'HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Logger',
      'HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions') | ForEach-Object {
        reg delete $_ /f 2>&1 | Out-Null
    }
    Write-Output 'OMADM Provisioning cleared.'

    Write-Output "`n=== STEP 8: NGC Keys ==="
    $ngc = certutil -csp NGC -delkey 2>&1
    Write-Output $(if ($ngc -match 'deleted|success') { 'NGC keys cleared.' } else { 'NGC: nothing to clear.' })

    Write-Output "`n=== STEP 9: EnterpriseMgmt Tasks ==="
    $tasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue
    $tc = ($tasks | Measure-Object).Count
    $tasks | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Output "EnterpriseMgmt tasks removed: $tc"

    Write-Output "`n=== STEP 10: MDM Certificates ==="
    $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Issuer -match 'Microsoft Intune MDM|SC_Online_Issuing' }
    $cc = ($certs | Measure-Object).Count
    $certs | ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue }
    Write-Output "MDM certificates removed: $cc"

    $failCount = Show-ResultsTable -Results $allResults

    Write-Output "`n=== POST-CLEANUP VERIFICATION ==="
    $postOut = reg query 'HKLM\SOFTWARE\Microsoft\Enrollments' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $remaining = @($postOut | Where-Object { $_ -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' })
        if ($remaining.Count -gt 0) {
            Write-Output "WARNING: $($remaining.Count) GUID(s) still remain:"
            $remaining | ForEach-Object { Write-Output "  $($_.Trim())" }
        } else { Write-Output 'SUCCESS: All enrollment GUIDs removed.' }
    } else { Write-Output 'SUCCESS: Enrollments key is clean.' }

    Write-Output "`n=== FINAL STATE ==="
    dsregcmd /status 2>&1 | Select-String -Pattern 'AzureAdJoined|WorkplaceJoined|DeviceId|PreReqResult' |
        ForEach-Object { Write-Output $_.Line.Trim() }

    Write-Output "`n============================================================"
    if ($failCount -eq 0) {
        Write-Output 'CLEANUP COMPLETE -- REBOOT REQUIRED before Entra re-join.'
        exit 0
    } else {
        Write-Output "PARTIAL SUCCESS -- $failCount key(s) failed. Review failures above."
        exit 112
    }
} catch {
    Write-Output "`nFATAL ERROR: $($_.Exception.Message)"
    Write-Output "Stack: $($_.ScriptStackTrace)"
    exit 1
}
