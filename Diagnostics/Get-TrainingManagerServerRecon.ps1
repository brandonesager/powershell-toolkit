<#
.SYNOPSIS
    Recon a server for Firebird installation and Training Manager enterprise assets

.DESCRIPTION
    Pre-migration diagnostic for Training Manager 2018 multi-user conversion.
    Checks:
    - Existing Firebird service and installation
    - Port 3050 listener status
    - aliases.config file presence and contents
    - Enterprise installer and license file locations
    - Disk space for database hosting
    - Training Manager related files and folders

.NOTES
    Context: RMM (PS 5.1, SYSTEM)
    Exit Codes: 0 = all checks passed | 112 = partial findings | 1 = error

.KEYWORDS
    Firebird, Training Manager, multi-user, migration, recon
#>

$ErrorActionPreference = "Stop"

try {
    Write-Output "=== Training Manager Server Recon ==="
    Write-Output "Host: $env:COMPUTERNAME"
    Write-Output "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    $findings = 0
    $checks = 0

    # --- Firebird Service ---
    Write-Output "--- Firebird Service ---"
    $checks++
    $fbServices = @(Get-Service | Where-Object { $_.Name -match 'Firebird|FirebirdServer' -or $_.DisplayName -match 'Firebird' })
    if ($fbServices.Count -gt 0) {
        $findings++
        foreach ($svc in $fbServices) {
            Write-Output "FOUND: Service '$($svc.DisplayName)' ($($svc.Name)) - Status: $($svc.Status) - StartType: $($svc.StartType)"
        }
    } else {
        Write-Output "NOT FOUND: No Firebird service detected"
    }
    Write-Output ""

    # --- Firebird Installation Paths ---
    Write-Output "--- Firebird Installation ---"
    $checks++
    $fbPaths = @(
        "$env:ProgramFiles\Firebird",
        "${env:ProgramFiles(x86)}\Firebird",
        "$env:ProgramFiles\Firebird\Firebird_2_5",
        "$env:ProgramFiles\Firebird\Firebird_3_0",
        "$env:ProgramFiles\Firebird\Firebird_4_0"
    )
    $fbFound = $false
    foreach ($path in $fbPaths) {
        if (Test-Path $path) {
            $fbFound = $true
            $findings++
            Write-Output "FOUND: $path"
            $items = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue)
            Write-Output "  Contents: $($items.Count) items"
            $items | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Output
            break
        }
    }
    if (-not $fbFound) {
        Write-Output "NOT FOUND: No Firebird installation directory"
    }
    Write-Output ""

    # --- aliases.config ---
    Write-Output "--- Firebird Alias Config ---"
    $checks++
    $aliasPaths = @(
        "$env:ProgramFiles\Firebird\Firebird_2_5\aliases.config",
        "$env:ProgramFiles\Firebird\Firebird_3_0\aliases.conf",
        "$env:ProgramFiles\Firebird\Firebird_4_0\databases.conf",
        "$env:ProgramFiles\Firebird\aliases.config",
        "${env:ProgramFiles(x86)}\Firebird\Firebird_2_5\aliases.config"
    )
    $aliasFound = $false
    foreach ($ap in $aliasPaths) {
        if (Test-Path $ap) {
            $aliasFound = $true
            $findings++
            Write-Output "FOUND: $ap"
            $content = Get-Content $ap -ErrorAction SilentlyContinue
            if ($content) {
                Write-Output "  Contents:"
                foreach ($line in $content) {
                    if ($line.Trim() -and -not $line.Trim().StartsWith('#')) {
                        Write-Output "    $line"
                    }
                }
            } else {
                Write-Output "  (empty file)"
            }
        }
    }
    if (-not $aliasFound) {
        Write-Output "NOT FOUND: No alias config file"
    }
    Write-Output ""

    # --- Port 3050 Listener ---
    Write-Output "--- Port 3050 Status ---"
    $checks++
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 3050 })
    if ($listeners.Count -gt 0) {
        $findings++
        foreach ($l in $listeners) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            Write-Output "FOUND: Port 3050 listening - PID $($l.OwningProcess) ($($proc.ProcessName)) on $($l.LocalAddress)"
        }
    } else {
        Write-Output "NOT FOUND: Nothing listening on port 3050"
    }
    Write-Output ""

    # --- Firewall Rule for 3050 ---
    Write-Output "--- Firewall Rules (port 3050) ---"
    $checks++
    $fwRules = @(Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq '3050' } |
        ForEach-Object { Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_ -ErrorAction SilentlyContinue })
    if ($fwRules.Count -gt 0) {
        $findings++
        foreach ($rule in $fwRules) {
            Write-Output "FOUND: '$($rule.DisplayName)' - Enabled: $($rule.Enabled) - Direction: $($rule.Direction) - Action: $($rule.Action)"
        }
    } else {
        Write-Output "NOT FOUND: No firewall rules for port 3050"
    }
    Write-Output ""

    # --- Enterprise Installer and License ---
    Write-Output "--- Training Manager Enterprise Assets ---"
    $checks++
    $searchPaths = @(
        "C:\Software",
        "D:\Software",
        "C:\TrainingManagerInstallation",
        "D:\Shares\Software"
    )

    $installerFound = $false
    $licenseFound = $false

    foreach ($sp in ($searchPaths | Select-Object -Unique)) {
        if (-not (Test-Path $sp)) { continue }
        $exeFiles = @(Get-ChildItem -Path $sp -Recurse -Depth 3 -Filter "TrainingManager*Setup*.exe" -ErrorAction SilentlyContinue)
        $licFiles = @(Get-ChildItem -Path $sp -Recurse -Depth 3 -Filter "EntLicense.lic" -ErrorAction SilentlyContinue)
        $tdbFiles = @(Get-ChildItem -Path $sp -Recurse -Depth 3 -Filter "*.tdb" -ErrorAction SilentlyContinue)

        foreach ($f in $exeFiles) {
            $installerFound = $true
            Write-Output "FOUND INSTALLER: $($f.FullName) ($('{0:N1} MB' -f ($f.Length / 1MB)), $($f.LastWriteTime.ToString('yyyy-MM-dd')))"
        }
        foreach ($f in $licFiles) {
            $licenseFound = $true
            Write-Output "FOUND LICENSE: $($f.FullName) ($($f.LastWriteTime.ToString('yyyy-MM-dd')))"
        }
        foreach ($f in $tdbFiles) {
            Write-Output "FOUND DB FILE: $($f.FullName) ($('{0:N1} MB' -f ($f.Length / 1MB)), $($f.LastWriteTime.ToString('yyyy-MM-dd')))"
        }
    }

    if ($installerFound) { $findings++ }
    if (-not $installerFound) { Write-Output "NOT FOUND: TrainingManagerEnterpriseSetup.exe not found in searched paths" }
    if (-not $licenseFound) { Write-Output "NOT FOUND: EntLicense.lic not found in searched paths" }
    Write-Output "  Paths searched: $($searchPaths -join ', ')"
    Write-Output ""

    # --- KZSoftware Directories ---
    Write-Output "--- KZ Software Directories ---"
    $kzPaths = @(
        "C:\KZSoftware",
        "D:\KZSoftware",
        "C:\ProgramData\TrainingManager",
        "$env:ProgramFiles\KZ Software",
        "${env:ProgramFiles(x86)}\KZ Software",
        "$env:ProgramFiles\Training Manager",
        "${env:ProgramFiles(x86)}\Training Manager"
    )
    foreach ($kp in $kzPaths) {
        if (Test-Path $kp) {
            Write-Output "FOUND: $kp"
            Get-ChildItem -Path $kp -ErrorAction SilentlyContinue |
                Select-Object Name, Length, LastWriteTime |
                Format-Table -AutoSize | Out-String | Write-Output
        }
    }
    Write-Output ""

    # --- Disk Space ---
    Write-Output "--- Disk Space ---"
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        ForEach-Object {
            $freeGB = [math]::Round($_.FreeSpace / 1GB, 1)
            $totalGB = [math]::Round($_.Size / 1GB, 1)
            $pctFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 0)
            Write-Output "$($_.DeviceID) $freeGB GB free / $totalGB GB total ($pctFree% free)"
        }
    Write-Output ""

    # --- Installed Programs (Training Manager / Firebird) ---
    Write-Output "--- Related Installed Programs ---"
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = foreach ($rp in $regPaths) {
        Get-ItemProperty $rp -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Training Manager|Firebird|KZ Software' } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
    if ($apps) {
        $apps | Format-Table -AutoSize | Out-String | Write-Output
    } else {
        Write-Output "NOT FOUND: No Training Manager or Firebird entries in Add/Remove Programs"
    }
    Write-Output ""

    # --- Summary ---
    Write-Output "=== Summary ==="
    Write-Output "Checks: $checks | Findings: $findings"

    if ($findings -eq 0) {
        Write-Output "RESULT: Clean server - no existing Firebird or Training Manager components. Ready for fresh install."
        exit 0
    } elseif ($findings -lt $checks) {
        Write-Output "RESULT: Partial findings - review output above for existing components."
        exit 112
    } else {
        Write-Output "RESULT: All components detected - Firebird may already be installed."
        exit 0
    }
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR: Line $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}
