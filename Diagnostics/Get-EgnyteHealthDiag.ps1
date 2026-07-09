<#
.SYNOPSIS
    Diagnoses Egnyte Desktop App health -- process, drive mount, version, auto-start, trusted sites, disk, and network.
.DESCRIPTION
    RMM diagnostic for recurring Egnyte drive disconnection. Checks:
    1. EgnyteClient.exe process state
    2. Z: drive mount presence and accessibility
    3. Egnyte installed version (file and registry)
    4. Auto-start registry entry (per-user via SID resolution)
    5. Trusted sites ZoneMap entries (per-user via SID)
    6. Disk space on system drive
    7. Network connectivity to Egnyte cloud on port 443

    Runs as SYSTEM -- resolves the logged-in user's SID for user-scoped checks.
    Exits 0 if no critical issues, 1 if any issues found.
.PARAMETER EgnyteTenant
    Egnyte tenant hostname for the port-443 connectivity check.
    Default: contoso.egnyte.com
.EXAMPLE
    .\Get-EgnyteHealthDiag.ps1
.EXAMPLE
    .\Get-EgnyteHealthDiag.ps1 -EgnyteTenant "otherclient.egnyte.com"
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=No critical issues, 1=Issues found or unhandled error
    PS 5.1 compatible.
.KEYWORDS
    Egnyte, diagnostic, drive, trusted sites, auto-start, Contoso, Z drive
#>

[CmdletBinding()]
param(
    [string]$EgnyteTenant = 'contoso.egnyte.com'
)

$ErrorActionPreference = "Stop"

try {

    # --- Resolve logged-in user SID ---
    $loggedIn = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $loggedIn) {
        Write-Output "WARNING: No user logged in -- user-scoped checks will be skipped"
        $userSid = $null
        $userName = "NONE"
    } else {
        $userName = $loggedIn
        try {
            $userSid = (New-Object System.Security.Principal.NTAccount($loggedIn)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Write-Output "WARNING: Cannot resolve SID for $loggedIn -- user-scoped checks skipped"
            $userSid = $null
        }
    }

    Write-Output "=== Egnyte Health Diagnostic ==="
    Write-Output "Machine: $env:COMPUTERNAME"
    Write-Output "User: $userName"
    Write-Output "SID: $userSid"
    Write-Output "Tenant: $EgnyteTenant"
    Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    # --- 1. Egnyte Process ---
    Write-Output "--- 1. Egnyte Process ---"
    $proc = Get-Process -Name "EgnyteClient" -ErrorAction SilentlyContinue
    if ($proc) {
        foreach ($p in $proc) {
            Write-Output "RUNNING: PID=$($p.Id) CPU=$($p.CPU) WS=$('{0:N0}' -f ($p.WorkingSet64/1MB))MB Start=$($p.StartTime)"
        }
    } else {
        Write-Output "NOT RUNNING: EgnyteClient.exe is not running"
    }
    Write-Output ""

    # --- 2. Z: Drive ---
    Write-Output "--- 2. Z: Drive ---"
    $zDrive = Get-PSDrive -Name Z -ErrorAction SilentlyContinue
    if ($zDrive) {
        Write-Output "MOUNTED: Provider=$($zDrive.Provider) Root=$($zDrive.Root)"
        $accessible = Test-Path "Z:\" -ErrorAction SilentlyContinue
        Write-Output "Accessible: $accessible"
    } else {
        Write-Output "NOT MOUNTED: Z: drive does not exist"
    }
    Write-Output ""

    # --- 3. Egnyte Version ---
    Write-Output "--- 3. Egnyte Version ---"
    $egnytePaths = @(
        "${env:ProgramFiles(x86)}\Egnyte Connect\EgnyteClient.exe",
        "$env:ProgramFiles\Egnyte Connect\EgnyteClient.exe"
    )
    $found = $false
    foreach ($ep in $egnytePaths) {
        if (Test-Path $ep) {
            $ver = (Get-Item $ep).VersionInfo
            Write-Output "Installed: $($ver.FileVersion) at $ep"
            $found = $true
            break
        }
    }
    if (-not $found) {
        Write-Output "NOT FOUND: Egnyte Connect not installed in Program Files"
    }

    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $egnyteReg = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Egnyte*" } |
        Select-Object DisplayName, DisplayVersion, InstallDate
    if ($egnyteReg) {
        foreach ($e in $egnyteReg) {
            Write-Output "Registry: $($e.DisplayName) v$($e.DisplayVersion) installed=$($e.InstallDate)"
        }
    }
    Write-Output ""

    # --- 4. Auto-Start (user HKCU via SID) ---
    Write-Output "--- 4. Auto-Start ---"
    if ($userSid) {
        $runKey = "Registry::HKU\$userSid\Software\Microsoft\Windows\CurrentVersion\Run"
        $egnyteRun = Get-ItemProperty $runKey -Name "EgnyteClient" -ErrorAction SilentlyContinue
        if ($egnyteRun) {
            Write-Output "CONFIGURED: $($egnyteRun.EgnyteClient)"
        } else {
            $allRun = Get-ItemProperty $runKey -ErrorAction SilentlyContinue
            $egnyteEntry = $allRun.PSObject.Properties | Where-Object { $_.Value -like "*Egnyte*" }
            if ($egnyteEntry) {
                Write-Output "CONFIGURED (alt name): $($egnyteEntry.Name) = $($egnyteEntry.Value)"
            } else {
                Write-Output "MISSING: No Egnyte auto-start entry in HKCU Run key"
                Write-Output "ACTION: This explains why Z: disappears after reboot"
            }
        }
    } else {
        Write-Output "SKIPPED: No user SID available"
    }
    Write-Output ""

    # --- 5. Trusted Sites ---
    Write-Output "--- 5. Trusted Sites ---"
    if ($userSid) {
        $zmBase = "Registry::HKU\$userSid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
        $escBase = "$zmBase\EscDomains"
        $domainsBase = "$zmBase\Domains"

        $checks = @(
            @{ Path="$domainsBase\egnyte.com"; Desc="egnyte.com in Domains" },
            @{ Path="$escBase\egnyte.com"; Desc="egnyte.com in EscDomains" },
            @{ Path="$domainsBase\EgnyteDrive"; Desc="EgnyteDrive in Domains" },
            @{ Path="$escBase\EgnyteDrive"; Desc="EgnyteDrive in EscDomains" }
        )

        $missing = 0
        foreach ($c in $checks) {
            if (Test-Path $c.Path) {
                $props = Get-ItemProperty $c.Path -ErrorAction SilentlyContinue
                $vals = $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
                $detail = ($vals | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ", "
                Write-Output "FOUND: $($c.Desc) [$detail]"
            } else {
                Write-Output "MISSING: $($c.Desc)"
                $missing++
            }
        }

        if (Test-Path "$domainsBase\egnyte.com") {
            $subs = Get-ChildItem "$domainsBase\egnyte.com" -ErrorAction SilentlyContinue
            if ($subs) {
                foreach ($s in $subs) {
                    Write-Output "  Subdomain: $($s.PSChildName)"
                }
            }
        }

        if ($missing -gt 0) {
            Write-Output "ACTION: $missing trusted site entries missing -- may cause intermittent auth failures"
        }
    } else {
        Write-Output "SKIPPED: No user SID available"
    }
    Write-Output ""

    # --- 6. Disk Space ---
    Write-Output "--- 6. Disk Space ---"
    $sysDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeGB = [math]::Round($sysDrive.FreeSpace / 1GB, 1)
    $totalGB = [math]::Round($sysDrive.Size / 1GB, 1)
    $pctFree = [math]::Round(($sysDrive.FreeSpace / $sysDrive.Size) * 100, 0)
    Write-Output "C: $freeGB GB free of $totalGB GB ($pctFree% free)"
    if ($freeGB -lt 5) {
        Write-Output "ACTION: Low disk space -- Egnyte cache may fail"
    }
    Write-Output ""

    # --- 7. Network to Egnyte ---
    Write-Output "--- 7. Network Connectivity ---"
    $tcResult = Test-NetConnection -ComputerName $EgnyteTenant -Port 443 -WarningAction SilentlyContinue
    Write-Output "Egnyte cloud ($EgnyteTenant): $($tcResult.RemoteAddress) Port443=$($tcResult.TcpTestSucceeded) Latency=$($tcResult.PingReplyDetails.RoundtripTime)ms"
    if (-not $tcResult.TcpTestSucceeded) {
        Write-Output "ACTION: Cannot reach Egnyte cloud on port 443 -- network issue"
    }
    Write-Output ""

    # --- Summary ---
    Write-Output "=== Summary ==="
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $proc) { $issues.Add("Egnyte process not running") }
    if (-not $zDrive) { $issues.Add("Z: drive not mounted") }
    if ($userSid) {
        $runCheck = Get-ItemProperty "Registry::HKU\$userSid\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        $hasAutoStart = $false
        if ($runCheck) {
            $hasAutoStart = ($runCheck.PSObject.Properties | Where-Object { $_.Value -like "*Egnyte*" }).Count -gt 0
        }
        if (-not $hasAutoStart) { $issues.Add("Auto-start missing") }
    }
    if ($freeGB -lt 5) { $issues.Add("Low disk space") }
    if (-not $tcResult.TcpTestSucceeded) { $issues.Add("Network connectivity failed") }

    if ($issues.Count -eq 0) {
        Write-Output "No critical issues detected"
        exit 0
    } else {
        Write-Output "Issues found: $($issues.Count)"
        foreach ($i in $issues) {
            Write-Output "  - $i"
        }
        exit 1
    }

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}
