<#
.SYNOPSIS
    Recon a workstation for Training Manager 2018 single-user installation and database file

.DESCRIPTION
    Pre-migration diagnostic for Training Manager 2018 multi-user conversion.
    Run on the current single-user DB host to gather:
    - Installed Training Manager version and edition
    - Database file (.tdb) location, size, and lock status
    - Firebird client components (embedded vs. server)
    - Application configuration files
    - Running Training Manager processes

.NOTES
    Context: RMM (PS 5.1, SYSTEM)
    Exit Codes: 0 = DB file found | 112 = app found but no DB | 1 = neither found

.KEYWORDS
    Firebird, Training Manager, multi-user, migration, recon, workstation
#>

$ErrorActionPreference = "Stop"

try {
    Write-Output "=== Training Manager Workstation Recon ==="
    Write-Output "Host: $env:COMPUTERNAME"
    Write-Output "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""

    $dbFound = $false
    $appFound = $false

    # --- Installed Programs ---
    Write-Output "--- Installed Programs (Training Manager / Firebird / KZ Software) ---"
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
        $appFound = $true
        $apps | Format-Table -AutoSize | Out-String | Write-Output
    } else {
        Write-Output "NOT FOUND: No Training Manager or Firebird in Add/Remove Programs"
    }
    Write-Output ""

    # --- Database File Search ---
    Write-Output "--- Database File (.tdb) Search ---"
    $dbSearchPaths = @(
        "C:\KZSoftware",
        "D:\KZSoftware",
        "C:\ProgramData\TrainingManager",
        "C:\ProgramData\KZ Software",
        "$env:ProgramFiles\KZ Software",
        "${env:ProgramFiles(x86)}\KZ Software",
        "$env:ProgramFiles\Training Manager",
        "${env:ProgramFiles(x86)}\Training Manager"
    )

    $tdbFiles = [System.Collections.Generic.List[object]]::new()

    foreach ($sp in $dbSearchPaths) {
        if (-not (Test-Path $sp)) { continue }
        $found = @(Get-ChildItem -Path $sp -Recurse -Filter "*.tdb" -ErrorAction SilentlyContinue)
        foreach ($f in $found) {
            $tdbFiles.Add($f)
        }
    }

    # Broader search on common Program* locations
    $broadPaths = @("C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData")
    foreach ($bp in $broadPaths) {
        if (-not (Test-Path $bp)) { continue }
        $found = @(Get-ChildItem -Path $bp -Recurse -Filter "*.tdb" -Depth 3 -ErrorAction SilentlyContinue)
        foreach ($f in $found) {
            if ($tdbFiles.FullName -notcontains $f.FullName) {
                $tdbFiles.Add($f)
            }
        }
    }

    if ($tdbFiles.Count -gt 0) {
        $dbFound = $true
        foreach ($f in $tdbFiles) {
            $sizeMB = [math]::Round($f.Length / 1MB, 2)
            Write-Output "FOUND: $($f.FullName)"
            Write-Output "  Size: $sizeMB MB ($($f.Length) bytes)"
            Write-Output "  Modified: $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Output "  Created: $($f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))"

            # Check if file is locked (in use by Firebird)
            try {
                $stream = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'None')
                $stream.Close()
                Write-Output "  Locked: No (safe to copy)"
            } catch {
                Write-Output "  Locked: Yes (Training Manager or Firebird is running - close app before migration)"
            }
        }
    } else {
        Write-Output "NOT FOUND: No .tdb files in standard locations"
        Write-Output "  Searched: $($dbSearchPaths -join ', ')"
    }
    Write-Output ""

    # --- Also check for .fdb files (alternate Firebird extension) ---
    Write-Output "--- Alternate DB Files (.fdb) ---"
    $fdbFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in $dbSearchPaths) {
        if (-not (Test-Path $sp)) { continue }
        $found = @(Get-ChildItem -Path $sp -Recurse -Filter "*.fdb" -ErrorAction SilentlyContinue)
        foreach ($f in $found) {
            $fdbFiles.Add($f)
        }
    }
    if ($fdbFiles.Count -gt 0) {
        foreach ($f in $fdbFiles) {
            Write-Output "FOUND: $($f.FullName) ($('{0:N2} MB' -f ($f.Length / 1MB)))"
        }
    } else {
        Write-Output "None found"
    }
    Write-Output ""

    # --- KZSoftware Directory Contents ---
    Write-Output "--- KZ Software Directories ---"
    $kzPaths = @(
        "C:\KZSoftware",
        "D:\KZSoftware",
        "C:\ProgramData\TrainingManager",
        "C:\ProgramData\KZ Software"
    )
    foreach ($kp in $kzPaths) {
        if (Test-Path $kp) {
            Write-Output "FOUND: $kp"
            Get-ChildItem -Path $kp -Recurse -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, LastWriteTime |
                Format-Table -AutoSize | Out-String | Write-Output
        }
    }
    Write-Output ""

    # --- Firebird Client Components ---
    Write-Output "--- Firebird Client Components ---"
    $fbClientPaths = @(
        "$env:ProgramFiles\Firebird",
        "${env:ProgramFiles(x86)}\Firebird",
        "C:\KZSoftware\fbclient.dll",
        "C:\KZSoftware\fbembed.dll"
    )
    foreach ($fcp in $fbClientPaths) {
        if (Test-Path $fcp) {
            Write-Output "FOUND: $fcp"
            if ((Get-Item $fcp).PSIsContainer) {
                Get-ChildItem -Path $fcp -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match '\.(dll|exe|conf|config)$' } |
                    Select-Object FullName, Length |
                    Format-Table -AutoSize | Out-String | Write-Output
            }
        }
    }

    # Check for embedded Firebird DLLs alongside the app
    $fbDlls = @("fbclient.dll", "fbembed.dll", "ib_util.dll", "firebird.msg")
    foreach ($sp in $dbSearchPaths) {
        if (-not (Test-Path $sp)) { continue }
        foreach ($dll in $fbDlls) {
            $dllPath = Join-Path $sp $dll
            if (Test-Path $dllPath) {
                $fi = Get-Item $dllPath
                Write-Output "FOUND: $dllPath ($('{0:N0} KB' -f ($fi.Length / 1KB)))"
            }
        }
    }
    Write-Output ""

    # --- Running Processes ---
    Write-Output "--- Running Processes (Training Manager / Firebird) ---"
    $procs = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match 'Training|Firebird|fbserver|fbguard|KZSoftware' })
    if ($procs.Count -gt 0) {
        foreach ($p in $procs) {
            $path = ""
            try { $path = $p.MainModule.FileName } catch { $path = "(access denied)" }
            Write-Output "RUNNING: $($p.ProcessName) (PID $($p.Id)) - $path"
        }
    } else {
        Write-Output "No Training Manager or Firebird processes running"
    }
    Write-Output ""

    # --- Local Firebird Service ---
    Write-Output "--- Local Firebird Service ---"
    $fbSvc = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Firebird' -or $_.DisplayName -match 'Firebird' })
    if ($fbSvc.Count -gt 0) {
        foreach ($svc in $fbSvc) {
            Write-Output "FOUND: $($svc.DisplayName) ($($svc.Name)) - Status: $($svc.Status)"
        }
    } else {
        Write-Output "No local Firebird service (expected for single-user embedded mode)"
    }
    Write-Output ""

    # --- Config Files ---
    Write-Output "--- Configuration Files ---"
    $configPatterns = @("*.ini", "*.config", "*.cfg", "*.conf")
    foreach ($sp in $dbSearchPaths) {
        if (-not (Test-Path $sp)) { continue }
        foreach ($pat in $configPatterns) {
            $configs = @(Get-ChildItem -Path $sp -Filter $pat -Recurse -ErrorAction SilentlyContinue)
            foreach ($c in $configs) {
                Write-Output "CONFIG: $($c.FullName)"
                $lines = @(Get-Content $c.FullName -TotalCount 20 -ErrorAction SilentlyContinue)
                foreach ($line in $lines) {
                    if ($line.Trim() -and -not $line.Trim().StartsWith('#') -and -not $line.Trim().StartsWith(';')) {
                        Write-Output "  $line"
                    }
                }
                Write-Output ""
            }
        }
    }

    # --- Summary ---
    Write-Output "=== Summary ==="
    Write-Output "Application installed: $(if ($appFound) { 'YES' } else { 'NO' })"
    Write-Output "Database file found: $(if ($dbFound) { 'YES' } else { 'NO' })"

    if ($dbFound) {
        Write-Output "RESULT: Database located. Ready for migration planning."
        exit 0
    } elseif ($appFound) {
        Write-Output "RESULT: App installed but .tdb not found in standard paths. Check app settings for custom DB location."
        exit 112
    } else {
        Write-Output "RESULT: Neither app nor database found. Verify correct target machine."
        exit 1
    }
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "ERROR: Line $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}
