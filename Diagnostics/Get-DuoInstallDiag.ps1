<#
.SYNOPSIS
    Comprehensive Duo Authentication for Windows Logon installation diagnostic.
.DESCRIPTION
    Consolidates three diagnostic checks into one script:
    1. Installation check -- registry, Add/Remove Programs, service status, DuoCredProv.dll
    2. Commands-tab check -- Duo services, Program Files paths, registry keys, firewall rules
    3. Per-user hive check (when -UserHive is specified) -- HKU Duo registry keys and
       AppData artifacts for the currently logged-in user

    The service check attempts to start DuoAuthService if it is stopped.
    Pass -UserHive to also run the per-user registry section (requires a user to be
    logged in; best run from SYSTEM remote session).
.PARAMETER UserHive
    When specified, resolves the logged-in user's SID and checks Duo registry keys
    and AppData paths in that user's hive. Omit for SYSTEM-only checks.
.EXAMPLE
    .\Get-DuoInstallDiag.ps1
.EXAMPLE
    .\Get-DuoInstallDiag.ps1 -UserHive
.NOTES
    Context:    RMM (SYSTEM) or SYSTEM remote session (SYSTEM)
    Platform:   Windows 10/11, PS 5.1
    Exit codes: 0=All checks passed, 1=Not installed or critical failure,
                112=Installed but partial (service issue or DLL missing)
    PS 5.1 compatible.
.KEYWORDS
    Duo, authentication, windows-logon, service, MFA, DuoCredProv, registry, diagnostic
#>

[CmdletBinding()]
param(
    [switch]$UserHive
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

# ===========================================================================
# SECTION 1: Installation, Service, and DLL Check
# ===========================================================================
Write-Log "=== SECTION 1: DUO INSTALLATION ==="

try {
    $duoInstalled = $false
    $duoVersion   = $null

    $regPaths = @(
        "HKLM:\SOFTWARE\Duo Security\DuoCredProv",
        "HKLM:\SOFTWARE\WOW6432Node\Duo Security\DuoCredProv"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $duoInstalled = $true
            try {
                $ver = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Version
                if ($null -ne $ver) { $duoVersion = $ver }
            }
            catch { }
            break
        }
    }

    if (-not $duoInstalled) {
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($base in $uninstallPaths) {
            if (Test-Path $base) {
                $match = Get-ChildItem -Path $base -ErrorAction SilentlyContinue |
                    Where-Object {
                        $name = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                        $null -ne $name -and $name -like "*Duo Authentication for Windows Logon*"
                    } |
                    Select-Object -First 1

                if ($null -ne $match) {
                    $duoInstalled = $true
                    $props = Get-ItemProperty -Path $match.PSPath -ErrorAction SilentlyContinue
                    if ($null -ne $props.DisplayVersion) { $duoVersion = $props.DisplayVersion }
                    break
                }
            }
            if ($duoInstalled) { break }
        }
    }

    if (-not $duoInstalled) {
        Write-Log "Duo Authentication for Windows Logon: NOT INSTALLED" -Level "ERROR"
        Write-Output "RESULT: Duo Authentication for Windows Logon is not installed."
        exit 1
    }

    $versionDisplay = if ($null -ne $duoVersion) { $duoVersion } else { "unknown" }
    Write-Log "Duo Authentication for Windows Logon: INSTALLED (version: $versionDisplay)"
    Write-Output "RESULT: Duo Authentication for Windows Logon installed. Version: $versionDisplay"

    # Service Check
    $serviceName = "DuoAuthService"
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($null -eq $svc) {
        Write-Log "$serviceName: NOT FOUND on this system" -Level "WARN"
        Write-Output "SERVICE: $serviceName not found on this system."
        $exitCode = 112
    } else {
        Write-Log "$serviceName status: $($svc.Status)"

        if ($svc.Status -eq "Running") {
            Write-Output "SERVICE: $serviceName is running."
            $exitCode = 0
        } else {
            Write-Log "Service is stopped. Attempting to start $serviceName..." -Level "WARN"
            Start-Service -Name $serviceName -ErrorAction Stop
            Start-Sleep -Seconds 5
            $svc.Refresh()
            if ($svc.Status -eq "Running") {
                Write-Log "Service started successfully."
                Write-Output "SERVICE: $serviceName was stopped; started successfully."
                $exitCode = 0
            } else {
                Write-Log "Service failed to reach Running state (current: $($svc.Status))." -Level "ERROR"
                Write-Output "SERVICE: $serviceName start attempted but status is $($svc.Status)."
                $exitCode = 112
            }
        }
    }

    # Credential Provider DLL Check
    $duoDllDir  = "C:\Program Files\Duo Security Authentication for Windows Logon"
    $duoDllPath = Join-Path $duoDllDir "DuoCredProv.dll"

    if (-not (Test-Path $duoDllDir)) {
        Write-Log "Duo install directory not found: $duoDllDir" -Level "ERROR"
        Write-Output "DLL CHECK: Install directory missing -- $duoDllDir"
        $exitCode = 1
    } elseif (Test-Path $duoDllPath) {
        $dllItem    = Get-Item -Path $duoDllPath -ErrorAction SilentlyContinue
        $dllVersion = if ($null -ne $dllItem) { $dllItem.VersionInfo.FileVersion } else { "unknown" }
        Write-Log "DuoCredProv.dll FOUND (file version: $dllVersion)"
        Write-Output "DLL CHECK: DuoCredProv.dll present. File version: $dllVersion"
    } else {
        Write-Log "DuoCredProv.dll NOT FOUND in $duoDllDir" -Level "WARN"
        Write-Output "DLL CHECK: DuoCredProv.dll missing from $duoDllDir -- reinstall recommended."
        $exitCode = 112
    }

} catch {
    Write-Log "Section 1 error: $($_.Exception.Message)" -Level "ERROR"
    $exitCode = 1
}

# ===========================================================================
# SECTION 2: Services, Paths, Registry, and Firewall (Commands-tab style)
# ===========================================================================
Write-Log "=== SECTION 2: DUO SERVICES AND PATHS ==="

try {
    Write-Output "=== Duo Services ==="
    $duoServices = Get-Service | Where-Object { $_.DisplayName -like "*Duo*" -or $_.Name -like "*Duo*" }
    if ($duoServices) {
        $duoServices | Select-Object Name, DisplayName, Status, StartType | Format-List
    } else {
        Write-Output "No Duo services found."
    }

    Write-Output "=== Duo Program Files ==="
    $paths = @(
        "C:\Program Files\Duo Security",
        "C:\Program Files (x86)\Duo Security",
        "C:\Program Files\Duo Authentication for Windows Logon",
        "C:\Program Files (x86)\Duo Authentication for Windows Logon"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-Output "EXISTS: $path"
            Get-ChildItem $path -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime | Format-List
        } else {
            Write-Output "NOT FOUND: $path"
        }
    }

    Write-Output "=== Duo Registry ==="
    $regPaths = @(
        "HKLM:\SOFTWARE\Duo Security",
        "HKLM:\SOFTWARE\WOW6432Node\Duo Security"
    )
    foreach ($reg in $regPaths) {
        if (Test-Path $reg) {
            Write-Output "EXISTS: $reg"
            Get-ItemProperty $reg -ErrorAction SilentlyContinue | Format-List
        } else {
            Write-Output "NOT FOUND: $reg"
        }
    }

    Write-Output "=== Duo Firewall Rules ==="
    $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*Duo*" -or $_.Name -like "*Duo*"
    }
    if ($fwRules) {
        $fwRules | Select-Object DisplayName, Name, Direction, Action, Enabled, Profile | Format-List
    } else {
        Write-Output "No Duo-related firewall rules found."
    }
} catch {
    Write-Log "Section 2 error: $($_.Exception.Message)" -Level "WARN"
}

# ===========================================================================
# SECTION 3: Per-User Hive Check (optional, requires logged-in user)
# ===========================================================================
if ($UserHive) {
    Write-Log "=== SECTION 3: PER-USER DUO REGISTRY ==="

    try {
        $user = (Get-CimInstance Win32_ComputerSystem).UserName
        if (-not $user) {
            Write-Host "ERROR: No user is logged in -- skipping user hive check."
        } else {
            $username = $user.Split('\')[-1]
            $domain   = $user.Split('\')[0]
            $sid = (New-Object System.Security.Principal.NTAccount($domain, $username)).Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
            $userProfile = (Get-CimInstance Win32_UserProfile |
                Where-Object { $_.SID -eq $sid }).LocalPath

            Write-Host "Target user : $user"
            Write-Host "SID         : $sid"
            Write-Host "Profile     : $userProfile"
            Write-Host "---"

            $duoPaths = @(
                "Registry::HKU\$sid\SOFTWARE\Duo Security",
                "Registry::HKU\$sid\SOFTWARE\Duo Security\DuoCredProv",
                "Registry::HKU\$sid\SOFTWARE\Duo Security\MSP",
                "Registry::HKU\$sid\SOFTWARE\Duo Security\Policies",
                "Registry::HKU\$sid\SOFTWARE\Policies\Duo Security",
                "Registry::HKU\$sid\SOFTWARE\WOW6432Node\Duo Security"
            )

            $foundAny = $false

            foreach ($path in $duoPaths) {
                if (Test-Path $path) {
                    $foundAny = $true
                    Write-Host ""
                    Write-Host "KEY: $path"

                    $values = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($values) {
                        $values.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS' } |
                            ForEach-Object {
                                Write-Host ("  {0,-35} = {1}" -f $_.Name, $_.Value)
                            }
                    } else {
                        Write-Host "  (key exists but no values)"
                    }

                    $subkeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                    if ($subkeys) {
                        foreach ($sub in $subkeys) {
                            Write-Host ""
                            Write-Host "  SUBKEY: $($sub.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','')"
                            $subValues = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                            if ($subValues) {
                                $subValues.PSObject.Properties |
                                    Where-Object { $_.Name -notmatch '^PS' } |
                                    ForEach-Object {
                                        Write-Host ("    {0,-33} = {1}" -f $_.Name, $_.Value)
                                    }
                            } else {
                                Write-Host "    (no values)"
                            }
                        }
                    }
                } else {
                    Write-Host "NOT FOUND : $path"
                }
            }

            Write-Host ""
            if ($foundAny) {
                Write-Host "Duo registry keys found in user hive. Review values above."
            } else {
                Write-Host "No Duo registry keys found under user hive."
            }
            Write-Host "---"

            # AppData file check
            Write-Host ""
            Write-Host "=== Duo AppData File Check ==="

            $appDataPaths = @(
                (Join-Path $userProfile "AppData\Roaming\Duo Security"),
                (Join-Path $userProfile "AppData\Roaming\Duo"),
                (Join-Path $userProfile "AppData\Local\Duo Security"),
                (Join-Path $userProfile "AppData\Local\Duo"),
                (Join-Path $userProfile "AppData\LocalLow\Duo Security"),
                (Join-Path $userProfile "AppData\LocalLow\Duo")
            )

            $foundAnyFiles = $false

            foreach ($appPath in $appDataPaths) {
                if (Test-Path $appPath) {
                    $foundAnyFiles = $true
                    Write-Host ""
                    Write-Host "FOUND: $appPath"
                    $items = Get-ChildItem -Path $appPath -Recurse -ErrorAction SilentlyContinue
                    if ($items) {
                        foreach ($item in $items) {
                            $type = if ($item.PSIsContainer) { "[DIR] " } else { "[FILE]" }
                            Write-Host ("  $type $($item.FullName)")
                        }
                    } else {
                        Write-Host "  (folder exists but is empty)"
                    }
                } else {
                    Write-Host "NOT FOUND : $appPath"
                }
            }

            Write-Host ""
            if ($foundAnyFiles) {
                Write-Host "Duo AppData artifacts found. Review paths above."
            } else {
                Write-Host "No Duo AppData folders found under user profile."
            }
            Write-Host "---"
        }
    } catch {
        Write-Log "Section 3 error: $($_.Exception.Message)" -Level "WARN"
    }
}

Write-Log "All checks completed."
exit $exitCode
