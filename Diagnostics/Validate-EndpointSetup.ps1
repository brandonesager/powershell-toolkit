<#
.SYNOPSIS
    Validates post-setup items on a newly provisioned endpoint.
.DESCRIPTION
    Runs a checklist of required apps and standard setup items, reporting PASS/FAIL
    per item with supporting detail. Checks:
    1. Required apps from -RequiredApps (Program Files, AppData, and registry)
    2. Adobe Acrobat Pro installation and activation evidence
    3. Duo Authentication for Windows Logon installation and credential provider
    4. Printers (system-level and per-user network connections)
    5. Outlook email signatures (per user profile)

    Runs as SYSTEM via RMM and iterates user profiles for per-user checks.
.PARAMETER RequiredApps
    Array of application display-name substrings to check in Program Files,
    per-user AppData\Local, and the registry uninstall hives.
    Default: @('Dialpad')
.EXAMPLE
    .\Validate-EndpointSetup.ps1
.EXAMPLE
    .\Validate-EndpointSetup.ps1 -RequiredApps @('Dialpad','Zoom','Webex')
.NOTES
    Context:    SYSTEM (RMM)
    Platform:   Windows 10/11, PS 5.1
.KEYWORDS
    endpoint, setup, validation, checklist, onboarding, Duo, Adobe, Acrobat, signatures
#>

[CmdletBinding()]
param(
    [string[]]$RequiredApps = @('Dialpad')
)

$ErrorActionPreference = "Continue"

# --- Helpers ---

function Write-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail = ""
    )
    $prefix = switch ($Status) {
        "PASS" { "[PASS]" }
        "FAIL" { "[FAIL]" }
        "INFO" { "[INFO]" }
        "WARN" { "[WARN]" }
        default { "[----]" }
    }
    if ($Detail) {
        Write-Output "$prefix $Name -- $Detail"
    } else {
        Write-Output "$prefix $Name"
    }
}

function Get-UserProfiles {
    $excludeNames = @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0', 'Administrator')
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $excludeNames -notcontains $_.Name -and $_.Name -notmatch '^(systemprofile|LocalService|NetworkService)$' }
    return $profiles
}

# --- Header ---

Write-Output "============================================"
Write-Output "  ENDPOINT SETUP VALIDATION"
Write-Output "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "  Host: $env:COMPUTERNAME"
Write-Output "============================================"
Write-Output ""

# =============================================
# 1. REQUIRED APPS
# =============================================
Write-Output "--- 1. REQUIRED APPS ---"

$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($appName in $RequiredApps) {
    $appFound = $false
    $appDetail = ""

    # Check Program Files
    $pfPaths = @(
        "$env:ProgramFiles\$appName",
        "${env:ProgramFiles(x86)}\$appName"
    )
    foreach ($path in $pfPaths) {
        if (Test-Path $path) {
            $appFound = $true
            $appDetail = "Found at $path"
            break
        }
    }

    # Check per-user AppData
    if (-not $appFound) {
        $userProfiles = Get-UserProfiles
        foreach ($profile in $userProfiles) {
            $userPath = Join-Path $profile.FullName "AppData\Local\$appName"
            if (Test-Path $userPath) {
                $appFound = $true
                $appDetail = "Per-user install: $userPath"
                break
            }
        }
    }

    # Check HKLM registry
    if (-not $appFound) {
        foreach ($regPath in $uninstallPaths) {
            $match = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*$appName*" }
            if ($match) {
                $appFound = $true
                $ver = if ($match.DisplayVersion) { $match.DisplayVersion } else { "unknown" }
                $appDetail = "Registry: $($match.DisplayName) v$ver"
                break
            }
        }
    }

    # Check per-user registry hives
    if (-not $appFound) {
        try {
            $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
            foreach ($sid in $sids) {
                $userUninstall = "Registry::$($sid.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                $match = Get-ItemProperty $userUninstall -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*$appName*" }
                if ($match) {
                    $appFound = $true
                    $ver = if ($match.DisplayVersion) { $match.DisplayVersion } else { "unknown" }
                    $appDetail = "Per-user registry: $($match.DisplayName) v$ver (SID: $($sid.PSChildName))"
                    break
                }
            }
        } catch { }
    }

    if ($appFound) {
        Write-Check "$appName installed" "PASS" $appDetail
    } else {
        Write-Check "$appName installed" "FAIL" "Not found in Program Files, AppData, or registry"
    }
}
Write-Output ""

# =============================================
# 2. ADOBE ACROBAT PRO ACTIVATED
# =============================================
Write-Output "--- 2. ADOBE ACROBAT PRO ---"

$acrobatInstalled = $false
$acrobatActivated = $false
$acrobatName = ""
$acrobatVersion = ""

foreach ($regPath in $uninstallPaths) {
    $match = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Adobe Acrobat" -and $_.DisplayName -notmatch "Reader" }
    if ($match) {
        if ($match -is [array]) { $match = $match[0] }
        $acrobatInstalled = $true
        $acrobatName = $match.DisplayName
        $acrobatVersion = $match.DisplayVersion
        break
    }
}

if ($acrobatInstalled) {
    Write-Check "Adobe Acrobat Pro installed" "PASS" "$acrobatName v$acrobatVersion"

    $activationChecks = @()

    $acrobatRegPaths = @(
        "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Registration",
        "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2020\Registration",
        "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2017\Registration",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Registration",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\2020\Registration"
    )
    foreach ($regKey in $acrobatRegPaths) {
        if (Test-Path $regKey) {
            $reg = Get-ItemProperty $regKey -ErrorAction SilentlyContinue
            if ($reg.SERIAL -and $reg.SERIAL -ne "" -and $reg.SERIAL -ne "0") {
                $activationChecks += "Serial found in registry"
                $acrobatActivated = $true
            }
        }
    }

    $adobeLicPaths = @(
        "$env:ProgramData\Adobe\Adobe Acrobat\Licensing",
        "$env:ProgramData\Adobe\Licensing"
    )
    foreach ($licPath in $adobeLicPaths) {
        if (Test-Path $licPath) {
            $licFiles = Get-ChildItem $licPath -Recurse -File -ErrorAction SilentlyContinue
            if ($licFiles.Count -gt 0) {
                $activationChecks += "Licensing cache present ($($licFiles.Count) files in $licPath)"
                $acrobatActivated = $true
            }
        }
    }

    $oobeDir = "$env:ProgramData\Adobe\OOBE"
    if (Test-Path $oobeDir) {
        $oobeFiles = Get-ChildItem $oobeDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'opm\.db|operatingconfigs' }
        if ($oobeFiles.Count -gt 0) {
            $activationChecks += "OOBE activation data present"
            $acrobatActivated = $true
        }
    }

    $nglPath = "$env:ProgramData\Adobe\Licensing\NGL"
    if (Test-Path $nglPath) {
        $nglFiles = Get-ChildItem $nglPath -Recurse -File -ErrorAction SilentlyContinue
        if ($nglFiles.Count -gt 0) {
            $activationChecks += "NGL licensing profile present ($($nglFiles.Count) files)"
            $acrobatActivated = $true
        }
    }

    if ($acrobatActivated) {
        Write-Check "Adobe Acrobat Pro activated" "PASS" ($activationChecks -join "; ")
    } else {
        Write-Check "Adobe Acrobat Pro activated" "WARN" "Installed but no activation evidence found -- verify manually"
    }
} else {
    Write-Check "Adobe Acrobat Pro installed" "FAIL" "Not found (only Reader, or not installed)"
    Write-Check "Adobe Acrobat Pro activated" "FAIL" "N/A -- not installed"
}
Write-Output ""

# =============================================
# 3. DUO SECURITY ENROLLED
# =============================================
Write-Output "--- 3. DUO SECURITY ---"

$duoFound = $false
$duoDetail = ""

foreach ($regPath in $uninstallPaths) {
    $match = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Duo*" -and $_.DisplayName -like "*Windows*Logon*" }
    if ($match) {
        if ($match -is [array]) { $match = $match[0] }
        $duoFound = $true
        $ver = if ($match.DisplayVersion) { $match.DisplayVersion } else { "unknown" }
        $duoDetail = "$($match.DisplayName) v$ver"
        break
    }
}

if (-not $duoFound) {
    foreach ($regPath in $uninstallPaths) {
        $match = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Duo Authentication*" -or $_.DisplayName -like "*Duo Security*" }
        if ($match) {
            if ($match -is [array]) { $match = $match[0] }
            $duoFound = $true
            $ver = if ($match.DisplayVersion) { $match.DisplayVersion } else { "unknown" }
            $duoDetail = "$($match.DisplayName) v$ver"
            break
        }
    }
}

if (-not $duoFound) {
    $duoPaths = @(
        "$env:ProgramFiles\Duo Security",
        "${env:ProgramFiles(x86)}\Duo Security"
    )
    foreach ($path in $duoPaths) {
        if (Test-Path $path) {
            $duoFound = $true
            $duoDetail = "Found at $path"
            break
        }
    }
}

$duoCP = $false
$credProvPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
if (Test-Path $credProvPath) {
    $providers = Get-ChildItem $credProvPath -ErrorAction SilentlyContinue
    foreach ($prov in $providers) {
        $defaultVal = (Get-ItemProperty "Registry::$($prov.Name)" -ErrorAction SilentlyContinue).'(default)'
        if ($defaultVal -like "*Duo*") {
            $duoCP = $true
            break
        }
    }
}

if ($duoFound) {
    $cpStatus = if ($duoCP) { "credential provider registered" } else { "credential provider NOT registered" }
    Write-Check "Duo Authentication installed" "PASS" "$duoDetail ($cpStatus)"
} else {
    Write-Check "Duo Authentication installed" "FAIL" "Not found in registry or Program Files"
}

$duoConfigPath = "HKLM:\SOFTWARE\Duo Security\DuoCredProv"
if (Test-Path $duoConfigPath) {
    $duoConfig = Get-ItemProperty $duoConfigPath -ErrorAction SilentlyContinue
    $hasHost = [bool]$duoConfig.ApiHostname
    $hasIkey = [bool]$duoConfig.IntegrationKey
    if ($hasHost -and $hasIkey) {
        Write-Check "Duo configured" "PASS" "API host and integration key present"
    } elseif ($hasHost -or $hasIkey) {
        Write-Check "Duo configured" "WARN" "Partial config -- missing $(if (-not $hasHost) {'API host'} else {'integration key'})"
    } else {
        Write-Check "Duo configured" "WARN" "Registry key exists but no API config found"
    }
} elseif ($duoFound) {
    Write-Check "Duo configured" "WARN" "Installed but DuoCredProv registry key missing -- may need configuration"
}
Write-Output ""

# =============================================
# 4. PRINTERS MAPPED
# =============================================
Write-Output "--- 4. PRINTERS ---"

try {
    $printers = Get-Printer -ErrorAction Stop
    $printerCount = ($printers | Measure-Object).Count
    if ($printerCount -gt 0) {
        Write-Check "Printers found" "INFO" "$printerCount printer(s) on this system"
        Write-Output ""
        foreach ($p in $printers) {
            $type = switch -Wildcard ($p.PortName) {
                "\\*"    { "Network" }
                "*IP*"   { "TCP/IP" }
                "WSD*"   { "WSD" }
                "USB*"   { "USB" }
                "PORTPROMPT*" { "Virtual" }
                "nul*"   { "Virtual" }
                default  { "Other" }
            }
            Write-Output "    Printer: $($p.Name)"
            Write-Output "      Driver: $($p.DriverName)"
            Write-Output "      Port:   $($p.PortName) ($type)"
            Write-Output "      Status: $($p.PrinterStatus)"
            Write-Output ""
        }
    } else {
        Write-Check "Printers found" "WARN" "No printers detected"
    }
} catch {
    Write-Check "Printers (Get-Printer)" "WARN" "Get-Printer failed: $($_.Exception.Message)"

    try {
        $wmiPrinters = Get-WmiObject -Class Win32_Printer -ErrorAction Stop
        $wmiCount = ($wmiPrinters | Measure-Object).Count
        Write-Check "Printers found (WMI fallback)" "INFO" "$wmiCount printer(s)"
        foreach ($wp in $wmiPrinters) {
            Write-Output "    Printer: $($wp.Name)"
            Write-Output "      Driver: $($wp.DriverName)"
            Write-Output "      Port:   $($wp.PortName)"
            Write-Output ""
        }
    } catch {
        Write-Check "Printers (WMI fallback)" "FAIL" "WMI query failed: $($_.Exception.Message)"
    }
}

Write-Output "  Per-User Network Printers:"
$foundUserPrinters = $false
try {
    $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
    foreach ($sid in $sids) {
        $printerConns = "Registry::$($sid.Name)\Printers\Connections"
        if (Test-Path $printerConns) {
            $conns = Get-ChildItem $printerConns -ErrorAction SilentlyContinue
            if ($conns) {
                try {
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)
                    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                    $userName = $objUser.Value
                } catch {
                    $userName = $sid.PSChildName
                }
                Write-Output "    User: $userName"
                foreach ($conn in $conns) {
                    $printerPath = $conn.PSChildName -replace ',', '\'
                    Write-Output "      -> \\$printerPath"
                }
                $foundUserPrinters = $true
                Write-Output ""
            }
        }
    }
} catch {
    Write-Output "    Could not enumerate user printer connections: $($_.Exception.Message)"
}
if (-not $foundUserPrinters) {
    Write-Output "    No per-user network printer connections found in loaded registry hives"
}
Write-Output ""

# =============================================
# 5. EMAIL SIGNATURE APPLIED
# =============================================
Write-Output "--- 5. EMAIL SIGNATURES ---"

$userProfiles = Get-UserProfiles
$anySignatureFound = $false

if ($userProfiles.Count -eq 0) {
    Write-Check "Email signatures" "WARN" "No user profiles found under C:\Users"
} else {
    foreach ($profile in $userProfiles) {
        $sigPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Signatures"
        $userName = $profile.Name

        if (Test-Path $sigPath) {
            $sigFiles = Get-ChildItem $sigPath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '\.(htm|html|rtf|txt)$' }

            if ($sigFiles.Count -gt 0) {
                $sigNames = $sigFiles | ForEach-Object {
                    $_.BaseName
                } | Sort-Object -Unique

                $anySignatureFound = $true
                Write-Check "Signatures for $userName" "PASS" "$($sigNames.Count) signature(s) found"
                foreach ($sigName in $sigNames) {
                    $formats = $sigFiles | Where-Object { $_.BaseName -eq $sigName } |
                        ForEach-Object { $_.Extension.TrimStart('.') }
                    Write-Output "      Name: $sigName (formats: $($formats -join ', '))"
                }

                try {
                    $sids = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
                    foreach ($sid in $sids) {
                        $profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($sid.PSChildName)"
                        if (Test-Path $profileListKey) {
                            $profilePath = (Get-ItemProperty $profileListKey -ErrorAction SilentlyContinue).ProfileImagePath
                            if ($profilePath -and $profilePath -like "*\$userName") {
                                $mailSettings = "Registry::$($sid.Name)\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings"
                                if (Test-Path $mailSettings) {
                                    $ms = Get-ItemProperty $mailSettings -ErrorAction SilentlyContinue
                                    $newSig = $ms.NewSignature
                                    $replySig = $ms.ReplySignature
                                    if ($newSig) {
                                        Write-Output "      Default (new): $newSig"
                                    }
                                    if ($replySig) {
                                        Write-Output "      Default (reply): $replySig"
                                    }
                                }
                                break
                            }
                        }
                    }
                } catch { }
            } else {
                Write-Check "Signatures for $userName" "FAIL" "Signatures folder exists but contains no signature files"
            }
        } else {
            Write-Check "Signatures for $userName" "FAIL" "No Signatures folder at $sigPath"
        }
        Write-Output ""
    }

    if (-not $anySignatureFound) {
        Write-Check "Email signatures" "FAIL" "No signatures found for any user profile"
    }
}

# --- Footer ---
Write-Output "============================================"
Write-Output "  Validation complete at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "============================================"
