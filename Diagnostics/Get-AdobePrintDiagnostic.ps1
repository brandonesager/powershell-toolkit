<#
.SYNOPSIS
    Diagnose Adobe Acrobat print issues

.DESCRIPTION
    Gathers diagnostic information for Adobe Acrobat print hang/loop issues.
    Checks: Adobe installation, version, print spooler, stuck jobs, user prefs, Protected Mode setting.
    Designed for RMM (PowerShell 5.1, SYSTEM context).

.EXAMPLE
    .\Get-AdobePrintDiagnostic.ps1

.NOTES
    Date: 2026-02-13
#>

# CONTEXT: RMM
# EXIT: 0=success, 1=failure

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

try {
    $results = @{
        Hostname = $env:COMPUTERNAME
        Timestamp = (Get-Date).ToString('o')
        AdobeInstalled = $false
        AdobeVersion = $null
        AdobePath = $null
        PrintSpoolerStatus = $null
        StuckPrintJobs = @()
        LoggedInUser = $null
        UserPrefsPath = $null
        UserPrefsExists = $false
        ProtectedModeRegistry = $null
        Recommendations = @()
    }

    Write-Log "=== Adobe Acrobat Print Diagnostic ==="
    Write-Log "Hostname: $($results.Hostname)"

    # Get logged-in user
    $userObj = Get-WmiObject -Class Win32_ComputerSystem
    $loggedInUser = $userObj.UserName
    if ($loggedInUser) {
        $results.LoggedInUser = $loggedInUser
        Write-Log "Logged-in user: $loggedInUser"

        # Get user SID for registry access
        $username = $loggedInUser.Split('\')[-1]
        $domain = $loggedInUser.Split('\')[0]
        $userAccount = New-Object System.Security.Principal.NTAccount($domain, $username)
        try {
            $userSID = $userAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            Write-Log "User SID: $userSID"
        } catch {
            Write-Log "Could not resolve user SID" "WARN"
            $userSID = $null
        }

        # Build user AppData path
        $userProfile = (Get-WmiObject Win32_UserProfile | Where-Object { $_.SID -eq $userSID }).LocalPath
        if ($userProfile) {
            $results.UserPrefsPath = Join-Path $userProfile "AppData\Roaming\Adobe\Acrobat\2020"
            $results.UserPrefsExists = Test-Path $results.UserPrefsPath
            Write-Log "User prefs path: $($results.UserPrefsPath)"
            Write-Log "Prefs folder exists: $($results.UserPrefsExists)"
        }

        # Check Protected Mode registry setting
        if ($userSID) {
            $protectedModeKey = "Registry::HKEY_USERS\$userSID\Software\Adobe\Acrobat Reader\2020\Privileged"
            $protectedModeKey2 = "Registry::HKEY_USERS\$userSID\Software\Adobe\Adobe Acrobat\2020\Privileged"

            foreach ($key in @($protectedModeKey, $protectedModeKey2)) {
                if (Test-Path $key) {
                    try {
                        $bProtectedMode = Get-ItemProperty -Path $key -Name "bProtectedMode" -ErrorAction SilentlyContinue
                        if ($null -ne $bProtectedMode) {
                            $results.ProtectedModeRegistry = $bProtectedMode.bProtectedMode
                            Write-Log "Protected Mode registry value: $($results.ProtectedModeRegistry) (0=disabled, 1=enabled)"
                        }
                    } catch {
                        Write-Log "Could not read Protected Mode setting" "WARN"
                    }
                    break
                }
            }
        }
    } else {
        Write-Log "No user currently logged in" "WARN"
    }

    # Check Adobe installation
    Write-Log "Checking Adobe installation..."
    $adobePaths = @(
        "C:\Program Files\Adobe\Acrobat 2020\Acrobat\Acrobat.exe",
        "C:\Program Files (x86)\Adobe\Acrobat 2020\Acrobat\Acrobat.exe",
        "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
    )

    foreach ($path in $adobePaths) {
        if (Test-Path $path) {
            $results.AdobeInstalled = $true
            $results.AdobePath = $path
            $fileInfo = Get-Item $path
            $results.AdobeVersion = $fileInfo.VersionInfo.ProductVersion
            Write-Log "Adobe found: $path"
            Write-Log "Version: $($results.AdobeVersion)"
            break
        }
    }

    if (-not $results.AdobeInstalled) {
        # Try registry
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($regPath in $uninstallPaths) {
            $adobe = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Adobe Acrobat*2020*" -or $_.DisplayName -like "*Adobe Acrobat*DC*" }
            if ($adobe) {
                $results.AdobeInstalled = $true
                $results.AdobeVersion = $adobe.DisplayVersion
                $results.AdobePath = $adobe.InstallLocation
                Write-Log "Adobe found via registry: $($adobe.DisplayName)"
                Write-Log "Version: $($results.AdobeVersion)"
                break
            }
        }
    }

    if (-not $results.AdobeInstalled) {
        Write-Log "Adobe Acrobat 2020/DC not found" "WARN"
    }

    # Check Print Spooler
    Write-Log "Checking Print Spooler service..."
    $spooler = Get-Service -Name Spooler
    $results.PrintSpoolerStatus = $spooler.Status.ToString()
    Write-Log "Print Spooler status: $($results.PrintSpoolerStatus)"

    # Check for stuck print jobs
    Write-Log "Checking for stuck print jobs..."
    try {
        $printJobs = Get-WmiObject -Class Win32_PrintJob -ErrorAction SilentlyContinue
        if ($printJobs) {
            foreach ($job in $printJobs) {
                $jobInfo = @{
                    Document = $job.Document
                    Owner = $job.Owner
                    Printer = $job.Name.Split(',')[0]
                    Status = $job.Status
                    Size = $job.Size
                }
                $results.StuckPrintJobs += $jobInfo
                Write-Log "Stuck job: $($job.Document) on $($jobInfo.Printer)" "WARN"
            }
        }
        Write-Log "Stuck print jobs found: $($results.StuckPrintJobs.Count)"
    } catch {
        Write-Log "Could not enumerate print jobs: $($_.Exception.Message)" "WARN"
    }

    # Check spooler folder for orphaned files
    $spoolerPath = "$env:SystemRoot\System32\spool\PRINTERS"
    $spoolerFiles = Get-ChildItem -Path $spoolerPath -ErrorAction SilentlyContinue
    if ($spoolerFiles) {
        Write-Log "Orphaned spooler files: $($spoolerFiles.Count)" "WARN"
    }

    # Generate recommendations
    Write-Log "=== Recommendations ==="

    if ($results.StuckPrintJobs.Count -gt 0 -or $spoolerFiles) {
        $results.Recommendations += "Clear print spooler (stuck jobs or orphaned files detected)"
        Write-Log "RECOMMEND: Clear print spooler"
    }

    if ($results.ProtectedModeRegistry -eq 1 -or $null -eq $results.ProtectedModeRegistry) {
        $results.Recommendations += "Disable Protected Mode in Adobe preferences"
        Write-Log "RECOMMEND: Disable Protected Mode"
    }

    if ($results.UserPrefsExists) {
        $results.Recommendations += "Consider resetting Adobe preferences folder if issue persists"
        Write-Log "RECOMMEND: Reset Adobe prefs if needed"
    }

    if ($results.AdobeVersion -like "2025.001.20744*") {
        $results.Recommendations += "CRITICAL: Adobe version 2025.001.20744 has known print bug - rollback or use Print as Image"
        Write-Log "CRITICAL: Known buggy Adobe version detected!" "WARN"
    }

    # Output JSON for parsing
    Write-Output "=== JSON OUTPUT ==="
    Write-Output ($results | ConvertTo-Json -Depth 3)

    Write-Log "=== Diagnostic Complete ==="
    exit 0

} catch {
    Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
