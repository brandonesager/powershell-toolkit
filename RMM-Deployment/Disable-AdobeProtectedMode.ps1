<#
.SYNOPSIS
    Disable Adobe Acrobat/Reader Protected Mode for printing troubleshooting.

.DESCRIPTION
    Disables Protected Mode in Adobe Acrobat/Reader (all versions) by setting
    the bProtectedMode registry value to 0 in the logged-in user's HKCU hive.

    Protected Mode sandboxing can interfere with printer drivers, especially
    with Konica and Kyocera printers. This is a common fix for PDF printing
    stuck at 0% progress with no error message.

    Supports: Acrobat DC, Reader DC, Acrobat 2020, Acrobat 2015

    Designed for RMM (PowerShell 5.1, SYSTEM context).

.EXAMPLE
    Deploy via RMM to target workstation

.NOTES
    Date: 2026-02-13
#>

# CONTEXT: RMM
# EXIT: 0=success, 1=failure (no user or no Adobe found), 112=partial (some apps modified)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

try {
    Write-Log "=== Disable Adobe Protected Mode Started ===" -Level "INFO"

    # Get logged-in user context
    Write-Log "Resolving logged-in user..." -Level "INFO"
    $loggedOnUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName

    if (-not $loggedOnUser) {
        Write-Log "ERROR: No user currently logged in - cannot modify user registry" -Level "ERROR"
        exit 1
    }

    Write-Log "Logged-in user: $loggedOnUser" -Level "INFO"

    # Resolve user SID
    $username = $loggedOnUser.Split('\')[-1]
    $domain = $loggedOnUser.Split('\')[0]
    $userSID = (New-Object System.Security.Principal.NTAccount($domain, $username)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    Write-Log "User SID: $userSID" -Level "INFO"

    # Mount HKU if not available
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        Write-Log "Mounted HKU registry drive" -Level "INFO"
    }

    $appsModified = @()
    $appsNotFound = @()

    # Define registry paths for all Adobe versions
    $adobeApps = @(
        @{Name="Acrobat DC"; RegPath="HKU:\$userSID\Software\Adobe\Adobe Acrobat\DC\Privileged"; InstallCheck="HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer"},
        @{Name="Reader DC"; RegPath="HKU:\$userSID\Software\Adobe\Acrobat Reader\DC\Privileged"; InstallCheck="HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer"},
        @{Name="Acrobat 2020"; RegPath="HKU:\$userSID\Software\Adobe\Adobe Acrobat\2020\Privileged"; InstallCheck="HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2020\Installer"},
        @{Name="Acrobat 2015"; RegPath="HKU:\$userSID\Software\Adobe\Adobe Acrobat\2015\Privileged"; InstallCheck="HKLM:\SOFTWARE\Adobe\Adobe Acrobat\2015\Installer"}
    )

    foreach ($app in $adobeApps) {
        Write-Log "" -Level "INFO"
        Write-Log "Checking $($app.Name)..." -Level "INFO"

        # Check if Adobe app is installed
        $appInstalled = Test-Path $app.InstallCheck -ErrorAction SilentlyContinue

        if ($appInstalled) {
            Write-Log "$($app.Name) detected" -Level "INFO"

            # Create registry path if it doesn't exist
            if (-not (Test-Path $app.RegPath)) {
                Write-Log "Creating registry path: $($app.RegPath)" -Level "INFO"
                New-Item -Path $app.RegPath -Force | Out-Null
            }

            # Set bProtectedMode to 0 (disabled)
            Set-ItemProperty -Path $app.RegPath -Name "bProtectedMode" -Value 0 -Type DWord -Force
            Write-Log "SUCCESS: $($app.Name) Protected Mode DISABLED" -Level "INFO"

            # Verify the change
            $verifyValue = (Get-ItemProperty -Path $app.RegPath -Name "bProtectedMode" -ErrorAction SilentlyContinue).bProtectedMode
            if ($verifyValue -eq 0) {
                Write-Log "Verified: bProtectedMode = 0" -Level "INFO"
                $appsModified += $app.Name
            } else {
                Write-Log "WARNING: Failed to verify registry change" -Level "WARN"
            }
        } else {
            Write-Log "$($app.Name) not installed on this system" -Level "INFO"
            $appsNotFound += $app.Name
        }
    }

    # === SUMMARY ===
    Write-Log "" -Level "INFO"
    Write-Log "=== Summary ===" -Level "INFO"

    if ($appsModified.Count -gt 0) {
        Write-Log "Protected Mode disabled for: $($appsModified -join ', ')" -Level "INFO"
    }

    if ($appsNotFound.Count -gt 0) {
        Write-Log "Not installed: $($appsNotFound -join ', ')" -Level "INFO"
    }

    Write-Log "" -Level "INFO"
    Write-Log "IMPORTANT: User must close and reopen Adobe applications for changes to take effect" -Level "WARN"
    Write-Log "" -Level "INFO"
    Write-Log "Next steps:" -Level "INFO"
    Write-Log "1. Close all Adobe Acrobat/Reader windows" -Level "INFO"
    Write-Log "2. Open a PDF and test printing to printer" -Level "INFO"
    Write-Log "3. If issue persists, proceed with driver reinstall or preferences reset" -Level "INFO"

    Write-Log "" -Level "INFO"
    Write-Log "=== Script Complete ===" -Level "INFO"

    # Determine exit code
    if ($appsModified.Count -gt 0 -and $appsNotFound.Count -eq 0) {
        # All detected apps modified
        exit 0
    } elseif ($appsModified.Count -gt 0 -and $appsNotFound.Count -gt 0) {
        # Some apps modified, some not found
        exit 112
    } elseif ($appsModified.Count -eq 0 -and $appsNotFound.Count -gt 0) {
        # No Adobe apps found at all
        Write-Log "ERROR: No Adobe Acrobat or Reader installations found" -Level "ERROR"
        exit 1
    } else {
        # Shouldn't reach here, but handle gracefully
        exit 1
    }

} catch {
    Write-Log "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
