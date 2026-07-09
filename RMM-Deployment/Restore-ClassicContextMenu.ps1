<#
.SYNOPSIS
    Restore classic Windows 10 right-click context menu on Windows 11

.DESCRIPTION
    Sets an empty default value at the InprocServer32 key for CLSID
    {86ca1aa0-34aa-4e8b-a509-50c905bae2a2} under the logged-in user's
    registry hive, which disables the modern Windows 11 context menu
    and restores the classic Windows 10 full context menu.

    Designed for RMM (PowerShell 5.1, SYSTEM context).
    Resolves the logged-in user's SID to write to HKU instead of HKCU.
    Restarts Explorer to apply changes immediately.

.EXAMPLE
    .\Restore-ClassicContextMenu.ps1
    Enables classic context menu for the currently logged-in user

.NOTES
    Category: RMM-Deployment

.KEYWORDS
    context-menu, Windows-11, registry, user-context, RMM, SYSTEM
#>

$ErrorActionPreference = "Stop"

try {
    # Verify Windows 11
    $build = [System.Environment]::OSVersion.Version.Build
    if ($build -lt 22000) {
        Write-Output "SKIP: Not Windows 11 (build $build)"
        exit 0
    }

    # Get logged-in user
    $user = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $user) {
        Write-Output "ERROR: No user logged in"
        exit 1
    }

    $username = $user.Split('\')[-1]
    $domain = $user.Split('\')[0]

    # Resolve SID
    $sid = (New-Object System.Security.Principal.NTAccount($domain, $username)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value

    # Target registry path under user's HKU hive
    $clsid = "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
    $regPath = "Registry::HKU\$sid\Software\Classes\CLSID\$clsid\InprocServer32"

    # Create key if it doesn't exist
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set empty default value (this is what disables the modern menu)
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value "" -Type String

    # Verify
    $check = (Get-ItemProperty -Path $regPath -Name "(Default)")."(Default)"
    if ($check -ne "") {
        Write-Output "ERROR: Registry value not set correctly"
        exit 1
    }

    # Restart Explorer to apply
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Output "SUCCESS: Classic context menu enabled for $user (build $build)"
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
