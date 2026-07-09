<#
.SYNOPSIS
    Full removal (nuke) of the RMM (ITSPlatform/SAAZ) agent from an endpoint.

.DESCRIPTION
    Stops and deletes all SAAZ/ITSPlatform services, removes primary registry keys,
    removes install directories and ProgramData remnants, removes the self-heal
    scheduled task, and clears stale Windows Installer product registration.
    Registry-based MSI scan avoids Win32_Product (repair trigger).

    Run this before installing a fresh agent from the RMM portal.
    Set RMM job timeout to 300 seconds minimum (msiexec /x can take 60-90s).

    Exit 0 — nuke complete, no remnants.
    Exit 112 — nuke complete with warnings; review output before reinstalling.

.NOTES
    Context:  RMM (SYSTEM, PS 5.1)
    Platform: Windows 10/11/Server 2019+
    PS 5.1 compatible.

.KEYWORDS
    CWR-AGT-001, ITSPlatform, SAAZ, RMM, agent repair, nuke reinstall
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# Step 1 -- Stop and delete all SAAZ/ITS services
Write-Output "=== Step 1: Stopping and deleting services ==="
$services = @('SAAZappr','SAAZDPMACTL','SAAZRemoteSupport','SAAZScheduler','SAAZServerPlus','SAAZWatchDog','ITSPlatform','ITSPlatformManager','CagService')
foreach ($svc in $services) {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
        Write-Output "  Stopped + deleted: $svc"
    } else {
        Write-Output "  Not found (skipped): $svc"
    }
}

# Step 2 -- Remove primary SAAZ/ITS registry keys
Write-Output "=== Step 2: Removing registry keys ==="
$regKeys = @(
    'HKLM:\SOFTWARE\WOW6432Node\SAAZOD',
    'HKLM:\SOFTWARE\SAAZOD',
    'HKLM:\SOFTWARE\WOW6432Node\ITSPlatform',
    'HKLM:\SOFTWARE\WOW6432Node\ \ITSPlatform'
)
foreach ($key in $regKeys) {
    if (Test-Path $key) {
        Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $key"
    } else {
        Write-Output "  Not found (skipped): $key"
    }
}

# Step 3 -- Remove install directories and ProgramData remnant
Write-Output "=== Step 3: Removing directories ==="
$dirs = @(
    "C:\Program Files (x86)\SAAZOD",
    "C:\Program Files (x86)\SAAZODBKP",
    "C:\Program Files (x86)\ITSPlatform",
    "C:\ProgramData\SAAZOD"
)
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $dir"
    } else {
        Write-Output "  Not found (skipped): $dir"
    }
}

# Step 4 -- Remove self-heal scheduled task
Write-Output "=== Step 4: Removing scheduled task ==="
$task = Get-ScheduledTask -TaskName 'ITSPlatformSelfHealUtility' -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName 'ITSPlatformSelfHealUtility' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "  Removed: ITSPlatformSelfHealUtility"
} else {
    Write-Output "  Not found (skipped): ITSPlatformSelfHealUtility"
}

# Step 5 -- Clear stale Windows Installer product registration
# Avoids Win32_Product (repair trigger). Registry-based scan only.
Write-Output "=== Step 5: Clearing stale MSI product registration ==="

$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$found = @()
foreach ($path in $uninstallPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.DisplayName -like '*ITSPlatform*' -or
            $props.DisplayName -like '*SAAZ*' -or
            $props.DisplayName -like '*RMM*') {
            $found += [PSCustomObject]@{
                Name = $props.DisplayName
                GUID = $_.PSChildName
                Path = $_.PSPath
            }
        }
    }
}

$installerProductsPath = 'HKLM:\SOFTWARE\Classes\Installer\Products'
$installerFound = @()
if (Test-Path $installerProductsPath) {
    Get-ChildItem $installerProductsPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.ProductName -like '*ITSPlatform*' -or
            $props.ProductName -like '*SAAZ*' -or
            $props.ProductName -like '*RMM*') {
            $installerFound += [PSCustomObject]@{
                ProductName = $props.ProductName
                PackedGUID  = $_.PSChildName
                Path        = $_.PSPath
            }
        }
    }
}

if ($found.Count -eq 0 -and $installerFound.Count -eq 0) {
    Write-Output "  No stale MSI entries found."
} else {
    foreach ($entry in $found) {
        if ($entry.GUID -match '^\{') {
            Write-Output "  msiexec /x $($entry.GUID) ..."
            $proc = Start-Process msiexec -ArgumentList "/x $($entry.GUID) /quiet /norestart" -Wait -PassThru -NoNewWindow
            Write-Output "  msiexec exit code: $($proc.ExitCode)"
        }
        if (Test-Path $entry.Path) {
            Remove-Item $entry.Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "  Removed Uninstall key: $($entry.Path)"
        }
    }
    foreach ($entry in $installerFound) {
        Write-Output "  Removing Installer\Products entry: $($entry.ProductName)"
        Remove-Item $entry.Path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $($entry.Path)"

        $featPath = $entry.Path -replace 'Products', 'Features'
        if (Test-Path $featPath) {
            Remove-Item $featPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "  Removed Features: $featPath"
        }

        $udPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$($entry.PackedGUID)"
        if (Test-Path $udPath) {
            Remove-Item $udPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "  Removed UserData: $udPath"
        }
    }
}

# Step 6 -- Verification
Write-Output "=== Step 6: Verification ==="
$warnings = 0

foreach ($svc in @('ITSPlatform','ITSPlatformManager')) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Write-Output "  WARNING: Service still registered: $svc"
        $warnings++
    }
}

foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Write-Output "  WARNING: Directory still present: $dir"
        $warnings++
    }
}

foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\SAAZOD','HKLM:\SOFTWARE\SAAZOD')) {
    if (Test-Path $key) {
        Write-Output "  WARNING: Registry key still present: $key"
        $warnings++
    }
}

if ($warnings -eq 0) {
    Write-Output "Nuke complete. No remnants found."
    Write-Output "Next: download fresh agent from RMM portal > Sites > (select site) > Download Agent."
    exit 0
} else {
    Write-Output "Nuke completed with $warnings warning(s). Review output above before reinstalling."
    exit 112
}
