<#
.SYNOPSIS
    Reset Office 365 activation state by removing expired grace keys and clearing license tokens.

.DESCRIPTION
    Removes expired Office grace-period product keys (VMFTK=ProPlus, 3RQ6B=Business),
    clears license token cache, WAM credentials, and identity cache, then prompts user to re-sign in.
    Resolves 0xC004F009 (grace period expired) activation failures. Clears Common\Identity so
    sign-in triggers a fresh vNext subscription check rather than reusing a stale cached identity.

.PARAMETER CloseOfficeApps
    Automatically close all Office applications before clearing cache.

.EXAMPLE
    .\Reset-OfficeActivation.ps1
    Remove expired keys and clear caches interactively.

.EXAMPLE
    .\Reset-OfficeActivation.ps1 -CloseOfficeApps
    Automatically close Office apps before clearing state.

.NOTES
    Context: User context (interactive) or SYSTEM with SID resolution
    Post-execution: User must sign into Office (File > Account > Sign In) and reboot

.LINK
    Error: errors/systems/windows.md (0xC004F009)
#>

[CmdletBinding()]
param(
    [switch]$CloseOfficeApps
)

# Locate OSPP.VBS
$c2rPath = "$env:ProgramFiles\Microsoft Office\root\Office16\OSPP.VBS"
$msiPath = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OSPP.VBS"

$osppPath = if (Test-Path $c2rPath) {
    $c2rPath
} elseif (Test-Path $msiPath) {
    $msiPath
} else {
    Write-Error "OSPP.VBS not found. Office installation may be missing or corrupted."
    exit 1
}

Write-Host "Found OSPP.VBS: $osppPath" -ForegroundColor Green

# Step 1: Remove expired grace keys
Write-Host "`nRemoving expired grace-period product keys..." -ForegroundColor Cyan

$graceKeys = @('VMFTK', '3RQ6B')  # ProPlus Grace, Business Grace
foreach ($key in $graceKeys) {
    Write-Host "  Removing key: $key" -ForegroundColor Yellow
    $result = & cscript //NoLogo $osppPath /unpkey:$key 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Removed: $key" -ForegroundColor Green
    } else {
        Write-Host "    Key not found or already removed: $key" -ForegroundColor Gray
    }
}

# Step 2: Resolve logged-in user SID (for SYSTEM context or current user)
$loggedInUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $loggedInUser) {
    Write-Warning "No user logged in. Cannot clear user-specific license tokens."
    exit 1
}

$sid = (New-Object System.Security.Principal.NTAccount($loggedInUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$userProfile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
$localAppData = Join-Path $userProfile 'AppData\Local'

Write-Host "`nTarget user: $loggedInUser (SID: $sid)" -ForegroundColor Cyan

# Step 3: Close Office applications (optional)
if ($CloseOfficeApps) {
    Write-Host "`nClosing Office applications..." -ForegroundColor Cyan
    $officeProcesses = Get-Process EXCEL, WINWORD, POWERPNT, OUTLOOK, ONENOTE, MSACCESS, MSPUB -ErrorAction SilentlyContinue
    if ($officeProcesses) {
        $officeProcesses | ForEach-Object {
            Stop-Process $_ -Force
            Write-Host "  Stopped: $($_.ProcessName)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No Office processes running." -ForegroundColor Gray
    }
}

# Step 4: Clear license tokens and WAM cache
Write-Host "`nClearing license tokens and credential cache..." -ForegroundColor Cyan

$cachePaths = @(
    "$localAppData\Microsoft\Office\Licenses",
    "$localAppData\Microsoft\Office\16.0\Licensing",
    "$localAppData\Microsoft\TokenBroker",
    "$localAppData\Microsoft\OneAuth",
    "$localAppData\Microsoft\IdentityCache"
)

foreach ($path in $cachePaths) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Cleared: $path" -ForegroundColor Green
    } else {
        Write-Host "  Not found: $path" -ForegroundColor Gray
    }
}

# Clear licensing registry
try {
    Remove-ItemProperty "Registry::HKU\$sid\Software\Microsoft\Office\16.0\Common\Licensing" -Name * -ErrorAction SilentlyContinue
    Write-Host "  Cleared: Office licensing registry" -ForegroundColor Green
} catch {
    Write-Host "  Licensing registry already clear or inaccessible" -ForegroundColor Gray
}

# Clear identity registry (prevents stale identity from blocking fresh vNext subscription check)
try {
    Remove-Item "Registry::HKU\$sid\Software\Microsoft\Office\16.0\Common\Identity" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Cleared: Office identity registry" -ForegroundColor Green
} catch {
    Write-Host "  Identity registry already clear or inaccessible" -ForegroundColor Gray
}

# Step 5: Instructions for user
Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Open any Office application (Word, Excel, Outlook)" -ForegroundColor White
Write-Host "2. Go to File > Account > Sign In" -ForegroundColor White
Write-Host "3. Enter your work or school account credentials" -ForegroundColor White
Write-Host "4. Reboot the workstation" -ForegroundColor White
Write-Host "5. Verify activation: File > Account > 'Product Activated'" -ForegroundColor White
Write-Host "6. Optional: run vnextdiag.ps1 -action list to confirm vNext subscription state" -ForegroundColor White

Write-Host "`nActivation state reset complete." -ForegroundColor Green
exit 0
