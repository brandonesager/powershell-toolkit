<#
.SYNOPSIS
    Detect SPO module version conflicts and PnP assembly mismatches that cause 400 on Connect-SPOService.

.DESCRIPTION
    Checks:
    - All installed versions of Microsoft.Online.SharePoint.PowerShell (needs 16.0.22601.12000+ for ModernAuth).
    - Loaded PnP module versions (PnP.PowerShell or SharePointPnPPowerShellOnline).
    - Assembly mismatch between SPO module and PnP module (Microsoft.Online.SharePoint.Client.Tenant DLL conflict).
    - SharePoint Client Components SDK installation (known conflict with SPO PS module).
    - Loaded SharePoint-related modules in the current session.
    - Actionable guidance for each detected issue.

    Run from a local Windows PowerShell 5.1 session (any Windows endpoint).
    Does not require an active SPO connection.

.EXAMPLE
    .\Get-SpoDiagnostics.ps1

.NOTES
    Created: 2026-05-29
    Category: M365-SharePoint
    Context: Local Windows PS 5.1

    Root cause: PnP.PowerShell and Microsoft.Online.SharePoint.PowerShell
    load conflicting versions of Microsoft.Online.SharePoint.Client.Tenant, causing Connect-SPOService
    to return 400 Bad Request. Fix: remove SPO module and reinstall fresh, or use browser UI.

.KEYWORDS
    SharePoint, SPO, PnP, module conflict, 400, Connect-SPOService, assembly mismatch, ModernAuth
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Continue'

Write-Host "`n=== SPO Module Diagnostics ===" -ForegroundColor Cyan

# 1. Installed SPO module versions
Write-Host "`n--- Microsoft.Online.SharePoint.PowerShell installed versions ---" -ForegroundColor Yellow
$spoInstalled = Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable |
    Select-Object Name, Version, ModuleBase | Sort-Object Version -Descending
if ($spoInstalled) {
    $spoInstalled | Format-Table -AutoSize
    $latest = $spoInstalled | Select-Object -First 1
    $minVersion = [Version]'16.0.22601.12000'
    if ($latest.Version -ge $minVersion) {
        Write-Host "Version OK ($($latest.Version) >= $minVersion for ModernAuth)." -ForegroundColor Green
    } else {
        Write-Host "Version TOO OLD ($($latest.Version)). Minimum for ModernAuth: $minVersion" -ForegroundColor Red
        Write-Host "Fix: Uninstall-Module Microsoft.Online.SharePoint.PowerShell -Force -AllVersions" -ForegroundColor Yellow
        Write-Host "     Install-Module Microsoft.Online.SharePoint.PowerShell -Force" -ForegroundColor Yellow
    }
} else {
    Write-Host "Microsoft.Online.SharePoint.PowerShell NOT installed." -ForegroundColor Red
    Write-Host "Fix: Install-Module Microsoft.Online.SharePoint.PowerShell -Force" -ForegroundColor Yellow
}

# 2. Loaded PnP modules (conflict source)
Write-Host "`n--- Loaded PnP modules (current session) ---" -ForegroundColor Yellow
$pnpLoaded = Get-Module PnP* | Select-Object Name, Version, ModuleBase
if ($pnpLoaded) {
    $pnpLoaded | Format-Table -AutoSize
    Write-Host "WARNING: PnP module loaded alongside SPO module may cause assembly conflict." -ForegroundColor Red
    Write-Host "Fix: Remove-Module PnP* before loading SPO module, or run in a fresh PS session." -ForegroundColor Yellow
} else {
    Write-Host "No PnP modules loaded." -ForegroundColor Green
}

# 3. Loaded SharePoint modules
Write-Host "`n--- Loaded SharePoint-related modules ---" -ForegroundColor Yellow
$spLoaded = Get-Module *SharePoint* | Select-Object Name, Version
if ($spLoaded) { $spLoaded | Format-Table -AutoSize } else { Write-Host "None." -ForegroundColor Green }

# 4. SharePoint Client Components SDK (registry)
Write-Host "`n--- SharePoint Client Components SDK (registry check) ---" -ForegroundColor Yellow
$sdk = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like '*SharePoint*Client*' } |
    Select-Object DisplayName, DisplayVersion
if ($sdk) {
    $sdk | Format-Table -AutoSize
    Write-Host "SharePoint Client Components SDK detected — may conflict with SPO PS module." -ForegroundColor Red
    Write-Host "Fix: uninstall via Programs and Features, then reinstall SPO module." -ForegroundColor Yellow
} else {
    Write-Host "Not installed." -ForegroundColor Green
}

# 5. Assembly conflict check (Microsoft.Online.SharePoint.Client.Tenant)
Write-Host "`n--- Assembly conflict check (Microsoft.Online.SharePoint.Client.Tenant) ---" -ForegroundColor Yellow
$tenantAsm = [System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GetName().Name -eq 'Microsoft.Online.SharePoint.Client.Tenant' } |
    Select-Object -ExpandProperty Location
if ($tenantAsm) {
    $tenantAsm | ForEach-Object { Write-Host "Loaded: $_" }
    if ($tenantAsm.Count -gt 1) {
        Write-Host "CONFLICT: multiple Tenant assembly locations loaded." -ForegroundColor Red
        Write-Host "Fix: start a new PowerShell session and load only one module (SPO or PnP, not both)." -ForegroundColor Yellow
    } else {
        Write-Host "Single location loaded -- no conflict detected." -ForegroundColor Green
    }
} else {
    Write-Host "Assembly not yet loaded in this session." -ForegroundColor DarkGray
}

# 6. Summary guidance
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "If Connect-SPOService returns 400 Bad Request:"
Write-Host "  1. Confirm SPO module >= 16.0.22601.12000 (ModernAuth requirement)."
Write-Host "  2. Do not mix PnP.PowerShell and SPO module in the same session."
Write-Host "  3. Uninstall SharePoint Client Components SDK if present."
Write-Host "  4. Try: Connect-SPOService -Url <admin-url> -ModernAuth `$true"
Write-Host "  5. If GDAP tenant: add tenant auth endpoint:"
Write-Host "     Connect-SPOService -Url <admin-url> -AuthenticationUrl https://login.microsoftonline.com/<tenantId>/oauth2/authorize"
Write-Host "  6. If all PS paths fail, use SharePoint admin center browser UI as fallback."
