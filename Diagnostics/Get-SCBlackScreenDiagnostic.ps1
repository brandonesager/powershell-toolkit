<#
.SYNOPSIS
    Diagnoses ScreenConnect black-screen and display rendering issues.
.DESCRIPTION
    Gathers display driver details, checks for privacy/screen-capture software,
    reports ScreenConnect service status and DisableGPU registry setting, checks
    WPF hardware acceleration state, detects HP Sure View, enumerates all displays,
    and reports DPI scaling. Read-only -- makes no changes.

    Run in a user session (ScreenConnect Interact or Quick Assist) to capture
    the full display context for the logged-in user.
.EXAMPLE
    .\Get-SCBlackScreenDiagnostic.ps1
.NOTES
    Context:    User session (ScreenConnect Interact / Quick Assist)
    Platform:   Windows 10/11, PS 5.1
    PS 5.1 compatible.
.KEYWORDS
    ScreenConnect, black screen, display, GPU, DisableGPU, Sure View, WPF, diagnostic
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

#region Display Driver Check
Write-Host "=== Display Drivers ===" -ForegroundColor Cyan
Get-WmiObject Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, Status | Format-Table -AutoSize
#endregion

#region Privacy/Screen Capture Software
Write-Host "`n=== Screen Capture/Privacy Software ===" -ForegroundColor Cyan
$privacyProcs = Get-Process | Where-Object { $_.ProcessName -match 'privacy|screen|capture|guard|sureview|command center' }
if ($privacyProcs) {
    $privacyProcs | Select-Object ProcessName, Id, Path | Format-Table -AutoSize
} else {
    Write-Host "No known privacy/screen capture software detected" -ForegroundColor Green
}
#endregion

#region ScreenConnect Service Status
Write-Host "`n=== ScreenConnect Service ===" -ForegroundColor Cyan
$scServices = Get-Service -Name "ScreenConnect Client*" -ErrorAction SilentlyContinue
if ($scServices) {
    $scServices | Select-Object Name, Status, StartType | Format-Table -AutoSize

    $guid = ($scServices[0].Name -replace 'ScreenConnect Client \(','') -replace '\)',''
    Write-Host "SC Client GUID: $guid" -ForegroundColor Yellow

    $regPath = "HKLM:\SOFTWARE\ScreenConnect Client ($guid)\Settings"
    if (Test-Path $regPath) {
        $disableGPU = (Get-ItemProperty -Path $regPath -Name DisableGPU -ErrorAction SilentlyContinue).DisableGPU
        Write-Host "DisableGPU setting: $(if ($disableGPU -eq 1) { 'Enabled (GPU disabled)' } else { 'Not set (GPU enabled)' })"
    }
} else {
    Write-Host "No ScreenConnect services found!" -ForegroundColor Red
}
#endregion

#region GPU Hardware Acceleration (WPF/Avalon)
Write-Host "`n=== WPF Hardware Acceleration ===" -ForegroundColor Cyan
$avalon = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Avalon.Graphics" -Name DisableHWAcceleration -ErrorAction SilentlyContinue
if ($avalon.DisableHWAcceleration -eq 1) {
    Write-Host "WPF Hardware Acceleration: DISABLED" -ForegroundColor Yellow
} else {
    Write-Host "WPF Hardware Acceleration: Enabled (default)" -ForegroundColor Green
}
#endregion

#region HP Sure View Check
Write-Host "`n=== HP Sure View ===" -ForegroundColor Cyan
$hpSureView = Get-WmiObject -Namespace "root\HP\InstrumentedBIOS" -Class HP_BIOSEnumeration -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'Sure View' }
if ($hpSureView) {
    Write-Host "HP Sure View found: $($hpSureView.CurrentValue)" -ForegroundColor Yellow
    Write-Host "Toggle with Fn+F2 or via HP Command Center" -ForegroundColor Yellow
} else {
    Write-Host "HP Sure View not detected (or not HP device)" -ForegroundColor Green
}
#endregion

#region Display Settings
Write-Host "`n=== Display Configuration ===" -ForegroundColor Cyan
Add-Type -AssemblyName System.Windows.Forms
$screens = [System.Windows.Forms.Screen]::AllScreens
foreach ($screen in $screens) {
    Write-Host "Display: $($screen.DeviceName)"
    Write-Host "  Bounds: $($screen.Bounds.Width)x$($screen.Bounds.Height)"
    Write-Host "  Primary: $($screen.Primary)"
}

$dpi = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name AppliedDPI -ErrorAction SilentlyContinue).AppliedDPI
if ($dpi) {
    $scale = [math]::Round($dpi / 96 * 100)
    Write-Host "`nDisplay Scale: ${scale}%" -ForegroundColor $(if ($scale -gt 100) { 'Yellow' } else { 'Green' })
}
#endregion

Write-Host "`n=== Diagnostics Complete ===" -ForegroundColor Cyan
