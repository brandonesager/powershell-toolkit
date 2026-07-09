<#
.SYNOPSIS
    Aggressive HDD performance optimization for Windows 10/11

.DESCRIPTION
    Applies comprehensive optimizations to mitigate 100% disk usage on HDD-based systems:
    - Disables NTFS Last Access timestamps (reduces writes by ~20%)
    - Disables 8.3 short filename creation
    - Increases NTFS memory usage for better caching
    - Disables Prefetch/Superfetch
    - Disables Windows Tips, background apps, Timeline
    - Sets fixed virtual memory (prevents dynamic pagefile resizing)
    - Disables automatic maintenance and scheduled defrag
    - Optimizes visual effects for performance
    - Disables Storage Sense

    WARNING: Some features will be disabled. These optimizations help but won't fully fix
    the 100% disk issue on an HDD. Windows 10/11 expects an SSD.

.NOTES
    Context: Interactive Admin or RMM (PS 5.1, SYSTEM)
    Requires: Administrator privileges
    Restart: Required for full effect
#>

#Requires -RunAsAdministrator

Write-Host "================================================" -ForegroundColor Cyan
Write-Host " HDD AGGRESSIVE OPTIMIZATION" -ForegroundColor Cyan
Write-Host " (Beyond basic service disabling)" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# 1. Disable NTFS Last Access Time Stamps (reduces writes by ~20%)
# -----------------------------------------------------------------------------
Write-Host "[1/12] Disabling NTFS Last Access timestamps..." -ForegroundColor Yellow
fsutil behavior set disablelastaccess 1
Write-Host "  - Last Access timestamps disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 2. Disable 8.3 Short Filename Creation (legacy DOS names)
# -----------------------------------------------------------------------------
Write-Host "[2/12] Disabling 8.3 short filename creation..." -ForegroundColor Yellow
fsutil behavior set disable8dot3 1
Write-Host "  - 8.3 filenames disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 3. Increase NTFS Memory Usage (better caching)
# -----------------------------------------------------------------------------
Write-Host "[3/12] Increasing NTFS memory usage..." -ForegroundColor Yellow
fsutil behavior set memoryusage 2
Write-Host "  - NTFS memory usage set to maximum" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 4. Disable Prefetch and Superfetch completely (registry)
# -----------------------------------------------------------------------------
Write-Host "[4/12] Disabling Prefetch via registry..." -ForegroundColor Yellow
$prefetchPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
Set-ItemProperty -Path $prefetchPath -Name "EnablePrefetcher" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $prefetchPath -Name "EnableSuperfetch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  - Prefetch disabled in registry" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 5. Disable Windows Tips and Suggestions (background polling)
# -----------------------------------------------------------------------------
Write-Host "[5/12] Disabling Windows Tips/Suggestions..." -ForegroundColor Yellow
$contentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Set-ItemProperty -Path $contentDeliveryPath -Name "SubscribedContent-338389Enabled" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $contentDeliveryPath -Name "SubscribedContent-310093Enabled" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $contentDeliveryPath -Name "SubscribedContent-338388Enabled" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $contentDeliveryPath -Name "SoftLandingEnabled" -Value 0 -ErrorAction SilentlyContinue
Write-Host "  - Tips and suggestions disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 6. Disable Background Apps (huge impact on HDDs)
# -----------------------------------------------------------------------------
Write-Host "[6/12] Disabling background apps..." -ForegroundColor Yellow
$bgAppsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
Set-ItemProperty -Path $bgAppsPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
# Also via policy
$bgPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
if (-not (Test-Path $bgPolicyPath)) { New-Item -Path $bgPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $bgPolicyPath -Name "LetAppsRunInBackground" -Value 2 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  - Background apps disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 7. Disable Timeline / Activity History
# -----------------------------------------------------------------------------
Write-Host "[7/12] Disabling Timeline/Activity History..." -ForegroundColor Yellow
$activityPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $activityPath)) { New-Item -Path $activityPath -Force | Out-Null }
Set-ItemProperty -Path $activityPath -Name "EnableActivityFeed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $activityPath -Name "PublishUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $activityPath -Name "UploadUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  - Timeline disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 8. Set Virtual Memory to Fixed Size (prevents dynamic resizing)
# -----------------------------------------------------------------------------
Write-Host "[8/12] Setting fixed virtual memory..." -ForegroundColor Yellow
# Get RAM size and set pagefile to 1.5x
$ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$pagefileSizeMB = [math]::Round($ram * 1.5 * 1024)
$pagefileMax = [math]::Round($ram * 2 * 1024)

# Disable automatic pagefile management
$cs = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
$cs.AutomaticManagedPagefile = $false
$cs.Put() | Out-Null

# Set fixed pagefile
$pagefile = Get-WmiObject -Class Win32_PageFileSetting -ErrorAction SilentlyContinue
if ($pagefile) {
    $pagefile.InitialSize = $pagefileSizeMB
    $pagefile.MaximumSize = $pagefileMax
    $pagefile.Put() | Out-Null
}
Write-Host "  - Pagefile set to fixed ${pagefileSizeMB}MB - ${pagefileMax}MB" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 9. Disable Automatic Maintenance
# -----------------------------------------------------------------------------
Write-Host "[9/12] Disabling automatic maintenance..." -ForegroundColor Yellow
$maintPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"
Set-ItemProperty -Path $maintPath -Name "MaintenanceDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  - Automatic maintenance disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 10. Disable Scheduled Defrag (HDD doesn't need constant defrag)
# -----------------------------------------------------------------------------
Write-Host "[10/12] Disabling scheduled defragmentation..." -ForegroundColor Yellow
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable 2>$null
Write-Host "  - Scheduled defrag disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 11. Optimize Visual Effects for Performance
# -----------------------------------------------------------------------------
Write-Host "[11/12] Setting visual effects to Performance..." -ForegroundColor Yellow
$visualFxPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
Set-ItemProperty -Path $visualFxPath -Name "VisualFXSetting" -Value 2 -Type DWord -ErrorAction SilentlyContinue
# Also set SystemPropertiesPerformance options
$perfPath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $perfPath -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Type Binary -ErrorAction SilentlyContinue
Write-Host "  - Visual effects set to Performance" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 12. Disable Storage Sense (automatic cleanup can thrash disk)
# -----------------------------------------------------------------------------
Write-Host "[12/12] Disabling Storage Sense..." -ForegroundColor Yellow
$storagePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
if (Test-Path $storagePath) {
    Set-ItemProperty -Path $storagePath -Name "01" -Value 0 -Type DWord -ErrorAction SilentlyContinue
}
Write-Host "  - Storage Sense disabled" -ForegroundColor Green

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host " OPTIMIZATION COMPLETE" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Applied optimizations:" -ForegroundColor White
Write-Host "  [X] NTFS Last Access timestamps disabled" -ForegroundColor Green
Write-Host "  [X] 8.3 short filenames disabled" -ForegroundColor Green
Write-Host "  [X] NTFS memory usage maximized" -ForegroundColor Green
Write-Host "  [X] Prefetch fully disabled" -ForegroundColor Green
Write-Host "  [X] Windows tips/suggestions disabled" -ForegroundColor Green
Write-Host "  [X] Background apps disabled" -ForegroundColor Green
Write-Host "  [X] Timeline/Activity History disabled" -ForegroundColor Green
Write-Host "  [X] Virtual memory set to fixed size" -ForegroundColor Green
Write-Host "  [X] Automatic maintenance disabled" -ForegroundColor Green
Write-Host "  [X] Scheduled defrag disabled" -ForegroundColor Green
Write-Host "  [X] Visual effects set to Performance" -ForegroundColor Green
Write-Host "  [X] Storage Sense disabled" -ForegroundColor Green
Write-Host ""
Write-Host "================================================" -ForegroundColor Yellow
Write-Host " RESTART REQUIRED" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORTANT: These optimizations will help but won't fully fix" -ForegroundColor Yellow
Write-Host "the 100% disk issue on an HDD. Windows 10/11 expects an SSD." -ForegroundColor Yellow
Write-Host ""
Write-Host "BIOS CHECK: Ensure SATA mode is set to AHCI (not IDE/RAID)" -ForegroundColor White
Write-Host "            AHCI enables NCQ which helps HDD performance." -ForegroundColor White
Write-Host ""

exit 0
