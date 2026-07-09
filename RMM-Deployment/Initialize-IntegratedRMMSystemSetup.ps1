<#
.SYNOPSIS
  Integrated RMM System Setup Script - Enterprise-grade one-shot execution for complete system configuration

.DESCRIPTION
  Performs comprehensive system setup including:
  - Windows Updates installation (OS updates first for optimal compatibility)
  - HP driver/firmware updates (HP devices only, using correct HPIA parameters)
  - Software cleanup (HP Wolf, Teams, Mail - all variants)
  - Taskbar and application defaults configuration (machine-wide for all users)
  - Azure AD user addition to local administrators (with validation)

  Enhanced with enterprise features:
  - Comprehensive error tracking and reporting
  - Parameter validation and input sanitization
  - Enhanced pending reboot detection (including ConfigMgr)
  - Machine-wide configuration affecting all current and future users
  - Robust retry mechanisms with optional progress indicators
  - Modern CIM/PowerShell practices (no deprecated WMI calls)

.PARAMETER AzureADUser
  Azure AD user email to add to local Administrators group (e.g., "user@domain.com")

.PARAMETER IncludeDrivers
  Include driver updates in Windows Update process

.PARAMETER IncludeBIOS
  Include BIOS updates in HP Image Assistant process

.PARAMETER ExcludeKB
  KB IDs to exclude from Windows Updates (e.g., @("KB5030219","KB5028166"))

.PARAMETER SkipWindowsUpdates
  Skip Windows Updates installation

.PARAMETER SkipHPIA
  Skip HP Image Assistant execution

.PARAMETER SkipTaskbarConfig
  Skip taskbar and application configuration

.PARAMETER ShowProgress
  Display progress indicators during long-running operations (may not be visible in RMM)

.NOTES
  Requires PowerShell 5.1 and Administrator privileges
  Designed for RMM and similar platforms

    Category: RMM-Deployment
.KEYWORDS
    RMM, SYSTEM, provision, HPIA, bloatware
#>

[CmdletBinding()]
param(
    [string]$AzureADUser = "user@client.example.com",
    [switch]$IncludeDrivers,
    [switch]$IncludeBIOS,
    [string[]]$ExcludeKB = @(),
    [switch]$SkipWindowsUpdates,
    [switch]$SkipHPIA,
    [switch]$SkipTaskbarConfig,
    [switch]$ShowProgress
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'  # Stop on critical errors, but handle gracefully in try-catch blocks
$global:RMMScriptErrors = @()  # Track non-critical errors for final reporting

#region Logging and Helper Functions
function Write-RMMLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Output $logMessage

    # Track errors for final summary
    if ($Level -eq 'ERROR') {
        $global:RMMScriptErrors += $Message
    }

    # Also write to Windows Event Log for RMM visibility
    try {
        $eventID = switch ($Level) {
            'ERROR' { 1001 }
            'WARN'  { 1002 }
            default { 1000 }
        }
        Write-EventLog -LogName Application -Source "RMM-SystemSetup" -EntryType Information -EventId $eventID -Message $logMessage -ErrorAction SilentlyContinue
    } catch {
        # Event log write failed, continue silently
    }
}

function Test-PendingReboot {
    try {
        $rebootReasons = @()

        # Component Based Servicing
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $rebootReasons += "Component Based Servicing"
        }

        # Pending File Rename Operations
        $pendingFileRename = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            $rebootReasons += "Pending File Rename Operations"
        }

        # Windows Update Auto Update
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $rebootReasons += "Windows Update"
        }

        # ConfigMgr Client SDK
        try {
            $ccmClientSDK = Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -MethodName 'DetermineIfRebootPending' -ErrorAction SilentlyContinue
            if ($ccmClientSDK -and $ccmClientSDK.RebootPending) {
                $rebootReasons += "ConfigMgr Client"
            }
        } catch {
            # ConfigMgr not installed, continue
        }

        # Additional Windows Update locations
        if (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
            $rebootReasons += "Windows Update Services"
        }

        if ($rebootReasons.Count -gt 0) {
            Write-RMMLog "Reboot required due to: $($rebootReasons -join ', ')" -Level INFO
            return $true
        }

        return $false
    } catch {
        Write-RMMLog "Error checking pending reboot status: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5,
        [string]$OperationName = "Operation"
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            if ($ShowProgress) {
                Write-Progress -Activity "RMM System Setup" -Status "$OperationName (Attempt $i of $MaxRetries)" -PercentComplete (($i / $MaxRetries) * 100)
            }
            return & $ScriptBlock
        } catch {
            if ($i -eq $MaxRetries) {
                throw $_
            }
            Write-RMMLog "Attempt $i failed: $($_.Exception.Message). Retrying in $DelaySeconds seconds..." -Level WARN
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}
#endregion

#region Prerequisites Check
Write-RMMLog "=== RMM INTEGRATED SYSTEM SETUP STARTED ===" -Level SUCCESS

# Validate parameters
if ($AzureADUser -and $AzureADUser -notmatch '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
    Write-RMMLog "Invalid email format for AzureADUser: $AzureADUser" -Level ERROR
    exit 1
}

# System detection
$isHPDevice   = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer -match 'HP|Hewlett'
$isWindows11  = [int](Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber -ge 22000

#region 1. Windows Updates
if (-not $SkipWindowsUpdates) {
    Write-RMMLog "=== PHASE 1: WINDOWS UPDATES ===" -Level SUCCESS

    try {
        # Ensure PSGallery is trusted
        Invoke-WithRetry {
            try {
                $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
            } catch {
                Register-PSRepository -Default -ErrorAction Stop
                $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
            }
            if ($repo.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
        }

        # Check if PSWindowsUpdate module exists
        $psWindowsUpdateModule = Get-Module -ListAvailable -Name PSWindowsUpdate
        if (-not $psWindowsUpdateModule) {
            Write-RMMLog "Installing PSWindowsUpdate module..."
            Invoke-WithRetry -OperationName "Installing PSWindowsUpdate Module" {
                Install-Module PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
            }
            $psWindowsUpdateModule = Get-Module -ListAvailable -Name PSWindowsUpdate
        } else {
            Write-RMMLog "PSWindowsUpdate module already installed (version: $($psWindowsUpdateModule.Version))"
        }

        # Import the module
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Write-RMMLog "PSWindowsUpdate version: $((Get-Module PSWindowsUpdate).Version)" -Level SUCCESS
        } catch {
            Write-RMMLog "Failed to import PSWindowsUpdate module: $($_.Exception.Message)" -Level ERROR
            throw
        }

        # Register Microsoft Update service (critical for Office updates)
        try {
            $existingServices = Get-WUServiceManager
            $hasMicrosoftUpdate = $existingServices | Where-Object { $_.ServiceID -eq "7971F918-A847-4430-9279-4A52D1EFE18D" }

            if (-not $hasMicrosoftUpdate) {
                Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
                Write-RMMLog "Microsoft Update service registered" -Level SUCCESS
            } else {
                Write-RMMLog "Microsoft Update service already registered" -Level SUCCESS
            }
        } catch {
            Write-RMMLog "CRITICAL: Could not register Microsoft Update service: $($_.Exception.Message)" -Level ERROR
            Write-RMMLog "Office and other Microsoft products may not receive updates" -Level WARN
        }

        # Build update parameters with proper error handling
        $scanParams = @{
            AcceptAll     = $true
            IgnoreReboot  = $true
            ErrorAction   = 'SilentlyContinue'  # Don't stop on individual update failures
            MicrosoftUpdate = $true
        }
        $installParams = @{
            AcceptAll     = $true
            IgnoreReboot  = $true
            ErrorAction   = 'SilentlyContinue'  # Don't stop on individual update failures
            Verbose       = $false
            Confirm       = $false
            MicrosoftUpdate = $true
        }

        if (-not $IncludeDrivers) {
            $scanParams['NotCategory'] = 'Drivers'
            $installParams['NotCategory'] = 'Drivers'
            Write-RMMLog "Excluding driver updates from Windows Update (HPIA will handle hardware-specific drivers)"
        } else {
            Write-RMMLog "Including driver updates from Windows Update (may overlap with HPIA)"
        }

        if ($ExcludeKB -and $ExcludeKB.Count -gt 0) {
            $scanParams['NotKBArticleID'] = $ExcludeKB
            $installParams['NotKBArticleID'] = $ExcludeKB
            Write-RMMLog "Excluding KB articles: $($ExcludeKB -join ', ')"
        }

        # Scan and install updates
        Write-RMMLog "Scanning for Windows Updates..."
        Get-WindowsUpdate @scanParams | Out-Null

        Write-RMMLog "Installing Windows Updates..."
        $updateResults = Install-WindowsUpdate @installParams

        if ($updateResults) {
            $updateResults | ForEach-Object {
                $kb = try { ($_ | Select-Object -ExpandProperty KB).Trim() } catch { '' }
                $title = try { $_.Title } catch { '' }
                $result = try { $_.Result } catch { '' }
                Write-RMMLog "Update: $(if ($kb) { "KB$kb" } else { 'No KB' }) | $title | Result: $result" -Level SUCCESS
            }
        } else {
            Write-RMMLog "No updates were installed" -Level SUCCESS
        }

    } catch {
        Write-RMMLog "Windows Updates failed: $($_.Exception.Message)" -Level ERROR
    }
} else {
    Write-RMMLog "Skipping Windows Updates (SkipWindowsUpdates parameter)" -Level INFO
}
#endregion

#region 2. HP Image Assistant (HP devices only)
if (-not $SkipHPIA -and $isHPDevice) {
    Write-RMMLog "=== PHASE 2: HP IMAGE ASSISTANT ===" -Level SUCCESS

    try {
        # Locate HPImageAssistant.exe
        $HPIAPath = ""
        $candidates = @(
            "$env:ProgramFiles\HP\HP Image Assistant\HPImageAssistant.exe",
            "$env:ProgramFiles(x86)\HP\HP Image Assistant\HPImageAssistant.exe"
        ) | Where-Object { Test-Path $_ }

        if (-not $candidates) {
            $candidates = Get-ChildItem 'C:\SWSetup' -Filter 'HPImageAssistant.exe' -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -ExpandProperty FullName -First 1
        } else {
            $candidates = $candidates[0]
        }
        $HPIAPath = $candidates

        if (Test-Path $HPIAPath) {
            Write-RMMLog "Found HP Image Assistant: $HPIAPath"

            # Create working directories with validation
            $Base = Join-Path $env:ProgramData 'HPIA'
            $DL = Join-Path $Base 'Downloads'
            $Rpt = Join-Path $Base 'Reports'
            $Log = Join-Path $Base 'Logs'

            try {
                $null = New-Item $DL, $Rpt, $Log -ItemType Directory -Force -ErrorAction Stop
                Write-RMMLog "Created HPIA working directories: $Base" -Level SUCCESS
            } catch {
                Write-RMMLog "CRITICAL: Failed to create HPIA directories: $($_.Exception.Message)" -Level ERROR
                throw
            }

            # Validate directories were created
            @($DL, $Rpt, $Log) | ForEach-Object {
                if (-not (Test-Path $_)) {
                    Write-RMMLog "CRITICAL: HPIA directory not created: $_" -Level ERROR
                    throw "Failed to create required HPIA directory: $_"
                }
            }

            # Build category list
            $categories = 'Drivers,Software,Firmware'
            if ($IncludeBIOS) {
                $categories += ',BIOS'
                Write-RMMLog "Including BIOS updates"
            }

            $argList = @(
                '/Operation:Analyze',
                '/Action:Install',
                '/Selection:All',
                '/InstallType:AutoInstallable',
                '/Silent',
                "/Category:$categories",
                "/ReportFolder:$Rpt",
                "/LogFolder:$Log",
                "/SoftPaqDownloadFolder:$DL",
                '/AutoCleanup'
            )

            Write-RMMLog "Running HP Image Assistant with categories: $categories"
            $proc = Start-Process -FilePath $HPIAPath -ArgumentList $argList -Wait -PassThru
            $code = $proc.ExitCode

            switch ($code) {
                0    {
                    Write-RMMLog "HP Image Assistant completed successfully" -Level SUCCESS
                }
                256  {
                    Write-RMMLog "HP Image Assistant: No recommendations found" -Level SUCCESS
                }
                3010 {
                    Write-RMMLog "HP Image Assistant completed - reboot required" -Level SUCCESS
                    # Force reboot detection since HPIA requires it
                    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -Force -ErrorAction SilentlyContinue | Out-Null
                }
                3020 {
                    Write-RMMLog "HP Image Assistant: One or more installs failed" -Level WARN
                }
                default {
                    Write-RMMLog "HP Image Assistant completed with exit code: $code" -Level WARN
                }
            }
        } else {
            Write-RMMLog "HP Image Assistant not found - skipping HP updates" -Level WARN
        }
    } catch {
        Write-RMMLog "HP Image Assistant failed: $($_.Exception.Message)" -Level ERROR
    }
} elseif (-not $isHPDevice) {
    Write-RMMLog "Non-HP device detected - skipping HP Image Assistant" -Level INFO
} else {
    Write-RMMLog "Skipping HP Image Assistant (SkipHPIA parameter)" -Level INFO
}
#endregion

#region 3. Software Cleanup
Write-RMMLog "=== PHASE 3: SOFTWARE CLEANUP ===" -Level SUCCESS

try {
    # Uninstall HP Wolf Security
    Write-RMMLog "Removing HP Wolf Security..."
    Get-Package -Name "*HP Wolf Security*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-RMMLog "Uninstalling $($_.Name)"
        try {
            $_ | Uninstall-Package -Force -ErrorAction Stop
            Write-RMMLog "Successfully removed $($_.Name)" -Level SUCCESS
        } catch {
            Write-RMMLog "Failed to remove $($_.Name): $($_.Exception.Message)" -Level WARN
        }
    }

    # Uninstall Microsoft Teams
    Write-RMMLog "Removing Microsoft Teams..."

    # Machine-wide installer using CIM (not deprecated WMI)
    try {
        $TeamsMachineWide = Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%Teams Machine-Wide Installer%'" -ErrorAction SilentlyContinue
        if ($TeamsMachineWide) {
            Write-RMMLog "Found Teams Machine-Wide Installer, removing..."
            $TeamsMachineWide | Invoke-CimMethod -MethodName Uninstall | Out-Null
            Write-RMMLog "Removed Teams Machine-Wide Installer" -Level SUCCESS
        } else {
            Write-RMMLog "Teams Machine-Wide Installer not found"
        }
    } catch {
        Write-RMMLog "Failed to remove Teams Machine-Wide Installer: $($_.Exception.Message)" -Level WARN
    }

    # User-level Teams - check multiple locations
    $teamsLocations = @(
        "$env:LOCALAPPDATA\Microsoft\Teams\Update.exe",
        "$env:ProgramFiles\WindowsApps\MicrosoftTeams*\msteams.exe"
    )

    foreach ($location in $teamsLocations) {
        if ($location -like "*WindowsApps*") {
            # Handle UWP Teams
            try {
                Get-AppxPackage -AllUsers *Teams* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                Write-RMMLog "Removed UWP Teams application" -Level SUCCESS
            } catch {
                Write-RMMLog "Failed to remove UWP Teams: $($_.Exception.Message)" -Level WARN
            }
        } else {
            # Handle classic Teams
            if (Test-Path $location) {
                try {
                    Start-Process -FilePath $location -ArgumentList "--uninstall", "-s" -Wait -NoNewWindow -ErrorAction Stop
                    Write-RMMLog "Removed Teams classic application" -Level SUCCESS
                } catch {
                    Write-RMMLog "Failed to remove Teams classic app: $($_.Exception.Message)" -Level WARN
                }
            }
        }
    }

    # Additional Teams cleanup - remove residual folders
    $teamsCleanupPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Teams",
        "$env:APPDATA\Microsoft\Teams",
        "$env:ProgramData\Microsoft\Teams"
    )

    foreach ($path in $teamsCleanupPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                Write-RMMLog "Cleaned up Teams folder: $path" -Level SUCCESS
            } catch {
                Write-RMMLog "Could not remove Teams folder $path`: $($_.Exception.Message)" -Level WARN
            }
        }
    }

    # Uninstall Windows Mail app (UWP)
    Write-RMMLog "Removing Windows Mail app..."
    try {
        Get-AppxPackage -AllUsers *windowscommunicationsapps* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*windowscommunicationsapps*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-RMMLog "Removed Windows Mail app" -Level SUCCESS
    } catch {
        Write-RMMLog "Failed to remove Windows Mail app: $($_.Exception.Message)" -Level WARN
    }

} catch {
    Write-RMMLog "Software cleanup phase encountered errors: $($_.Exception.Message)" -Level WARN
}
#endregion

#region 4. Taskbar and Application Configuration (Windows 11 only)
if (-not $SkipTaskbarConfig -and $isWindows11) {
    Write-RMMLog "=== PHASE 4: TASKBAR CONFIGURATION (ALL USERS) ===" -Level SUCCESS

    try {
        # Create LayoutModification.xml for default taskbar (applies to all new users)
        Write-RMMLog "Configuring default taskbar layout for all users..."

        $layoutXML = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\File Explorer.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ProgramFiles%\Microsoft Office\root\Office16\OUTLOOK.EXE" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ProgramFiles%\Microsoft Office\root\Office16\WINWORD.EXE" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

        # Save layout file to correct system-wide location for all users
        $shellPath = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"
        $layoutPath = Join-Path $shellPath "LayoutModification.xml"

        try {
            if (-not (Test-Path $shellPath)) {
                New-Item -Path $shellPath -ItemType Directory -Force | Out-Null
            }
            $layoutXML | Out-File -FilePath $layoutPath -Encoding UTF8 -Force
            Write-RMMLog "Created system-wide taskbar layout file: $layoutPath" -Level SUCCESS
        } catch {
            Write-RMMLog "Failed to create layout file: $($_.Exception.Message)" -Level ERROR
            # Try user-specific location as fallback
            try {
                $userShellPath = "$env:LOCALAPPDATA\Microsoft\Windows\Shell"
                if (-not (Test-Path $userShellPath)) {
                    New-Item -Path $userShellPath -ItemType Directory -Force | Out-Null
                }
                $layoutXML | Out-File -FilePath (Join-Path $userShellPath "LayoutModification.xml") -Encoding UTF8 -Force
                Write-RMMLog "Created user-specific taskbar layout as fallback" -Level SUCCESS
            } catch {
                Write-RMMLog "Failed to create fallback layout file: $($_.Exception.Message)" -Level WARN
            }
        }

        # Apply via Group Policy registry keys (machine-wide)
        try {
            $gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
            if (-not (Test-Path $gpPath)) {
                New-Item -Path $gpPath -Force | Out-Null
            }
            Set-ItemProperty -Path $gpPath -Name "LockedStartLayout" -Value 1 -Type DWORD
            Set-ItemProperty -Path $gpPath -Name "StartLayoutFile" -Value $layoutPath -Type String
            Write-RMMLog "Applied taskbar layout via Group Policy registry" -Level SUCCESS
        } catch {
            Write-RMMLog "Failed to set Group Policy registry keys: $($_.Exception.Message)" -Level WARN
        }

        # Configure default file associations (machine-wide)
        Write-RMMLog "Configuring default applications for all users..."

        try {
            # Set Outlook as default mail handler (machine-wide)
            $mailtoPath = "HKLM:\SOFTWARE\Classes\mailto\shell\open\command"
            if (-not (Test-Path $mailtoPath)) {
                New-Item -Path $mailtoPath -Force | Out-Null
            }
            $outlookPath = "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
            if (Test-Path $outlookPath) {
                Set-ItemProperty -Path $mailtoPath -Name "(Default)" -Value "`"$outlookPath`" -c IPM.Note /m `"%1`""
                Write-RMMLog "Set Outlook as system-wide default mail client" -Level SUCCESS
            }
        } catch {
            Write-RMMLog "Failed to set system-wide mail client: $($_.Exception.Message)" -Level WARN
        }

        try {
            # Configure Adobe Acrobat as default PDF viewer (machine-wide)
            $acrobatPath = "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
            if (Test-Path $acrobatPath) {
                $pdfPath = "HKLM:\SOFTWARE\Classes\.pdf"
                if (-not (Test-Path $pdfPath)) {
                    New-Item -Path $pdfPath -Force | Out-Null
                }
                Set-ItemProperty -Path $pdfPath -Name "(Default)" -Value "AcroExch.Document.DC"

                $acrobatClassPath = "HKLM:\SOFTWARE\Classes\AcroExch.Document.DC\shell\open\command"
                if (-not (Test-Path $acrobatClassPath)) {
                    New-Item -Path $acrobatClassPath -Force | Out-Null
                }
                Set-ItemProperty -Path $acrobatClassPath -Name "(Default)" -Value "`"$acrobatPath`" `"%1`""
                Write-RMMLog "Set Adobe Acrobat as system-wide default PDF viewer" -Level SUCCESS
            }
        } catch {
            Write-RMMLog "Failed to set system-wide PDF viewer: $($_.Exception.Message)" -Level WARN
        }

        # Configure new user defaults by modifying default user profile
        Write-RMMLog "Configuring defaults for new user accounts..."
        try {
            # Load default user registry hive
            $defaultUserPath = "C:\Users\Default\NTUSER.DAT"
            if (Test-Path $defaultUserPath) {
                & reg load "HKU\DefaultUser" $defaultUserPath 2>$null

                # Set mail associations for new users
                $newUserMailto = "HKU\DefaultUser\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\MAILTO\UserChoice"
                & reg add $newUserMailto /v ProgId /t REG_SZ /d "AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /f 2>$null

                # Set PDF associations for new users
                $newUserPdf = "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice"
                & reg add $newUserPdf /v ProgId /t REG_SZ /d "AcroExch.Document.DC" /f 2>$null

                # Unload registry hive
                & reg unload "HKU\DefaultUser" 2>$null
                Write-RMMLog "Configured default user profile for new accounts" -Level SUCCESS
            }
        } catch {
            Write-RMMLog "Failed to configure default user profile: $($_.Exception.Message)" -Level WARN
        }

        # Remove bloatware for all users (current and future)
        Write-RMMLog "Removing bloatware for all users..."
        try {
            # Remove for all existing users
            Get-AppxPackage -AllUsers *windowscommunicationsapps* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

            # Remove provisioned packages (prevents reinstall for new users)
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*windowscommunicationsapps*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

            # Additional common bloatware removal
            $bloatwareApps = @(
                "*Microsoft.BingWeather*",
                "*Microsoft.GetHelp*",
                "*Microsoft.Getstarted*",
                "*Microsoft.Microsoft3DViewer*",
                "*Microsoft.MicrosoftOfficeHub*",
                "*Microsoft.MicrosoftSolitaireCollection*",
                "*Microsoft.MixedReality.Portal*",
                "*Microsoft.Office.OneNote*",
                "*Microsoft.People*",
                "*Microsoft.SkypeApp*",
                "*Microsoft.Wallet*",
                "*Microsoft.WindowsCamera*",
                "*Microsoft.windowscommunicationsapps*",
                "*Microsoft.WindowsFeedbackHub*",
                "*Microsoft.WindowsMaps*",
                "*Microsoft.WindowsSoundRecorder*",
                "*Microsoft.Xbox.TCUI*",
                "*Microsoft.XboxApp*",
                "*Microsoft.XboxGameOverlay*",
                "*Microsoft.XboxIdentityProvider*",
                "*Microsoft.XboxSpeechToTextOverlay*",
                "*Microsoft.ZuneMusic*",
                "*Microsoft.ZuneVideo*"
            )

            foreach ($app in $bloatwareApps) {
                try {
                    Get-AppxPackage -AllUsers $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                } catch {
                    # Silently continue if app not found
                }
            }
            Write-RMMLog "Removed bloatware applications" -Level SUCCESS
        } catch {
            Write-RMMLog "Failed to remove some bloatware: $($_.Exception.Message)" -Level WARN
        }

        Write-RMMLog "Taskbar and application configuration completed for all users (current and future)" -Level SUCCESS

    } catch {
        Write-RMMLog "Taskbar configuration failed: $($_.Exception.Message)" -Level ERROR
    }
} elseif (-not $isWindows11) {
    Write-RMMLog "Non-Windows 11 system - skipping taskbar configuration" -Level INFO
} else {
    Write-RMMLog "Skipping taskbar configuration (SkipTaskbarConfig parameter)" -Level INFO
}
#endregion

#region 5. Azure AD User Addition
Write-RMMLog "=== PHASE 5: AZURE AD USER CONFIGURATION ===" -Level SUCCESS

if ($AzureADUser) {
    try {
        $azureUser = "AzureAD\$AzureADUser"
        Write-RMMLog "Validating Azure AD user: $AzureADUser"

        # Test if we can resolve the AzureAD domain
        try {
            $domain = ([System.DirectoryServices.DirectorySearcher]::new()).SearchRoot
            if ($domain) {
                Write-RMMLog "Domain services accessible for validation" -Level SUCCESS
            }
        } catch {
            Write-RMMLog "WARNING: Cannot validate domain connectivity: $($_.Exception.Message)" -Level WARN
            Write-RMMLog "Proceeding with user addition (may fail if user doesn't exist)" -Level WARN
        }

        # Check if user is already in Administrators group
        try {
            $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $azureUser -or $_.Name -eq $AzureADUser }
            if ($adminMembers) {
                Write-RMMLog "$azureUser is already a member of Administrators group" -Level SUCCESS
                return
            }
        } catch {
            Write-RMMLog "Could not check existing group membership: $($_.Exception.Message)" -Level WARN
        }

        # Attempt to add the user
        Write-RMMLog "Adding $azureUser to local Administrators group..."
        Add-LocalGroupMember -Group "Administrators" -Member $azureUser -ErrorAction Stop

        # Verify the addition was successful
        $verifyMembership = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $azureUser }
        if ($verifyMembership) {
            Write-RMMLog "Successfully added and verified $azureUser in Administrators group" -Level SUCCESS
        } else {
            Write-RMMLog "User was added but verification failed" -Level WARN
        }

    } catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -like "*already a member*") {
            Write-RMMLog "$azureUser is already a member of Administrators group" -Level SUCCESS
        } elseif ($errorMessage -like "*not found*" -or $errorMessage -like "*cannot be found*") {
            Write-RMMLog "ERROR: Azure AD user '$AzureADUser' not found or not accessible from this machine" -Level ERROR
            Write-RMMLog "Ensure the user exists in Azure AD and the machine is domain-joined" -Level ERROR
        } else {
            Write-RMMLog "Failed to add $azureUser to Administrators group: $errorMessage" -Level ERROR
        }
    }
} else {
    Write-RMMLog "No Azure AD user specified - skipping user addition" -Level INFO
}
#endregion

#region Final Status and Reboot Check
Write-RMMLog "=== SETUP COMPLETION STATUS ===" -Level SUCCESS

# Check if reboot is required
if (Test-PendingReboot) {
    Write-RMMLog "REBOOT REQUIRED - System restart recommended to complete all changes" -Level WARN
    $exitCode = 3010
} else {
    Write-RMMLog "No reboot required" -Level SUCCESS
    $exitCode = 0
}

# Final error summary
if ($global:RMMScriptErrors.Count -gt 0) {
    Write-RMMLog "=== ERRORS ENCOUNTERED DURING EXECUTION ===" -Level WARN
    $global:RMMScriptErrors | ForEach-Object { Write-RMMLog "- $_" -Level ERROR }
    Write-RMMLog "Total errors: $($global:RMMScriptErrors.Count)" -Level WARN

    # If critical errors occurred but we're not already setting reboot code, use error code
    if ($exitCode -eq 0 -and $global:RMMScriptErrors.Count -gt 3) {
        $exitCode = 1603  # Generic installer error for RMM systems
        Write-RMMLog "Setting exit code 1603 due to multiple critical errors" -Level WARN
    }
} else {
    Write-RMMLog "No errors encountered during execution" -Level SUCCESS
}

# Summary
Write-RMMLog "=== SUMMARY ===" -Level SUCCESS
Write-RMMLog "- Windows Updates: $(if ($SkipWindowsUpdates) { 'Skipped' } else { 'Completed' })"
Write-RMMLog "- HP Updates: $(if ($SkipHPIA -or -not $isHPDevice) { 'Skipped' } else { 'Completed' })"
Write-RMMLog "- Software cleanup: Completed"
Write-RMMLog "- Taskbar Config: $(if ($SkipTaskbarConfig -or -not $isWindows11) { 'Skipped' } else { 'Completed' })"
Write-RMMLog "- Azure AD User: $(if ($AzureADUser) { 'Configured' } else { 'Skipped' })"
Write-RMMLog "- Final Exit Code: $exitCode"
Write-RMMLog "=== RMM INTEGRATED SYSTEM SETUP COMPLETED ===" -Level SUCCESS

# Clear any remaining progress indicators
if ($ShowProgress) {
    Write-Progress -Activity "RMM System Setup" -Completed
}

exit $exitCode
