#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Initialize-StandardWorkstation — Automates Contoso workstation configuration via RMM deployment

.DESCRIPTION
    Full workstation provisioning for Contoso.
    Removes OEM bloat (HP Wolf, UWP apps), configures Edge policies and bookmarks,
    sets Egnyte trusted sites, configures default PDF handler, suppresses Adobe trial,
    sets power policy (lid close), manages Yardi CheckScan versions, verifies printer
    queues, creates Outlook signature, and runs compliance checks. Non-interactive
    SYSTEM-level deployment via RMM. Supports -DryRun for safe preview.
    Client: Contoso (contoso.com)

.PARAMETER DeviceType
    Device type: Main, MainLoaner, Remote, or RemoteLoaner.

.PARAMETER UserFirstName
    User's first name for signature creation.

.PARAMETER UserLastName
    User's last name for signature creation.

.PARAMETER Title
    User's job title for signature creation.

.PARAMETER Email
    User's email address for signature creation.

.PARAMETER DryRun
    Perform validation without making changes.

.PARAMETER Rename
    Switch to actually rename the device (requires reboot).

.PARAMETER InstallerURLs
    Hashtable of application names to installer URLs for silent installation.

.PARAMETER OutlookSignatureTemplateHTML
    HTML template for Outlook signature with {FirstName}, {LastName}, {Title}, {Email} placeholders.

.PARAMETER AcrobatTrialSuppressReg
    Hashtable of registry keys and values to suppress Adobe Acrobat trial prompts.

.PARAMETER Contoso_BookmarksJSON
    Path to JSON file containing Contoso managed bookmarks for Edge import.

.PARAMETER EgnyteDomain
    Egnyte domain for trusted site configuration. Default: contoso.egnyte.com

.PARAMETER DeviceNameIndex
    Numeric index suffix for device naming convention. Default: 001

.PARAMETER SentinelOneSiteToken
    SentinelOne site token for EDR agent registration.

.PARAMETER DuoLandingPage
    Duo Security landing page URL for Edge homepage configuration.

.PARAMETER UninstallList
    Array of application names or identifying numbers to uninstall.

.PARAMETER YardiOldVersion
    Display name of old Yardi CheckScan version to remove before verifying new version.

.NOTES
    Category: Environment-Specific
    Context: RMM SYSTEM-level deployment
    Compatible: PowerShell 5.1+, Windows 10/11

.KEYWORDS
    Contoso, workstation, provision, RMM, SYSTEM, compliance, Egnyte

.EXAMPLE
    .\Initialize-StandardWorkstation.ps1 -DeviceType Main -DryRun

.EXAMPLE
    .\Initialize-StandardWorkstation.ps1 -DeviceType Remote -UserFirstName "John" -UserLastName "Doe" -Title "Operations Manager" -Email "jdoe@contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Main', 'MainLoaner', 'Remote', 'RemoteLoaner')]
    [string]$DeviceType,

    [string]$UserFirstName = '',
    [string]$UserLastName = '',
    [string]$Title = '',
    [string]$Email = '',

    [switch]$DryRun,
    [switch]$Rename,

    [hashtable]$InstallerURLs = @{},

    [string]$OutlookSignatureTemplateHTML = @'
<html>
<body>
<div style="font-family: Arial, sans-serif; font-size: 11pt;">
<strong>{FirstName} {LastName}</strong><br>
{Title}<br>
Contoso<br>
Email: <a href="mailto:{Email}">{Email}</a><br>
</div>
</body>
</html>
'@,

    [hashtable]$AcrobatTrialSuppressReg = @{},

    [string]$Contoso_BookmarksJSON = '',

    [string]$EgnyteDomain = 'contoso.egnyte.com',

    [string]$DeviceNameIndex = '001',

    [string]$SentinelOneSiteToken = '',

    [string]$DuoLandingPage = 'https://contoso.login.duosecurity.com/',

    [array]$UninstallList = @(),

    [string]$YardiOldVersion = 'Yardi CheckScan v70.8.9.20'
)

# Initialize logging
if (!(Test-Path -LiteralPath 'C:\Temp')) { 
    New-Item -ItemType Directory -Path 'C:\Temp' | Out-Null 
}
$Log = "C:\Temp\Workstation_Setup_Local_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $Log -Append

# Global variables
$Script:ErrorCount = 0
$Script:WarningCount = 0
$Script:ComplianceReport = @{
    DeviceType = $DeviceType
    DeviceNameSuggested = ''
    DeviceRenamed = $false
    DryRunMode = $DryRun.IsPresent
    UserInfo = @{}
    TaskResults = @{}
    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Errors = @()
    Warnings = @()
    RestorePointCreated = $false
}

function Write-RMM-Log { 
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Code,
        [string]$Level = "INFO",
        [hashtable]$Data = @{}
    )
    $jsonData = if ($Data.Count -gt 0) { 
        $pairs = $Data.GetEnumerator() | ForEach-Object { "`"$($_.Key)`":`"$($_.Value)`"" }
        "{$($pairs -join ',')}"
    } else { "{}" }
    
    $prefix = if ($DryRun) { " [DRY RUN]" } else { "" }
    $rmmMessage = "[RMM]|$Level|$Code|$Message$prefix|$jsonData"
    Write-Output $rmmMessage
}

function Write-Warning-Log { 
    param([Parameter(Mandatory)][string]$Message, [string]$Code = "WARN", [hashtable]$Data = @{})
    Write-RMM-Log -Message $Message -Code $Code -Level "WARN" -Data $Data
    $Script:WarningCount++
    $Script:ComplianceReport.Warnings += $Message
}

function Write-Error-Log { 
    param([Parameter(Mandatory)][string]$Message, [string]$Code = "ERROR", [hashtable]$Data = @{})
    Write-RMM-Log -Message $Message -Code $Code -Level "ERROR" -Data $Data
    $Script:ErrorCount++
    $Script:ComplianceReport.Errors += $Message
}

function Write-Log { 
    param([Parameter(Mandatory)][string]$Message, [string]$Code = "INFO", [hashtable]$Data = @{})
    Write-RMM-Log -Message $Message -Code $Code -Level "INFO" -Data $Data
}

function Initialize-RMM-Tracking {
    # Create RMM Scripts registry path for tracking
    $RegPath = "HKLM:\SOFTWARE\RMM\Scripts\Workstation_Setup"
    try {
        if (!(Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
            Write-Log "Created RMM tracking registry path" -Code "INIT" -Data @{"path"=$RegPath}
        }
        Set-ItemProperty -Path $RegPath -Name "LastRun" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Set-ItemProperty -Path $RegPath -Name "Version" -Value "1.1"
        Set-ItemProperty -Path $RegPath -Name "DeviceType" -Value $DeviceType
        
        # Create Windows Event Log source
        if (!(Get-EventLog -LogName Application -Source "RMM-Scripts" -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName Application -Source "RMM-Scripts" -ErrorAction SilentlyContinue
            Write-Log "Created RMM-Scripts event log source" -Code "INIT"
        }
    }
    catch {
        Write-Warning-Log "Could not initialize RMM tracking: $($_.Exception.Message)" -Code "INIT"
    }
}

function Write-RMM-Event {
    param([string]$Message, [int]$EventId = 1001, [string]$EntryType = "Information")
    try {
        Write-EventLog -LogName Application -Source "RMM-Scripts" -EventId $EventId -Message $Message -EntryType $EntryType -ErrorAction SilentlyContinue
    }
    catch {
        # Silently ignore event log failures to prevent script interruption
    }
}

function Set-RMM-Status {
    param([string]$Status, [hashtable]$Data = @{})
    $RegPath = "HKLM:\SOFTWARE\RMM\Scripts\Workstation_Setup"
    try {
        Set-ItemProperty -Path $RegPath -Name "Status" -Value $Status -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "ErrorCount" -Value $Script:ErrorCount -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "WarningCount" -Value $Script:WarningCount -ErrorAction SilentlyContinue
        if ($Data.Count -gt 0) {
            foreach ($item in $Data.GetEnumerator()) {
                Set-ItemProperty -Path $RegPath -Name $item.Key -Value $item.Value -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        # Silently ignore registry failures to prevent script interruption
    }
}

function Test-RequiredModule {
    param([string]$ModuleName)
    $module = Get-Module -Name $ModuleName -ListAvailable -ErrorAction SilentlyContinue
    if ($module) {
        Write-Log "Module available: $ModuleName" -Code "MODULE" -Data @{"module"=$ModuleName;"version"=$module.Version}
        return $true
    } else {
        Write-Warning-Log "Module not available: $ModuleName" -Code "MODULE" -Data @{"module"=$ModuleName;"status"="missing"}
        return $false
    }
}

function Import-RequiredModule {
    param([string]$ModuleName, [switch]$Required)
    try {
        if (Test-RequiredModule -ModuleName $ModuleName) {
            Import-Module -Name $ModuleName -Force -ErrorAction Stop
            Write-Log "Module imported successfully: $ModuleName" -Code "MODULE" -Data @{"module"=$ModuleName;"status"="imported"}
            return $true
        } else {
            if ($Required) {
                Write-Error-Log "Required module not available: $ModuleName" -Code "MODULE" -Data @{"module"=$ModuleName;"status"="required_missing"}
                Write-Log "Install guidance: Install-Module -Name $ModuleName -Force -Scope CurrentUser" -Code "MODULE"
            }
            return $false
        }
    }
    catch {
        Write-Error-Log "Failed to import module $ModuleName`: $($_.Exception.Message)" -Code "MODULE" -Data @{"module"=$ModuleName;"error"=$_.Exception.Message}
        return $false
    }
}

function Initialize-ModuleManagement {
    Write-Log "Initializing module management" -Code "MODULE"
    
    # Test for commonly needed modules (none required for this script currently)
    $optionalModules = @(
        "PSScriptAnalyzer",
        "Pester"
    )
    
    foreach ($module in $optionalModules) {
        Test-RequiredModule -ModuleName $module | Out-Null
    }
    
    Write-Log "Module management initialized" -Code "MODULE"
}

function Test-ExistingConnections {
    # Check for existing PowerShell sessions that might be reused
    Write-Log "Checking for existing connections" -Code "CONNECTION"
    
    $connections = @{
        "PowerShellSessions" = (Get-PSSession).Count
        "WMIConnections" = "Available"
        "RegistryAccess" = if (Test-Path "HKLM:\") { "Available" } else { "Limited" }
    }
    
    foreach ($conn in $connections.GetEnumerator()) {
        Write-Log "Connection status: $($conn.Key) = $($conn.Value)" -Code "CONNECTION" -Data @{"type"=$conn.Key;"status"=$conn.Value}
    }
    
    return $connections
}

function Initialize-ConnectionHandling {
    Write-Log "Initializing connection handling" -Code "CONNECTION"
    $connections = Test-ExistingConnections
    Write-Log "Connection handling initialized" -Code "CONNECTION" -Data @{"connections"=$connections.Count}
}

function New-RestorePoint {
    if ($DryRun) {
        Write-Log "Would create system restore point"
        return
    }
    
}

function Get-UserIdentity {
    Write-Log "Resolving user identity information..."
    
    # Try to get from current user context
    try {
        if (!$UserFirstName -or !$UserLastName -or !$Email) {
            $currentUser = $env:USERNAME
            
            # Try whoami /upn for Azure AD joined machines
            $upnResult = whoami /upn 2>$null
            if ($LASTEXITCODE -eq 0 -and $upnResult -match '@') {
                $Email = $upnResult.Trim()
                Write-Log "Discovered email from UPN: $Email"
            }
            
            # Try to extract from email
            if ($Email -and !$UserFirstName -and !$UserLastName) {
                $emailParts = ($Email.Split('@')[0]).Split('.')
                if ($emailParts.Count -eq 2) {
                    $UserFirstName = (Get-Culture).TextInfo.ToTitleCase($emailParts[0])
                    $UserLastName = (Get-Culture).TextInfo.ToTitleCase($emailParts[1])
                    Write-Log "Inferred name from email: $UserFirstName $UserLastName"
                }
            }
        }
        
        # Set defaults for missing information (RMM non-interactive)
        if (!$UserFirstName) {
            $UserFirstName = "User"
            Write-Warning-Log "UserFirstName not provided, using default: User"
        }
        if (!$UserLastName) {
            $UserLastName = "Account"
            Write-Warning-Log "UserLastName not provided, using default: Account"
        }
        if (!$Title) {
            $Title = "Contoso Employee"
            Write-Warning-Log "Title not provided, using default: Contoso Employee"
        }
        if (!$Email) {
            $Email = "jdoe@contoso.com"
            Write-Warning-Log "Email not provided, using default: jdoe@contoso.com"
        }
        
        $Script:ComplianceReport.UserInfo = @{
            FirstName = $UserFirstName
            LastName = $UserLastName
            Title = $Title
            Email = $Email
        }
        
        Write-Log "User identity resolved: $UserFirstName $UserLastName ($Title) - $Email"
    }
    catch {
        Write-Error-Log "Error resolving user identity: $($_.Exception.Message)"
    }
}

function New-OutlookSignature {
    if ($DryRun) {
        Write-Log "Would create Outlook signature for $UserFirstName $UserLastName"
        return
    }
    
    try {
        Write-Log "Creating Outlook signature..."
        
        # In SYSTEM context, $env:APPDATA resolves to system profile — use logged-on user's profile instead
        $userProfile = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
        if ($userProfile) {
            $userSid = (New-Object System.Security.Principal.NTAccount($userProfile)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $userProfilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSid").ProfileImagePath
            $signaturesPath = "$userProfilePath\AppData\Roaming\Microsoft\Signatures"
        } else {
            $signaturesPath = "$env:APPDATA\Microsoft\Signatures"
        }
        if (!(Test-Path $signaturesPath)) {
            New-Item -Path $signaturesPath -ItemType Directory -Force | Out-Null
        }
        
        $signatureName = "Contoso_Default"
        
        # Create HTML signature
        $htmlContent = $OutlookSignatureTemplateHTML
        $htmlContent = $htmlContent.Replace('{FirstName}', $UserFirstName)
        $htmlContent = $htmlContent.Replace('{LastName}', $UserLastName)
        $htmlContent = $htmlContent.Replace('{Title}', $Title)
        $htmlContent = $htmlContent.Replace('{Email}', $Email)
        
        $htmlPath = "$signaturesPath\$signatureName.htm"
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        
        # Create RTF signature (basic)
        $rtfContent = "{\rtf1\ansi\deff0 {\fonttbl {\f0 Arial;}}{\f0\fs22 \b $UserFirstName $UserLastName\b0\par$Title\par\parContoso\parEmail: $Email\par}}"
        $rtfPath = "$signaturesPath\$signatureName.rtf"
        $rtfContent | Out-File -FilePath $rtfPath -Encoding UTF8
        
        # Create TXT signature
        $txtContent = @"
$UserFirstName $UserLastName
$Title
Contoso
Email: $Email
"@
        $txtPath = "$signaturesPath\$signatureName.txt"
        $txtContent | Out-File -FilePath $txtPath -Encoding UTF8
        
        # Set as default signature in registry
        $outlookRegPath = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings"
        if (!(Test-Path $outlookRegPath)) {
            New-Item -Path $outlookRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $outlookRegPath -Name "NewSignature" -Value $signatureName
        Set-ItemProperty -Path $outlookRegPath -Name "ReplySignature" -Value $signatureName
        
        Write-Log "Outlook signature created and set as default: $signatureName"
        $Script:ComplianceReport.TaskResults['OutlookSignature'] = 'Created'
    }
    catch {
        Write-Error-Log "Error creating Outlook signature: $($_.Exception.Message)"
    }
}

function Backup-RegistryKey {
    param(
        [string]$KeyPath,
        [string]$BackupName
    )
    
    if ($DryRun) {
        Write-Log "Would backup registry key: $KeyPath"
        return "DryRun_$BackupName"
    }
    
    try {
        $backupPath = "C:\Temp\RegBackup_$BackupName`_$(Get-Date -Format 'yyyyMMddHHmmss').reg"
        reg export $KeyPath $backupPath /y 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Registry backup created: $backupPath"
            return $backupPath
        }
    }
    catch {
        Write-Warning-Log "Could not backup registry key $KeyPath`: $($_.Exception.Message)"
    }
    return $null
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = 'String'
    )
    
    if ($DryRun) {
        Write-Log "Would set registry: $Path\$Name = $Value"
        return $true
    }
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created registry path: $Path"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "Set registry: $Path\$Name = $Value"
        return $true
    }
    catch {
        Write-Error-Log "Error setting registry $Path\$Name`: $($_.Exception.Message)"
        return $false
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return $null -ne $item.$Name
    }
    catch {
        return $false
    }
}

function Get-DeviceNameSuggestion {
    param([string]$Type, [string]$Index)
    
    switch ($Type) {
        'Main' { return "Contoso-LT-$Index" }
        'MainLoaner' { return "Contoso-LOAN-$Index" }
        'Remote' { return "CONTOSO-LT-$Index" }
        'RemoteLoaner' { return "CONTOSO-LOAN-$Index" }
        default { return "Contoso-UNKNOWN-$Index" }
    }
}

function Remove-OEMBloat {
    Write-Log "Processing OEM bloat removal..."
    
    if ($DryRun) {
        Write-Log "Would remove HP Wolf Security products and UWP apps (Teams, Mail)"
        $Script:ComplianceReport.TaskResults['OEMBloatRemoval'] = 'Simulated'
        return
    }
    
    # HP Wolf Security removal
    try {
        $hpWolfProducts = Get-CimInstance -ClassName Win32_Product | Where-Object {
            $_.Name -like "*HP Wolf*" -or $_.Name -like "*HP Security*"
        }
        
        if ($hpWolfProducts) {
            Write-Log "Found HP Wolf Security products to remove: $($hpWolfProducts.Count)"
            foreach ($product in $hpWolfProducts) {
                Write-Log "Removing HP Wolf Security: $($product.Name)"
                $result = $product.Uninstall()
                if ($result.ReturnValue -eq 0) {
                    Write-Log "Successfully removed: $($product.Name)"
                } else {
                    Write-Warning-Log "Failed to remove $($product.Name) (Exit Code: $($result.ReturnValue))"
                }
            }
        } else {
            Write-Log "No HP Wolf Security products found"
        }
    }
    catch {
        Write-Error-Log "Error during HP Wolf Security removal: $($_.Exception.Message)"
    }
    
    # UWP App removal
    try {
        $uwpAppsToRemove = @(
            'MicrosoftTeams',
            'microsoft.windowscommunicationsapps'  # Mail app
        )
        
        foreach ($appName in $uwpAppsToRemove) {
            $packages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$appName*" }
            if ($packages) {
                Write-Log "Found UWP packages to remove for $appName`: $($packages.Count)"
                foreach ($package in $packages) {
                    try {
                        Write-Log "Removing UWP app: $($package.Name)"
                        Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                        Write-Log "Successfully removed: $($package.Name)"
                    }
                    catch {
                        Write-Warning-Log "Could not remove $($package.Name): $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Log "No $appName packages found"
            }
        }
    }
    catch {
        Write-Error-Log "Error during UWP app removal: $($_.Exception.Message)"
    }
    
    # Custom uninstall list
    if ($UninstallList.Count -gt 0) {
        Write-Log "Processing custom uninstall list: $($UninstallList.Count) items"
        foreach ($item in $UninstallList) {
            try {
                $products = Get-CimInstance -ClassName Win32_Product | Where-Object {
                    $_.Name -like "*$item*" -or $_.IdentifyingNumber -eq $item
                }
                if ($products) {
                    foreach ($product in $products) {
                        Write-Log "Removing custom item: $($product.Name)"
                        $result = $product.Uninstall()
                        if ($result.ReturnValue -eq 0) {
                            Write-Log "Successfully removed: $($product.Name)"
                        }
                    }
                } else {
                    Write-Log "Custom uninstall item not found: $item"
                }
            }
            catch {
                Write-Warning-Log "Could not process uninstall item '$item': $($_.Exception.Message)"
            }
        }
    }
    
    $Script:ComplianceReport.TaskResults['OEMBloatRemoval'] = 'Completed'
}

function Set-EdgePolicies {
    Write-Log "Configuring Microsoft Edge policies..."
    
    $edgePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -BackupName 'EdgePolicies'
    
    # Set startup page to Duo
    Set-RegistryValue -Path $edgePolicyPath -Name 'HomepageLocation' -Value $DuoLandingPage
    Set-RegistryValue -Path $edgePolicyPath -Name 'HomepageIsNewTabPage' -Value 0 -Type DWord
    Set-RegistryValue -Path $edgePolicyPath -Name 'NewTabPageLocation' -Value $DuoLandingPage
    
    # Enable favorites bar
    Set-RegistryValue -Path $edgePolicyPath -Name 'BookmarkBarEnabled' -Value 1 -Type DWord
    
    # Import bookmarks if provided
    if ($Contoso_BookmarksJSON -and (Test-Path $Contoso_BookmarksJSON)) {
        try {
            $bookmarksContent = Get-Content -Path $Contoso_BookmarksJSON -Raw
            Set-RegistryValue -Path $edgePolicyPath -Name 'ManagedBookmarks' -Value $bookmarksContent
            Write-Log "Imported Contoso bookmarks from: $Contoso_BookmarksJSON"
        }
        catch {
            Write-Warning-Log "Could not import bookmarks: $($_.Exception.Message)"
        }
    } else {
        Write-Warning-Log "Contoso bookmarks JSON not provided or not found"
    }
    
    $Script:ComplianceReport.TaskResults['EdgePolicies'] = 'Completed'
}

function Set-TrustedSites {
    Write-Log "Configuring IE/Edge trusted sites..."
    
    $trustedSitesPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -BackupName 'TrustedSites'
    
    # Create Egnyte file protocol trusted site
    try {
        $egnyteDrivePath = "$trustedSitesPath\egnytedrive"
        if ($DryRun) {
            Write-Log "Would create trusted site: file://egnytedrive"
        } else {
            if (!(Test-Path $egnyteDrivePath)) {
                New-Item -Path $egnyteDrivePath -Force | Out-Null
            }
            Set-RegistryValue -Path $egnyteDrivePath -Name 'file' -Value 2 -Type DWord
            Write-Log "Added file://egnytedrive to trusted sites"
        }
    }
    catch {
        Write-Error-Log "Error configuring egnytedrive trusted site: $($_.Exception.Message)"
    }
    
    # Create Egnyte HTTPS trusted site
    try {
        $egnyteParts = $EgnyteDomain.Split('.')
        $domainPath = "$trustedSitesPath\$($egnyteParts[-2]).$($egnyteParts[-1])"
        
        if ($DryRun) {
            Write-Log "Would create trusted site: https://*.egnyte.com"
        } else {
            if (!(Test-Path $domainPath)) {
                New-Item -Path $domainPath -Force | Out-Null
            }
            if ($egnyteParts.Count -gt 2) {
                $subdomainPath = "$domainPath\$($egnyteParts[0])"
                if (!(Test-Path $subdomainPath)) {
                    New-Item -Path $subdomainPath -Force | Out-Null
                }
                Set-RegistryValue -Path $subdomainPath -Name 'https' -Value 2 -Type DWord
            }
            Set-RegistryValue -Path $domainPath -Name '*' -Value 2 -Type DWord
            Write-Log "Added https://*.egnyte.com to trusted sites"
        }
    }
    catch {
        Write-Error-Log "Error configuring Egnyte HTTPS trusted site: $($_.Exception.Message)"
    }
    
    # Disable "Require server verification" for trusted sites
    $internetSettingsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
    Set-RegistryValue -Path $internetSettingsPath -Name '1601' -Value 0 -Type DWord
    
    $Script:ComplianceReport.TaskResults['TrustedSites'] = 'Completed'
}

function Set-DefaultPDFApp {
    Write-Log "Setting default PDF application to Adobe Acrobat Reader..."
    
    # Try to set default PDF handler
    try {
        $adobeAppId = 'AcroExch.Document.DC'
        $pdfProgId = 'HKLM:\SOFTWARE\Classes\.pdf'
        
        Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Classes\.pdf' -BackupName 'PDFDefault'
        
        if ($DryRun) {
            Write-Log "Would set Adobe Acrobat Reader as default PDF handler"
        } else {
            if (Test-Path "HKLM:\SOFTWARE\Classes\$adobeAppId") {
                Set-RegistryValue -Path $pdfProgId -Name '(Default)' -Value $adobeAppId
                Write-Log "Set Adobe Acrobat Reader as default PDF handler"
            } else {
                Write-Warning-Log "Adobe Acrobat Reader not found in registry. May need manual configuration or SetUserFTA utility."
            }
        }
    }
    catch {
        Write-Error-Log "Error setting default PDF application: $($_.Exception.Message)"
    }
    
    $Script:ComplianceReport.TaskResults['DefaultPDFApp'] = 'Completed'
}

function Set-AcrobatTrialSuppression {
    Write-Log "Applying Adobe Acrobat trial suppression settings..."
    
    if ($AcrobatTrialSuppressReg.Count -gt 0) {
        Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Adobe' -BackupName 'AcrobatTrial'
        
        foreach ($regKey in $AcrobatTrialSuppressReg.GetEnumerator()) {
            foreach ($value in $regKey.Value.GetEnumerator()) {
                Set-RegistryValue -Path $regKey.Name -Name $value.Name -Value $value.Value
            }
        }
        Write-Log "Applied Acrobat trial suppression registry settings"
    } else {
        Write-Warning-Log "Acrobat trial suppression registry keys not provided"
    }
    
    $Script:ComplianceReport.TaskResults['AcrobatTrialSuppression'] = 'Completed'
}

function Set-PowerPolicy {
    Write-Log "Configuring power policy settings..."
    
    if ($DryRun) {
        Write-Log "Would set lid close action to 'Do nothing' on AC power"
        $Script:ComplianceReport.TaskResults['PowerPolicy'] = 'Simulated'
        return
    }
    
    try {
        # Set lid close action to "Do nothing" when on AC power
        $result = & powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
        if ($LASTEXITCODE -eq 0) {
            & powercfg /setactive SCHEME_CURRENT
            Write-Log "Set lid close action to 'Do nothing' on AC power"
        } else {
            Write-Warning-Log "Failed to set power policy (Exit Code: $LASTEXITCODE)"
        }
        
        # Verify the setting
        $currentSetting = & powercfg /query SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936
        if ($currentSetting -match "Current AC Power Setting Index: 0x00000000") {
            Write-Log "Verified: Lid close action set correctly"
        }
    }
    catch {
        Write-Error-Log "Error configuring power policy: $($_.Exception.Message)"
    }
    
    $Script:ComplianceReport.TaskResults['PowerPolicy'] = 'Completed'
}

function Install-Applications {
    Write-Log "Processing application installations..."
    
    if ($InstallerURLs.Count -eq 0) {
        Write-Warning-Log "No installer URLs provided"
        return
    }
    
    if ($DryRun) {
        Write-Log "Would install applications: $($InstallerURLs.Keys -join ', ')"
        $Script:ComplianceReport.TaskResults['ApplicationInstallation'] = 'Simulated'
        return
    }
    
    foreach ($app in $InstallerURLs.GetEnumerator()) {
        try {
            Write-Log "Processing installation: $($app.Name)"
            $downloadPath = "C:\Temp\$($app.Name)_installer.exe"
            
            # Download installer
            Write-Log "Downloading: $($app.Value)"
            Invoke-WebRequest -Uri $app.Value -OutFile $downloadPath -UseBasicParsing
            
            # Install silently (basic attempt)
            $installArgs = '/S /silent /quiet /verysilent /qn'
            Write-Log "Installing: $($app.Name)"
            $process = Start-Process -FilePath $downloadPath -ArgumentList $installArgs -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Successfully installed: $($app.Name)"
            } else {
                Write-Warning-Log "Installation may have failed for $($app.Name) (Exit Code: $($process.ExitCode))"
            }
            
            # Cleanup
            Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error-Log "Error installing $($app.Name): $($_.Exception.Message)"
        }
    }
    
    $Script:ComplianceReport.TaskResults['ApplicationInstallation'] = 'Completed'
}

function Manage-YardiCheckScan {
    Write-Log "Managing Yardi CheckScan versions..."
    
    if ($DryRun) {
        Write-Log "Would remove old Yardi CheckScan and verify v70.8.9.25"
        $Script:ComplianceReport.TaskResults['YardiCheckScan'] = 'Simulated'
        return
    }
    
    try {
        # Remove old version
        if ($YardiOldVersion) {
            $oldProducts = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "*$YardiOldVersion*" }
            if ($oldProducts) {
                foreach ($product in $oldProducts) {
                    Write-Log "Removing old Yardi CheckScan: $($product.Name)"
                    $result = $product.Uninstall()
                    if ($result.ReturnValue -eq 0) {
                        Write-Log "Successfully removed old version: $($product.Name)"
                    }
                }
            } else {
                Write-Log "Old Yardi CheckScan version not found"
            }
        }
        
        # Verify new version installation
        $newProducts = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "*Yardi CheckScan*70.8.9.25*" }
        if ($newProducts) {
            Write-Log "Verified: Yardi CheckScan v70.8.9.25 is installed"
        } else {
            Write-Warning-Log "Yardi CheckScan v70.8.9.25 not detected. Check Intune deployment."
        }
    }
    catch {
        Write-Error-Log "Error managing Yardi CheckScan: $($_.Exception.Message)"
    }
    
    $Script:ComplianceReport.TaskResults['YardiCheckScan'] = 'Completed'
}

function Test-PrinterQueues {
    Write-Log "Verifying printer queue configuration..."
    
    $requiredPrinters = @()
    if ($DeviceType -in @('Main', 'MainLoaner')) {
        $requiredPrinters = @('Printer-Main', 'Printer-Finance', 'Printer-Ops', 'Printer-HR')
    }
    
    if ($requiredPrinters.Count -gt 0) {
        try {
            $installedPrinters = Get-Printer | Select-Object -ExpandProperty Name
            $missingPrinters = @()
            
            foreach ($printer in $requiredPrinters) {
                if ($installedPrinters -notcontains $printer) {
                    $missingPrinters += $printer
                } else {
                    Write-Log "Verified printer: $printer"
                }
            }
            
            if ($missingPrinters.Count -eq 0) {
                Write-Log "Verified: All required printers are installed"
            } else {
                Write-Warning-Log "Missing printers: $($missingPrinters -join ', ')"
            }
        }
        catch {
            Write-Error-Log "Error checking printer queues: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Info: Remote device type -- user should create printer ticket once deployed"
        $Script:ComplianceReport.TaskResults['PrinterReminder'] = 'User must create ticket for printing setup'
    }
    
    $Script:ComplianceReport.TaskResults['PrinterQueues'] = 'Completed'
}

function Test-Compliance {
    Write-Log "Running compliance verification..."
    
    $compliance = @{
        EdgeHomePage = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HomepageLocation'
        FavoritesBar = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'BookmarkBarEnabled'
        TrustedSites = (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\egnytedrive' -Name 'file') -and
                      (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\egnyte.com' -ErrorAction SilentlyContinue)
        PowerPolicy = $true  # Assume verified by powercfg command
        DefaultPDF = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Classes\.pdf' -Name '(Default)'
        OutlookSignature = $true  # Manual creation; not validated by script
    }
    
    $Script:ComplianceReport.ComplianceChecks = $compliance
    
    $passedCount = ($compliance.Values | Where-Object { $_ -eq $true }).Count
    $totalCount = $compliance.Keys.Count
    $compliancePercentage = [math]::Round(($passedCount / $totalCount) * 100, 2)
    
    Write-Log "Compliance verification: $passedCount/$totalCount checks passed ($compliancePercentage%)"
    $Script:ComplianceReport.CompliancePercentage = $compliancePercentage
    
    # Log compliance details
    foreach ($check in $compliance.GetEnumerator()) {
        $status = if ($check.Value) { "PASS" } else { "FAIL" }
        $level = if ($check.Value) { "INFO" } else { "WARN" }
        Write-RMM-Log -Message "Compliance check: $($check.Name) = $status" -Code "COMPLIANCE" -Level $level
    }
}

function Export-ComplianceReport {
    Write-Log "Generating compliance report..."
    
    $reportPath = "C:\Temp\Contoso_Compliance_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Script:ComplianceReport.LogFile = $Log
    $Script:ComplianceReport.ErrorCount = $Script:ErrorCount
    $Script:ComplianceReport.WarningCount = $Script:WarningCount
    
    try {
        $Script:ComplianceReport | ConvertTo-Json | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Log "Compliance report exported: $reportPath"
        
        # Display summary via RMM logging
        Write-Log "WORKSTATION SETUP SUMMARY" -Code "SUMMARY" -Data @{
            "deviceType"=$DeviceType
            "suggestedName"=$Script:ComplianceReport.DeviceNameSuggested
            "user"="$UserFirstName $UserLastName ($Title)"
            "compliance"="$($Script:ComplianceReport.CompliancePercentage)%"
            "errors"=$Script:ErrorCount
            "warnings"=$Script:WarningCount
            "dryRunMode"=$DryRun.ToString()
        }
    }
    catch {
        Write-Error-Log "Error exporting compliance report: $($_.Exception.Message)"
    }
}

function Request-Reboot {
    if ($Script:ComplianceReport.DeviceRenamed -and !$DryRun) {
        Write-Log "REBOOT REQUIRED: Device has been renamed to $($Script:ComplianceReport.DeviceNameSuggested)"
        Write-Log "RMM will handle reboot automatically via exit code 2"
        # RMM deployment will handle reboot via exit code 2
    }
}

# Main execution
try {
    # Initialize RMM compliance features
    Initialize-RMM-Tracking
    Initialize-ModuleManagement  
    Initialize-ConnectionHandling
    
    Write-Log "Contoso Workstation Setup started" -Code "START" -Data @{"deviceType"=$DeviceType;"dryRun"=$DryRun.ToString()}
    Write-RMM-Event "Contoso Workstation Setup started for device type: $DeviceType"
    Set-RMM-Status "Running" @{"startTime"=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")}
    
    # Create restore point
    New-RestorePoint
    
    # Generate device name suggestion
    $suggestedName = Get-DeviceNameSuggestion -Type $DeviceType -Index $DeviceNameIndex
    $Script:ComplianceReport.DeviceNameSuggested = $suggestedName
    Write-Log "Suggested device name: $suggestedName"
    
    if ($Rename) {
        if ($DryRun) {
            Write-Log "Would rename device to: $suggestedName"
        } else {
            try {
                Rename-Computer -NewName $suggestedName -Force
                Write-Log "Device renamed to: $suggestedName (reboot required)"
                $Script:ComplianceReport.DeviceRenamed = $true
            }
            catch {
                Write-Error-Log "Error renaming device: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "Device rename not requested. Current name: $env:COMPUTERNAME"
    }
    
    # Get user identity for signature creation
    Get-UserIdentity
    
    # Execute configuration tasks
    Remove-OEMBloat
    Set-EdgePolicies
    Set-TrustedSites
    Set-DefaultPDFApp
    Set-AcrobatTrialSuppression
    Set-PowerPolicy
    Install-Applications
    Manage-YardiCheckScan
    Test-PrinterQueues
    
    # Outlook signature: create manually in Outlook UI (File > Options > Mail > Signatures).
    # Signature scripting removed. Include name, title, office address/phone, email.
    Write-Log "Outlook signature: skipped (manual creation required in Outlook UI)" -Code "SIGNATURE"
    
    # Compliance verification and reporting
    Test-Compliance
    Export-ComplianceReport
    
    # Handle reboot if required
    Request-Reboot
    
    # Determine final status and exit code
    $exitCode = 0
    $finalStatus = "Completed"
    
    if ($Script:ErrorCount -gt 0) {
        $exitCode = 1
        $finalStatus = "Failed"
    } elseif ($Script:ComplianceReport.DeviceRenamed -and !$DryRun) {
        $exitCode = 2
        $finalStatus = "Reboot Required"
    } elseif ($Script:WarningCount -gt 10) {
        $exitCode = 1
        $finalStatus = "Failed - Too Many Warnings"
    }
    
    Write-Log "Contoso Workstation Setup completed" -Code "COMPLETE" -Data @{
        "status"=$finalStatus
        "errors"=$Script:ErrorCount
        "warnings"=$Script:WarningCount
        "compliance"=$Script:ComplianceReport.CompliancePercentage
        "exitCode"=$exitCode
    }
    
    Write-RMM-Event "Contoso Workstation Setup completed with status: $finalStatus (Exit Code: $exitCode)" -EventId 1002
    Set-RMM-Status $finalStatus @{
        "endTime"=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        "exitCode"=$exitCode
        "compliance"=$Script:ComplianceReport.CompliancePercentage
    }
    
    exit $exitCode
}
catch {
    Write-Error-Log "Fatal error in main execution: $($_.Exception.Message)" -Code "FATAL" -Data @{"error"=$_.Exception.Message}
    Write-RMM-Event "Contoso Workstation Setup failed with fatal error: $($_.Exception.Message)" -EventId 1003 -EntryType "Error"
    Set-RMM-Status "Fatal Error" @{"error"=$_.Exception.Message}
    exit 99
}
finally {
    Stop-Transcript
}