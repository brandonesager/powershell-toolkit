<#
.SYNOPSIS
    [Brief description for RMM dashboard]
.DESCRIPTION
    [Detailed description with client impact and functionality]
    Designed for RMM deployment with PowerShell 5.1 compatibility
.NOTES
    PowerShell 5.1 compatible for RMM deployment
    Quick execution: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\ScriptName.ps1'
    With parameters: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\ScriptName.ps1' -Parameter1 Value1
    Category: RMM-Deployment
.EXAMPLE
    & .\ScriptName.ps1

.EXAMPLE
    & .\ScriptName.ps1 -ComputerName "SERVER01" -Remediate

.KEYWORDS
    RMM, SYSTEM, template, logging, exit-code
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    # Define parameters with proper types, validation, and defaults
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\temp\RMM-ScriptOutput-$(Get-Date -Format 'yyyyMMdd-HHmm').log",
    
    [Parameter(Mandatory = $false)]
    [switch]$Remediate,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Function to check and install required modules (PowerShell 5.1 compatible)
function Test-RequiredModule {
    param([string[]]$ModuleNames)
    
    $MissingModules = @()
    foreach ($Module in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $Module)) {
            $MissingModules += $Module
            Write-Output "[RMM]|WARN|MODULE|Module not installed: $Module|{`"action`":`"install_required`"}"
        }
        elseif (-not (Get-Module -Name $Module)) {
            Write-Output "[RMM]|INFO|MODULE|Importing module: $Module|{}"
            try {
                Import-Module $Module -Force
                Write-Output "[RMM]|SUCCESS|MODULE|Module imported: $Module|{}"
            }
            catch {
                Write-Output "[RMM]|ERROR|MODULE|Failed to import module: $Module|{`"error`":`"$($_.Exception.Message)`"}"
                return $false
            }
        }
        else {
            Write-Output "[RMM]|INFO|MODULE|Module already loaded: $Module|{}"
        }
    }
    
    if ($MissingModules.Count -gt 0) {
        Write-Output "[RMM]|ERROR|MODULE|Missing required modules|{`"modules`":`"$($MissingModules -join ', ')`"}"
        Write-Output "Install missing modules with: Install-Module $($MissingModules -join ', ') -Force"
        return $false
    }
    return $true
}

# Function to test WMI connectivity
function Test-WmiConnection {
    param([string]$ComputerName)
    
    try {
        $null = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
        Write-Output "[RMM]|SUCCESS|CONNECT|WMI connection verified|{`"computer`":`"$ComputerName`"}"
        return $true
    }
    catch {
        Write-Output "[RMM]|ERROR|CONNECT|WMI connection failed|{`"computer`":`"$ComputerName`",`"error`":`"$($_.Exception.Message)`"}"
        return $false
    }
}

# Function to test PowerShell remoting
function Test-PSRemoting {
    param([string]$ComputerName)
    
    if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
        return $true
    }
    
    try {
        $null = Invoke-Command -ComputerName $ComputerName -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        Write-Output "[RMM]|SUCCESS|CONNECT|PowerShell remoting verified|{`"computer`":`"$ComputerName`"}"
        return $true
    }
    catch {
        Write-Output "[RMM]|WARN|CONNECT|PowerShell remoting not available|{`"computer`":`"$ComputerName`",`"error`":`"$($_.Exception.Message)`"}"
        return $false
    }
}

# Function to write to registry for persistent settings
function Set-RMMRegistryValue {
    param(
        [string]$KeyPath = "HKLM:\SOFTWARE\RMM\Scripts",
        [string]$ValueName,
        [string]$ValueData,
        [string]$ValueType = "String"
    )
    
    try {
        if (-not (Test-Path $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $KeyPath -Name $ValueName -Value $ValueData -Type $ValueType
        Write-Output "[RMM]|SUCCESS|REGISTRY|Registry value set|{`"key`":`"$KeyPath`",`"name`":`"$ValueName`"}"
    }
    catch {
        Write-Output "[RMM]|ERROR|REGISTRY|Failed to set registry value|{`"error`":`"$($_.Exception.Message)`"}"
    }
}

# Function to write to Windows Event Log
function Write-RMMEvent {
    param(
        [string]$Source = "RMM-Scripts",
        [int]$EventID = 1000,
        [string]$EntryType = "Information",
        [string]$Message
    )
    
    try {
        # Create event source if it doesn't exist
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            New-EventLog -LogName Application -Source $Source
        }
        
        Write-EventLog -LogName Application -Source $Source -EventId $EventID -EntryType $EntryType -Message $Message
        Write-Output "[RMM]|SUCCESS|EVENT|Event logged|{`"source`":`"$Source`",`"id`":$EventID}"
    }
    catch {
        Write-Output "[RMM]|WARN|EVENT|Failed to write event log|{`"error`":`"$($_.Exception.Message)`"}"
    }
}

# Initialize start time for duration tracking
$StartTime = Get-Date

try {
    Write-Output "[RMM]|INFO|START|Starting [ScriptName]|{`"computer`":`"$ComputerName`",`"whatif`":$WhatIf,`"remediate`":$Remediate}"
    
    # 1. Check required modules (typically none for basic RMM scripts)
    $RequiredModules = @()  # Add modules like 'ActiveDirectory' if needed
    if ($RequiredModules.Count -gt 0) {
        if (-not (Test-RequiredModule -ModuleNames $RequiredModules)) {
            Write-Output "[RMM]|ERROR|PREREQ|Required modules not available|{}"
            exit 1
        }
    }
    
    # 2. Test connectivity to target computer
    if (-not (Test-WmiConnection -ComputerName $ComputerName)) {
        Write-Output "[RMM]|ERROR|CONNECTIVITY|Cannot connect to target computer|{`"computer`":`"$ComputerName`"}"
        exit 1
    }
    
    # Test PowerShell remoting (optional, for advanced operations)
    $PSRemotingAvailable = Test-PSRemoting -ComputerName $ComputerName
    
    # 3. Create log directory if needed
    $LogDirectory = Split-Path $LogPath -Parent
    if (-not (Test-Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    # 4. Main script logic
    Write-Output "[RMM]|INFO|EXECUTE|Starting main script operations|{}"
    
    $Results = @()
    
    if ($WhatIf) {
        Write-Output "[RMM]|INFO|WHATIF|Would perform operations on target|{`"computer`":`"$ComputerName`"}"
    } else {
        # Example: Get system information
        try {
            $ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName
            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
            
            $SystemInfo = [PSCustomObject]@{
                ComputerName = $ComputerInfo.Name
                Domain = $ComputerInfo.Domain
                Manufacturer = $ComputerInfo.Manufacturer
                Model = $ComputerInfo.Model
                TotalMemoryGB = [Math]::Round($ComputerInfo.TotalPhysicalMemory / 1GB, 2)
                OSName = $OSInfo.Caption
                OSVersion = $OSInfo.Version
                LastBootTime = $OSInfo.ConvertToDateTime($OSInfo.LastBootUpTime)
                FreeSpaceGB = [Math]::Round((Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName | Where-Object { $_.DriveType -eq 3 } | Measure-Object -Property FreeSpace -Sum).Sum / 1GB, 2)
                Timestamp = Get-Date
            }
            
            $Results += $SystemInfo
            
            Write-Output "[RMM]|SUCCESS|OPERATION|System information retrieved|{`"computer`":`"$($SystemInfo.ComputerName)`"}"
            
            # Example remediation action
            if ($Remediate) {
                Write-Output "[RMM]|INFO|REMEDIATE|Performing remediation actions|{}"
                
                # Example: Clear temp files
                $TempPath = "\\$ComputerName\C$\Windows\Temp"
                if (Test-Path $TempPath) {
                    $TempFiles = Get-ChildItem -Path $TempPath -Recurse -File | Measure-Object -Property Length -Sum
                    $TempSizeMB = [Math]::Round($TempFiles.Sum / 1MB, 2)
                    
                    if ($TempSizeMB -gt 100) {
                        Write-Output "[RMM]|WARN|CLEANUP|Large temp file accumulation detected|{`"sizeMB`":$TempSizeMB}"
                        # Remove files older than 7 days
                        Get-ChildItem -Path $TempPath -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue
                        Write-Output "[RMM]|SUCCESS|CLEANUP|Temp files cleaned|{}"
                    }
                }
            }
        }
        catch {
            Write-Output "[RMM]|ERROR|OPERATION|Failed to retrieve system information|{`"error`":`"$($_.Exception.Message)`"}"
            throw
        }
    }

    # 5. Export results and log
    if ($Results.Count -gt 0) {
        # Save to CSV
        $CsvPath = $LogPath -replace '\.log$', '.csv'
        $Results | Export-Csv -Path $CsvPath -NoTypeInformation
        
        # Save to log
        $Results | Out-String | Out-File -FilePath $LogPath -Append
        
        Write-Output "[RMM]|INFO|EXPORT|Results exported|{`"csv`":`"$CsvPath`",`"log`":`"$LogPath`",`"count`":$($Results.Count)}"
    }

    # 6. Set persistent registry value for tracking
    Set-RMMRegistryValue -ValueName "LastRun_$(Split-Path $MyInvocation.MyCommand.Name -LeafBase)" -ValueData (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    
    # 7. Write to Windows Event Log
    $EventMessage = "[ScriptName] completed successfully on $ComputerName. Duration: $((Get-Date) - $StartTime). Results: $($Results.Count)"
    Write-RMMEvent -Message $EventMessage
    
    # 8. Success completion
    $Duration = (Get-Date) - $StartTime
    Write-Output "[RMM]|SUCCESS|COMPLETE|[ScriptName] completed successfully|{`"computer`":`"$ComputerName`",`"duration`":`"$($Duration.TotalSeconds)s`",`"results`":$($Results.Count)}"
    
    # Exit with success code for RMM
    exit 0
}
catch {
    $ErrorMessage = "[ScriptName] failed on $ComputerName. Error: $($_.Exception.Message) Line: $($_.InvocationInfo.ScriptLineNumber)"
    Write-Output "[RMM]|ERROR|FAILURE|[ScriptName] failed|{`"computer`":`"$ComputerName`",`"error`":`"$($_.Exception.Message)`",`"line`":$($_.InvocationInfo.ScriptLineNumber)}"
    
    # Write error to Windows Event Log
    Write-RMMEvent -EventID 1001 -EntryType Error -Message $ErrorMessage
    
    # Set registry value for failure tracking
    Set-RMMRegistryValue -ValueName "LastError_$(Split-Path $MyInvocation.MyCommand.Name -LeafBase)" -ValueData (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    
    # Exit with error code for RMM
    exit 1
}