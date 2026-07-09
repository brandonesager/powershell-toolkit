<#
.SYNOPSIS
    Domain join and local admin configuration for new workstations

.DESCRIPTION
    Performs common onboarding steps for new domain workstations:
    - Rename computer
    - Join to domain with provided credentials
    - Enable built-in Administrator account
    - Create TechAdmin local account
    - Add domain user to local Administrators group

.PARAMETER NewComputerName
    New computer name (e.g., CLIENT-LT-01)

.PARAMETER DomainName
    Domain to join (e.g., CONTOSO)

.PARAMETER DomainUser
    Domain username to add as local admin (e.g., jdoe)

.PARAMETER Credential
    Domain admin credential for domain join operation

.PARAMETER LocalAdminPassword
    Password for built-in Administrator account

.PARAMETER TechAdminPassword
    Password for TechAdmin account

.PARAMETER RestartNow
    Restart the computer immediately after configuration

.EXAMPLE
    .\Initialize-DomainWorkstationOnboard.ps1 -NewComputerName "CLIENT-LT-01" -DomainName "CONTOSO" -DomainUser "jdoe" -Credential (Get-Credential) -LocalAdminPassword (Read-Host -AsSecureString) -TechAdminPassword (Read-Host -AsSecureString)

.EXAMPLE
    .\Initialize-DomainWorkstationOnboard.ps1 -NewComputerName "CLIENT-LT-01" -DomainName "CONTOSO" -DomainUser "jdoe" -Credential (Get-Credential) -LocalAdminPassword (Read-Host -AsSecureString) -TechAdminPassword (Read-Host -AsSecureString) -RestartNow

.NOTES
    Date: 2026-02-06
    Category: RMM-Deployment

.KEYWORDS
    provision, domain-join, RMM, SYSTEM, workstation
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$NewComputerName,

    [Parameter(Mandatory)]
    [string]$DomainName,

    [Parameter(Mandatory)]
    [string]$DomainUser,

    [Parameter(Mandatory)]
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
    [SecureString]$LocalAdminPassword,

    [Parameter(Mandatory)]
    [SecureString]$TechAdminPassword,

    [switch]$RestartNow
)

$ErrorActionPreference = "Stop"

try {
    Write-Output "=== Workstation Onboarding ==="
    Write-Output "Computer: $NewComputerName"
    Write-Output "Domain: $DomainName"
    Write-Output "Domain User: $DomainUser"

    $NeedsRestart = $false

    # Rename computer
    if ($env:COMPUTERNAME -ne $NewComputerName) {
        Write-Output "Renaming computer to $NewComputerName..."
        Rename-Computer -NewName $NewComputerName -Force
        Write-Output "Computer renamed. Restart required before domain join."
        $NeedsRestart = $true
    } else {
        Write-Output "Computer already named $NewComputerName"
    }

    # Domain join (if not already joined and no restart pending)
    if (-not $NeedsRestart) {
        $CurrentDomain = (Get-CimInstance Win32_ComputerSystem).Domain
        if ($CurrentDomain -ne "$DomainName.local" -and $CurrentDomain -ne $DomainName) {
            Write-Output "Joining domain $DomainName..."
            Add-Computer -DomainName $DomainName -Credential $Credential
            $NeedsRestart = $true
        } else {
            Write-Output "Already joined to domain: $CurrentDomain"
        }
    }

    # Enable built-in Administrator
    Write-Output "Configuring local Administrator account..."
    Enable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Set-LocalUser -Name "Administrator" -Password $LocalAdminPassword
    Write-Output "  Local Administrator enabled and password set"

    # Create TechAdmin
    $TechAdminExists = Get-LocalUser -Name "TechAdmin" -ErrorAction SilentlyContinue
    if (-not $TechAdminExists) {
        New-LocalUser -Name "TechAdmin" -Password $TechAdminPassword -PasswordNeverExpires -AccountNeverExpires
        Write-Output "  TechAdmin account created"
    }
    Add-LocalGroupMember -Group "Administrators" -Member "TechAdmin" -ErrorAction SilentlyContinue
    Write-Output "  TechAdmin added to Administrators"

    # Add domain user to local admins (after domain join)
    if (-not $NeedsRestart) {
        $DomainUserFull = "$DomainName\$DomainUser"
        Add-LocalGroupMember -Group "Administrators" -Member $DomainUserFull -ErrorAction SilentlyContinue
        Write-Output "  $DomainUserFull added to local Administrators"
    }

    # Remove default User if exists
    Remove-LocalGroupMember -Group "Administrators" -Member "User" -ErrorAction SilentlyContinue

    Write-Output "=== Summary ==="
    Get-LocalGroupMember -Group "Administrators" | Format-Table Name, PrincipalSource

    if ($NeedsRestart -and $RestartNow) {
        Write-Output "Restarting computer now..."
        Restart-Computer -Force
    } elseif ($NeedsRestart) {
        Write-Output "Restart required to complete configuration. Use -RestartNow to restart automatically."
    }

    exit 0

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "Stack: $($_.ScriptStackTrace)"
    exit 1
}
