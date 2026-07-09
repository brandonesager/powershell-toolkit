#Requires -Version 5.1

<#
.SYNOPSIS
    Set-EgnyteOffice365Integration — Provisions Egnyte as an Office 365 storage location via registry detection

.DESCRIPTION
    Detects the installed Office version, checks if the Egnyte storage provider
    (tp_egnyte_plus) is already registered in the ServicesManagerCache, and triggers
    the ms-office-storage-host provisioning URI if not present. Idempotent — skips
    if Egnyte is already configured.

.NOTES
    Category: Environment-Specific
.KEYWORDS
    Egnyte, Office, integration, registry, provision
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$CurrentServiceId = 'tp_egnyte_plus';

function Get-EgnyteExists {
    param (
        $OfficeVersion
    )

    $exists = 0;

    try {
        $localServices = Get-ChildItem -Path "HKCU:\Software\Microsoft\Office\$OfficeVersion\Common\ServicesManagerCache\Local" -ErrorAction Stop
        foreach ($value in $localServices) {
            $service = Get-ItemProperty "HKCU:\$value"  -ErrorAction Stop

            if ($service.ServiceId -eq $CurrentServiceId) {
                $exists = 1;
                break
            }
        }
    } catch {
        # Registry path not found or access error — treat as not exists
    }

    $exists;
}

function Get-OfficeVersion {
    $officeVersionX32 = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) | Select-Object -ExpandProperty VersionToReport
    $officeVersionX64 = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

    if ($officeVersionX32 -ne $null -and $officeVersionX64 -ne $null) {
        $officeVersion = $officeVersionX64 #Use x64 as default.
    } elseif($officeVersionX32 -eq $null -or $officeVersionX64 -eq $null) {
        $officeVersion = $officeVersionX32 + $officeVersionX64
    }

    $officeVersionMain = $officeVersion.Split(".")[0] + '.0'

    $officeVersionMain
}

$officeVersion = Get-OfficeVersion

Write-Host "Current Office Version: $officeVersion"

$egnyteExists = Get-EgnyteExists -OfficeVersion $officeVersion

if($egnyteExists -eq 0) {
    Write-Host "Egnyte not found, running provisioning script."
    start "ms-office-storage-host:asp|d|$CurrentServiceId|o|1|a|script"
} else {
    Write-Host "Egnyte found exiting..."
}
