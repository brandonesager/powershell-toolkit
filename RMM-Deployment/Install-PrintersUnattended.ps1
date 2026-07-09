#Requires -Version 5.1

<#
.SYNOPSIS
    Install-PrintersUnattended — Downloads Konica driver package, installs via pnputil, and renames printers

.DESCRIPTION
    Downloads a Konica Minolta driver package from the vendor FTP, extracts it,
    installs the PCL driver via pnputil, then renames installed printers per
    a configuration hashtable. Designed for RMM/SYSTEM context deployment.

.EXAMPLE
    .\Install-PrintersUnattended.ps1

.NOTES
    Category: RMM-Deployment
.KEYWORDS
    printer, provision, RMM, SYSTEM, driver
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Get-Printer | Select-Object Name, PortName, DriverName | Format-List

Get-PrinterDriver -Name "*konica*" | Format-List

# --- Configuration ---
$url = "https://cscsupportftp.mykonicaminolta.com/DownloadFile/Download.ashx?fileversionid=35315&productid=1977"
$destinationFolder = "C:\temp"
$zipFileName = "KonicaDriverPackage.zip"
$extractFolderName = "KonicaDriverPackage"

# Construct the full paths from the configuration variables
$downloadPath = Join-Path -Path $destinationFolder -ChildPath $zipFileName
$extractPath = Join-Path -Path $destinationFolder -ChildPath $extractFolderName
$infPath = Join-Path -Path $extractPath -ChildPath "Driver\Drivers\PCL\EN\Win_x64\KOAXPJ__.INF"

# --- Script Logic ---

# Step 1: Check for Administrator privileges
Write-Host "Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator to install drivers. Please re-open your PowerShell window as an Administrator and try again."
    # Pause to allow user to read the error before the window closes in some execution environments
    if ($Host.Name -eq "ConsoleHost") { Start-Sleep -Seconds 10 }
    return
}
Write-Host "Administrator privileges confirmed." -ForegroundColor Green

# Step 2: Ensure the destination folder exists
if (-not (Test-Path -Path $destinationFolder -PathType Container)) {
    Write-Host "Destination folder '$destinationFolder' not found. Creating it..." -ForegroundColor Yellow
    New-Item -Path $destinationFolder -ItemType Directory -Force | Out-Null
}

# Step 3: Download the file
Write-Host "Starting download from URL..."
Invoke-WebRequest -Uri $url -OutFile $downloadPath
Write-Host "Download complete! File saved to: $downloadPath" -ForegroundColor Green

# Step 4: Extract the contents of the .zip file
Write-Host "Extracting files to '$extractPath'..."
# The -Force parameter will create the destination directory and overwrite existing files
Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractPath -Force
Write-Host "Extraction complete." -ForegroundColor Green

# Step 5: Install the driver using the .inf file
Write-Host "Searching for INF file at: $infPath"
if (Test-Path -Path $infPath) {
    Write-Host "INF file found. Initiating driver installation..." -ForegroundColor Yellow

    # Use pnputil.exe, the modern tool for staging and installing drivers
    pnputil.exe /add-driver $infPath /install

    Write-Host "Driver installation command sent. Check the output above from PnPUtil for success or failure." -ForegroundColor Green
}
else {
    # This error will trigger if the INF is not at the expected path
    throw "Driver INF file not found at the specified path: $infPath"
}

# ===================================================================================
# Script:         Rename Specific Printers (Compatible Version)
# Description:    Uses WMI/CIM for broad compatibility with older Windows versions.
# Requirements:   Run as Administrator
# ===================================================================================

# --- Configuration ---
# Define the printers to rename in a hashtable for easy management.
$printersToRename = @{
    #"KONICA MINOLTA C658SeriesPCL(2)" = "LOCATION-A Konica - FRONT";
    "KONICA MINOLTA C658SeriesPCL" = "LOCATION-A Konica - MIDDLE";
}

# --- Script Logic ---

# Step 1: Check for Administrator privileges
Write-Host "Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator. Please re-open PowerShell as an Administrator and try again."
    if ($Host.Name -eq "ConsoleHost") { Start-Sleep -Seconds 10 }
    return
}
Write-Host "Administrator privileges confirmed." -ForegroundColor Green
Write-Host "--------------------------------------------------"

# Step 2: Loop through each printer and attempt to rename it
foreach ($oldName in $printersToRename.Keys) {
    $newName = $printersToRename[$oldName]

    Write-Host "Attempting to rename '$oldName' to '$newName'..."

    # Use Get-CimInstance to find the printer. This is universally compatible.
    # Note the single quotes inside the filter string.
    $printer = Get-CimInstance -ClassName Win32_Printer -Filter "Name = '$oldName'" -ErrorAction SilentlyContinue

    if ($printer) {
        # Printer was found, proceed with renaming using the WMI RenamePrinter method
            $printer | Invoke-CimMethod -MethodName "RenamePrinter" -Arguments @{ NewPrinterName = $newName } -ErrorAction Stop
            Write-Host "SUCCESS: Printer renamed successfully." -ForegroundColor Green
    }
    else {
        # Printer was not found
        Write-Host "SKIPPED: Printer with the name '$oldName' was not found." -ForegroundColor Yellow
    }
    Write-Host "" # Add a blank line for readability
}

Write-Host "--------------------------------------------------"
Write-Host "Script finished."
