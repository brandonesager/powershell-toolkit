#!ps
#maxlength=100000
#timeout=300000

<#
.SYNOPSIS
    Read-only AutoCAD plotter inventory and No Matching Media diagnostic.
.DESCRIPTION
    Resolves the currently logged-on user's profile dynamically (no hardcoded
    username). Inventories installed AutoCAD versions from the registry, locates
    all Plotters folders under the user's Autodesk AppData, lists PC3/PMP files,
    detects duplicate filenames (a known cause of "No Matching Media" errors),
    reads AutoCAD profile printer-support paths from the user hive, checks the
    user's default printer, enumerates installed printers, and lists custom
    print server forms. Run via RMM shell (SYSTEM), read-only.
.NOTES
    Category: Diagnostics
    PS 5.1 compatible.
    Context: RMM shell (SYSTEM), read-only.
.KEYWORDS
    AutoCAD, plotter, PC3, PMP, No Matching Media, printer, paper size, form
#>

[CmdletBinding()]
param()

function Section {
    param([string]$Title)
    Write-Output ""
    Write-Output ("=" * 70)
    Write-Output $Title
    Write-Output ("=" * 70)
}

Write-Output ("AutoCAD plotter diagnostic - {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
Write-Output ("Machine: {0}" -f $env:COMPUTERNAME)

# 1. Resolve the currently logged-on user's profile dynamically
Section "USER PROFILE"
$LoggedOn = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $LoggedOn) {
    Write-Output "ERROR: No interactive user logged on. Cannot locate user profile."
    exit 1
}
$UserProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Special -eq $false -and
        $_.LocalPath -match ("\\Users\\" + [regex]::Escape(($LoggedOn -split '\\')[-1]) + "$")
    } | Select-Object -First 1

if (-not $UserProfile) {
    Write-Output "ERROR: Could not locate profile for $LoggedOn under C:\Users"
    exit 1
}
$Sid      = $UserProfile.SID
$UserPath = $UserProfile.LocalPath
$AppData  = Join-Path $UserPath "AppData\Roaming"
Write-Output ("Logged on: {0}" -f $LoggedOn)
Write-Output ("SID:       {0}" -f $Sid)
Write-Output ("Profile:   {0}" -f $UserPath)
Write-Output ("AppData:   {0}" -f $AppData)

# 2. Installed AutoCAD versions
Section "INSTALLED AUTOCAD VERSIONS"
$AcadKeys    = @("HKLM:\SOFTWARE\Autodesk\AutoCAD", "HKLM:\SOFTWARE\WOW6432Node\Autodesk\AutoCAD")
$AcadVersions = @()
foreach ($Key in $AcadKeys) {
    if (Test-Path $Key) {
        Get-ChildItem $Key -ErrorAction SilentlyContinue | ForEach-Object {
            $Ver = $_.PSChildName
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $Line  = "{0} (Reg {1}) - ProductName: {2} - Release: {3}" -f `
                          $Ver, $_.PSChildName, $Props.ProductName, $Props.Release
                Write-Output $Line
                $AcadVersions += $Line
            }
        }
    }
}
if ($AcadVersions.Count -eq 0) { Write-Output "No AutoCAD registry entries found under HKLM" }

# 3. Plotters folders and PC3/PMP files
Section "PLOTTERS FOLDERS - ALL PC3/PMP FILES"
$AutodeskRoot = Join-Path $AppData "Autodesk"
$PlotterDirs  = @()
if (Test-Path $AutodeskRoot) {
    Get-ChildItem $AutodeskRoot -Recurse -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "Plotters" } | ForEach-Object { $PlotterDirs += $_.FullName }
}
$AllPlotterFiles = @()
foreach ($Dir in $PlotterDirs) {
    Write-Output ""
    Write-Output ("[{0}]" -f $Dir)
    $Files = Get-ChildItem $Dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { @(".pc3", ".pmp") -contains $_.Extension.ToLower() } | Sort-Object FullName
    foreach ($F in $Files) {
        $Rel = $F.FullName.Substring($Dir.Length).TrimStart("\")
        Write-Output ("  {0} | {1} bytes | mod {2:yyyy-MM-dd}" -f $Rel, $F.Length, $F.LastWriteTime)
        $AllPlotterFiles += $F
    }
}
if ($PlotterDirs.Count -eq 0) {
    Write-Output ("No Plotters folder found under {0}" -f $AutodeskRoot)
}

# 4. Duplicate PC3/PMP filename detection (Autodesk KB cause)
Section "DUPLICATE PC3/PMP FILENAMES"
$DupGroups = $AllPlotterFiles | Group-Object Name | Where-Object { $_.Count -gt 1 } | Sort-Object Name
if ($DupGroups) {
    foreach ($G in $DupGroups) {
        Write-Output ("DUPLICATE: {0} ({1} copies)" -f $G.Name, $G.Count)
        foreach ($F in $G.Group | Sort-Object FullName) {
            Write-Output ("  {0} | {1} bytes | mod {2:yyyy-MM-dd HH:mm}" -f $F.FullName, $F.Length, $F.LastWriteTime)
        }
    }
} else {
    Write-Output "No duplicate PC3/PMP filenames detected"
}

# 5. AutoCAD profile printer-support paths from the user hive
Section "AUTOCAD PROFILE PATHS (user hive)"
$HiveLoaded = $false
if (-not (Test-Path "Registry::HKEY_USERS\$Sid")) {
    $HivePath = Join-Path $UserPath "NTUSER.DAT"
    if (Test-Path $HivePath) {
        reg.exe load "HKU\$Sid" "$HivePath" 2>&1 | Out-Null
        if (Test-Path "Registry::HKEY_USERS\$Sid") { $HiveLoaded = $true }
    }
}
$UserHive      = "Registry::HKEY_USERS\$Sid"
$UserDefPrinter = $null
if (Test-Path $UserHive) {
    $AcadHkuPath = Join-Path $UserHive "SOFTWARE\Autodesk\AutoCAD"
    if (Test-Path $AcadHkuPath) {
        Get-ChildItem $AcadHkuPath -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $ProfilesKey = Join-Path $_.PSPath "Profiles"
                if (Test-Path $ProfilesKey) {
                    Get-ChildItem $ProfilesKey -ErrorAction SilentlyContinue | ForEach-Object {
                        $AcadProfileName = $_.PSChildName
                        $GeneralKey      = Join-Path $_.PSPath "General"
                        if (Test-Path $GeneralKey) {
                            $Props = Get-ItemProperty $GeneralKey -ErrorAction SilentlyContinue
                            Write-Output ""
                            Write-Output ("AutoCAD Profile: {0}" -f $AcadProfileName)
                            Write-Output ("  PrinterConfigDir:     {0}" -f $Props.PrinterConfigDir)
                            Write-Output ("  PrinterDescDir:       {0}" -f $Props.PrinterDescDir)
                            Write-Output ("  PrinterStyleSheetDir: {0}" -f $Props.PrinterStyleSheetDir)
                            Write-Output ("  PrinterPlotStyleDir:  {0}" -f $Props.PrinterPlotStyleDir)
                        }
                    }
                }
            }
        }
    } else {
        Write-Output ("No HKU\{0}\SOFTWARE\Autodesk\AutoCAD key found" -f $Sid)
    }
    $DefKey = Join-Path $UserHive "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    if (Test-Path $DefKey) {
        $UserDefPrinter = (Get-ItemProperty $DefKey -ErrorAction SilentlyContinue).Device
    }
} else {
    Write-Output ("Could not access HKU\{0} (hive not loaded)" -f $Sid)
}

Section "USER'S DEFAULT PRINTER"
Write-Output ("Device: {0}" -f $UserDefPrinter)

if ($HiveLoaded) {
    [gc]::Collect()
    Start-Sleep -Seconds 1
    reg.exe unload "HKU\$Sid" 2>&1 | Out-Null
}

# 6. Installed printers
Section "INSTALLED PRINTERS"
$Printers = Get-Printer -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($P in $Printers) {
    Write-Output ("{0} | Driver: {1} | Port: {2} | Shared: {3}" -f $P.Name, $P.DriverName, $P.PortName, $P.Shared)
}

# 7. Print server forms (custom only)
Section "PRINT SERVER FORMS (custom only, built-ins excluded)"
try {
    $Forms = Get-CimInstance -Namespace root\standardcimv2 -ClassName MSFT_PrinterForm -ErrorAction Stop |
        Where-Object { -not $_.Builtin } | Sort-Object Name
    if ($Forms) {
        foreach ($F in $Forms) {
            $WidthMm  = [math]::Round($F.PaperWidthMicrons / 1000, 1)
            $HeightMm = [math]::Round($F.PaperHeightMicrons / 1000, 1)
            Write-Output ("{0} | {1}x{2} mm" -f $F.Name, $WidthMm, $HeightMm)
        }
    } else {
        Write-Output "No custom forms registered"
    }
} catch {
    Write-Output ("Could not enumerate forms: {0}" -f $_.Exception.Message)
}

# Summary
Section "SUMMARY"
Write-Output ("AutoCAD versions in registry: {0}" -f $AcadVersions.Count)
Write-Output ("Plotters folders located:     {0}" -f $PlotterDirs.Count)
Write-Output ("PC3/PMP files found:          {0}" -f $AllPlotterFiles.Count)
Write-Output ("Duplicate PC3/PMP filenames:  {0}" -f ($DupGroups | Measure-Object).Count)
Write-Output ("Installed printers:           {0}" -f ($Printers | Measure-Object).Count)
Write-Output ("User default printer:         {0}" -f $UserDefPrinter)
