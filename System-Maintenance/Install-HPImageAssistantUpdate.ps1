<#
.SYNOPSIS
    HP Image Assistant installer and updater for driver/firmware maintenance

.DESCRIPTION
    Automates HP Image Assistant (HPIA) deployment and update installation:
    1. Finds HPIA installer in C:\Temp (matching *hpia*.exe)
    2. Runs the installer to extract HPIA to C:\SWSetup
    3. Locates extracted HPImageAssistant.exe
    4. Runs analysis to check for available updates
    5. Installs HP driver/firmware/software updates

    HPIA Installation Behavior:
    - Installer extracts to C:\SWSetup\sp######\
    - May show some extraction windows (not fully silent)
    - HPIA is portable and doesn't require traditional installation

    Place hp-hpia-*.exe installer in C:\Temp before running.

.PARAMETER IncludeBIOS
    Include BIOS updates in the installation (default: excluded for safety)

.PARAMETER AutoInstall
    Automatically install updates without prompting (default: prompts user)

.EXAMPLE
    .\Install-HPImageAssistantUpdate.ps1

.EXAMPLE
    .\Install-HPImageAssistantUpdate.ps1 -IncludeBIOS -AutoInstall

.NOTES
    Date: 2026-02-06
    Category: System-Maintenance

.KEYWORDS
    HPIA, HP, driver, firmware, update
#>

[CmdletBinding()]
param(
    [switch]$IncludeBIOS,
    [switch]$AutoInstall
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $(
        switch($Level) {
            'SUCCESS' { 'Green' }
            'WARN' { 'Yellow' }
            'ERROR' { 'Red' }
            default { 'White' }
        }
    )
}

Write-Host "`n=== HP IMAGE ASSISTANT INSTALLER & UPDATER ===" -ForegroundColor Cyan

# Check if this is an HP device
$manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
if ($manufacturer -notmatch '^(HP|Hewlett-Packard)') {
    Write-Log "This is not an HP device (Manufacturer: $manufacturer)" -Level ERROR
    Write-Log "HP Image Assistant only works on HP devices" -Level ERROR
    exit 1
}

Write-Log "HP device detected: $manufacturer" -Level SUCCESS

# Step 1: Find HPIA installer in C:\Temp
Write-Log "Searching for HPIA installer in C:\Temp..." -Level INFO

if (-not (Test-Path "C:\Temp")) {
    Write-Log "C:\Temp does not exist, creating it..." -Level INFO
    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
}

$HPIAInstaller = Get-ChildItem "C:\Temp" -Filter "*hpia*.exe" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $HPIAInstaller) {
    Write-Log "No HPIA installer found in C:\Temp matching pattern *hpia*.exe" -Level ERROR
    Write-Host "`nPlease download HP Image Assistant installer to C:\Temp first." -ForegroundColor Yellow
    Write-Host "Download from: https://ftp.hp.com/pub/caps-softpaq/cmit/HPIA.html" -ForegroundColor Cyan
    exit 1
}

Write-Log "Found installer: $($HPIAInstaller.Name)" -Level SUCCESS
Write-Log "Path: $($HPIAInstaller.FullName)" -Level INFO
Write-Log "Size: $([math]::Round($HPIAInstaller.Length / 1MB, 2)) MB" -Level INFO

# Step 2: Run the installer (extracts to C:\SWSetup)
Write-Log "Running HPIA installer (may show extraction windows)..." -Level INFO
Write-Log "Installer will extract to C:\SWSetup\sp######\" -Level INFO
Write-Log "NOTE: Close any HPIA windows that appear - extraction happens automatically" -Level WARN

try {
    # Don't wait - let it extract in background
    $installProc = Start-Process -FilePath $HPIAInstaller.FullName -ArgumentList "/s" -PassThru -ErrorAction Stop
    Write-Log "Installer started (PID: $($installProc.Id))" -Level INFO

    # Wait up to 60 seconds for HPImageAssistant.exe to appear in C:\SWSetup
    Write-Log "Waiting for extraction to complete (max 60 seconds)..." -Level INFO
    $timeout = 60
    $elapsed = 0
    $found = $false

    while ($elapsed -lt $timeout -and -not $found) {
        Start-Sleep -Seconds 2
        $elapsed += 2

        $testExe = Get-ChildItem "C:\SWSetup" -Filter "HPImageAssistant.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($testExe) {
            $found = $true
            Write-Log "Extraction completed after $elapsed seconds" -Level SUCCESS
        }
    }

    if (-not $found) {
        Write-Log "Extraction did not complete within $timeout seconds" -Level WARN
        Write-Log "Continuing anyway - will search for existing HPIA installation" -Level INFO
    }

    # Try to close any lingering HPIA GUI windows
    Get-Process | Where-Object { $_.ProcessName -like "*HPImageAssistant*" -or $_.MainWindowTitle -like "*HP Image Assistant*" } | ForEach-Object {
        try {
            Write-Log "Closing HPIA GUI window (PID: $($_.Id))..." -Level INFO
            $_.CloseMainWindow() | Out-Null
            Start-Sleep -Milliseconds 500
            if (-not $_.HasExited) { $_.Kill() }
        } catch { }
    }
}
catch {
    Write-Log "Installer failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Step 3: Find the extracted HPImageAssistant.exe
Write-Log "Searching for extracted HPImageAssistant.exe..." -Level INFO

Start-Sleep -Seconds 2  # Give extraction a moment to complete

$HPIAExe = Get-ChildItem "C:\SWSetup" -Filter "HPImageAssistant.exe" -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $HPIAExe) {
    Write-Log "HPImageAssistant.exe not found in C:\SWSetup" -Level WARN
    Write-Log "Searching in Program Files..." -Level INFO

    $programFilesPaths = @(
        "$env:ProgramFiles\HP\HP Image Assistant\HPImageAssistant.exe",
        "${env:ProgramFiles(x86)}\HP\HP Image Assistant\HPImageAssistant.exe"
    )

    foreach ($path in $programFilesPaths) {
        if (Test-Path $path) {
            $HPIAExe = Get-Item $path
            break
        }
    }

    if (-not $HPIAExe) {
        Write-Log "HPImageAssistant.exe not found anywhere!" -Level ERROR
        Write-Log "Installation may have failed. Check C:\SWSetup manually." -Level ERROR
        exit 1
    }
}

Write-Log "Found HPIA: $($HPIAExe.FullName)" -Level SUCCESS
Write-Log "Version: $($HPIAExe.VersionInfo.FileVersion)" -Level INFO

# Step 4: Setup HPIA working directories
$HPIABase = "C:\ProgramData\HPIA"
$HPIADownloads = Join-Path $HPIABase "Downloads"
$HPIAReports = Join-Path $HPIABase "Reports"
$HPIALogs = Join-Path $HPIABase "Logs"

Write-Log "Creating HPIA working directories..." -Level INFO
New-Item -Path $HPIADownloads, $HPIAReports, $HPIALogs -ItemType Directory -Force | Out-Null
Write-Log "Working directory: $HPIABase" -Level INFO

# Step 5: Run HPIA Analysis first
Write-Log "Running HPIA analysis..." -Level INFO

$analyzeArgs = @(
    '/Operation:Analyze',
    '/Action:List',
    '/Silent',
    "/ReportFolder:$HPIAReports",
    "/LogFolder:$HPIALogs"
)

Write-Log "Command: HPImageAssistant.exe $($analyzeArgs -join ' ')" -Level INFO

try {
    $analyzeProc = Start-Process -FilePath $HPIAExe.FullName -ArgumentList $analyzeArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop

    switch ($analyzeProc.ExitCode) {
        0    { Write-Log "Analysis completed: Updates available" -Level SUCCESS }
        256  {
            Write-Log "Analysis completed: No recommendations" -Level SUCCESS
            Write-Host "`nSystem is up to date!" -ForegroundColor Green
            Write-Host "Reports: $HPIAReports" -ForegroundColor Yellow
            exit 0
        }
        3010 { Write-Log "Analysis completed: Reboot required from previous updates" -Level WARN }
        default { Write-Log "Analysis exit code: $($analyzeProc.ExitCode)" -Level WARN }
    }
}
catch {
    Write-Log "Analysis failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Step 6: Ask if user wants to install updates (unless AutoInstall is set)
if (-not $AutoInstall) {
    Write-Host "`n" -NoNewline
    $installUpdates = Read-Host "Proceed with installing updates? (Y/N)"

    if ($installUpdates -ne 'Y') {
        Write-Log "Update installation cancelled by user" -Level INFO
        Write-Log "Analysis report saved to: $HPIAReports" -Level INFO
        exit 0
    }
}
else {
    Write-Log "AutoInstall enabled - proceeding with updates" -Level INFO
}

# Step 7: Install updates
Write-Log "Installing HP updates (this may take several minutes)..." -Level INFO
Write-Host "Please be patient, this process can take 10-30 minutes..." -ForegroundColor Yellow

$categories = 'Drivers,Software,Firmware'
if ($IncludeBIOS) {
    $categories += ',BIOS'
    Write-Log "Including BIOS updates" -Level WARN
}
else {
    Write-Log "Excluding BIOS updates (use -IncludeBIOS to include)" -Level INFO
}

$installArgs = @(
    '/Operation:Analyze',
    '/Action:Install',
    '/Selection:All',
    '/InstallType:AutoInstallable',
    '/Silent',
    "/Category:$categories",
    "/SoftPaqDownloadFolder:$HPIADownloads",
    "/ReportFolder:$HPIAReports",
    "/LogFolder:$HPIALogs",
    '/AutoCleanup'
)

Write-Log "Command: HPImageAssistant.exe $($installArgs -join ' ')" -Level INFO

try {
    $installProc = Start-Process -FilePath $HPIAExe.FullName -ArgumentList $installArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
}
catch {
    Write-Log "Update installation failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Step 8: Display results
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "HPIA UPDATE RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$rebootNeeded = $false

switch ($installProc.ExitCode) {
    0    {
        Write-Log "Updates installed successfully!" -Level SUCCESS
        $rebootNeeded = $false
    }
    256  {
        Write-Log "No updates were needed" -Level SUCCESS
        $rebootNeeded = $false
    }
    3010 {
        Write-Log "Updates installed - REBOOT REQUIRED" -Level WARN
        $rebootNeeded = $true
    }
    3020 {
        Write-Log "Some updates failed to install" -Level WARN
        Write-Log "Check reports and logs for details" -Level INFO
        $rebootNeeded = $false
    }
    default {
        Write-Log "Update process completed with exit code: $($installProc.ExitCode)" -Level WARN
        Write-Log "Check reports and logs for details" -Level INFO
        $rebootNeeded = $false
    }
}

Write-Host "`nReports: " -NoNewline -ForegroundColor Yellow
Write-Host $HPIAReports -ForegroundColor White
Write-Host "Logs: " -NoNewline -ForegroundColor Yellow
Write-Host $HPIALogs -ForegroundColor White

# Check for HTML report
$htmlReport = Get-ChildItem $HPIAReports -Filter "*.html" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($htmlReport) {
    Write-Host "`nHTML Report: " -NoNewline -ForegroundColor Cyan
    Write-Host $htmlReport.FullName -ForegroundColor White
}

if ($rebootNeeded) {
    Write-Host "`n*** REBOOT REQUIRED ***" -ForegroundColor Red

    if (-not $AutoInstall) {
        $rebootNow = Read-Host "`nReboot now? (Y/N)"
        if ($rebootNow -eq 'Y') {
            Write-Log "Initiating reboot in 10 seconds..." -Level WARN
            shutdown /r /t 10 /c "Reboot required after HP updates"
        }
    }
    else {
        Write-Log "AutoInstall mode: Reboot required but not initiated automatically" -Level WARN
    }

    exit 3010
}

Write-Host "`n========================================`n" -ForegroundColor Cyan
exit 0
