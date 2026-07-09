#Requires -Version 5.1

<#
.SYNOPSIS
    Test-GPOPrinterDeployment — Diagnose why a GPO-deployed printer isn't appearing

.DESCRIPTION
    Comprehensive workstation-side diagnostic for GPO printer deployment failures.
    Runs 10 checks from the endpoint to identify the root cause:

    1. Logged-in user detection
    2. DNS resolution of print server
    3. Print server port connectivity (SMB 445, RPC 135, RAW 9100)
    4. Direct printer IP connectivity (port 9100)
    5. Printer share UNC access
    6. GPO application (gpresult parsing)
    7. User OU placement vs GPO target OU
    8. AD site assignment
    9. Currently installed printers
    10. Summary with issue list

    Designed for RMM/SYSTEM remote session (PS 5.1, SYSTEM context). Read-only — makes
    no changes to the system.

.PARAMETER PrintServer
    Hostname of the print server. Required.

.PARAMETER PrinterShare
    Share name of the printer on the print server. Required.

.PARAMETER PrinterIP
    Direct IP address of the printer device. Required.

.PARAMETER GPOName
    Display name of the GPO that deploys the printer. Required.

.PARAMETER TargetOU
    Distinguished name of the OU the GPO is linked to. Required.

.EXAMPLE
    .\Test-GPOPrinterDeployment.ps1 -PrintServer 'PRINT01' -PrinterShare 'OFFICE-HP' `
        -PrinterIP '10.0.1.50' -GPOName 'Printer Policy - Main Office' `
        -TargetOU 'OU=Users,OU=MainOffice,DC=contoso,DC=com'

.NOTES
    Category: Diagnostics
    Context: SYSTEM (RMM) or interactive
    PS Version: 5.1
    Exit Codes: 0=No issues, 1=Issues found

.KEYWORDS
    printer, GPO, diagnostic, deployment, troubleshoot
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PrintServer,

    [Parameter(Mandatory = $true)]
    [string]$PrinterShare,

    [Parameter(Mandatory = $true)]
    [string]$PrinterIP,

    [Parameter(Mandatory = $true)]
    [string]$GPOName,

    [Parameter(Mandatory = $true)]
    [string]$TargetOU
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

$script:Issues = @()

try {
    Write-Output "=== GPO Printer Deployment Diagnostic ==="
    Write-Log "Computer: $env:COMPUTERNAME"
    Write-Log "Print Server: $PrintServer"
    Write-Log "Printer: \\$PrintServer\$PrinterShare ($PrinterIP)"
    Write-Log "GPO: $GPOName"
    Write-Output ""

    # --- 1. Logged-in user ---
    Write-Output "--- 1. LOGGED-IN USER ---"
    $explorerProc = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $explorerProc) {
        Write-Log "No interactive user detected (no explorer.exe)" "WARN"
        Write-Log "Most checks require a logged-in user. Exiting." "ERROR"
        exit 1
    }

    $owner = $explorerProc.GetOwner()
    $LoggedInUser = "$($owner.Domain)\$($owner.User)"
    $UserName     = $owner.User
    Write-Log "Logged-in user: $LoggedInUser"
    Write-Output ""

    # --- 2. DNS resolution ---
    Write-Output "--- 2. DNS RESOLUTION ---"
    try {
        $dns = Resolve-DnsName $PrintServer -ErrorAction Stop
        Write-Log "$PrintServer -> $($dns.IPAddress -join ', ')"
    } catch {
        Write-Log "Cannot resolve $PrintServer - $($_.Exception.Message)" "FAIL"
        $script:Issues += "DNS resolution failed for $PrintServer"
    }
    Write-Output ""

    # --- 3. Print server connectivity ---
    Write-Output "--- 3. PRINT SERVER CONNECTIVITY ---"
    foreach ($port in @(445, 135, 9100)) {
        $label = switch ($port) { 445 {'SMB'} 135 {'RPC'} 9100 {'RAW Print'} }
        $tcp = Test-NetConnection -ComputerName $PrintServer -Port $port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) {
            Write-Log "${PrintServer}:${port} ($label): PASS"
        } else {
            Write-Log "${PrintServer}:${port} ($label): FAIL" "FAIL"
            $script:Issues += "Print server port $port ($label) not reachable"
        }
    }
    Write-Output ""

    # --- 4. Direct printer IP connectivity ---
    Write-Output "--- 4. PRINTER IP CONNECTIVITY ---"
    $tcp9100 = Test-NetConnection -ComputerName $PrinterIP -Port 9100 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($tcp9100.TcpTestSucceeded) {
        Write-Log "${PrinterIP}:9100 (RAW Print): PASS"
    } else {
        Write-Log "${PrinterIP}:9100 (RAW Print): FAIL" "FAIL"
        $script:Issues += "Printer IP not reachable on 9100"
    }
    Write-Output ""

    # --- 5. Printer share access ---
    Write-Output "--- 5. PRINTER SHARE ACCESS ---"
    $uncPath = "\\$PrintServer\$PrinterShare"
    $shareExists = Test-Path $uncPath -ErrorAction SilentlyContinue
    if ($shareExists) {
        Write-Log "$uncPath accessible: True"
    } else {
        Write-Log "$uncPath accessible: False" "FAIL"
        $script:Issues += "Printer share not accessible"
        $printShare = Test-Path "\\$PrintServer\print$" -ErrorAction SilentlyContinue
        Write-Log "\\$PrintServer\print`$ accessible: $printShare"
    }
    Write-Output ""

    # --- 6. GPO application ---
    Write-Output "--- 6. GPO APPLICATION ---"
    Write-Log "Running gpresult for $LoggedInUser..."
    $gpResult = & gpresult.exe /USER $LoggedInUser /R 2>&1
    $gpText = $gpResult -join "`n"

    $gpoPattern = [regex]::Escape($GPOName)
    if ($gpText -match $gpoPattern) {
        Write-Log "GPO APPLIED: '$GPOName' found in gpresult"
    } else {
        Write-Log "GPO NOT APPLIED: '$GPOName' NOT found in gpresult" "FAIL"
        $script:Issues += "GPO not applying to user"
    }

    # Check denied GPOs
    $deniedSection = $false
    foreach ($line in $gpResult) {
        if ($line -match 'denied.*GPO|GPO.*denied|not applied|filtering') {
            $deniedSection = $true
        }
        if ($deniedSection -and $line -match $gpoPattern) {
            Write-Log "GPO appears in denied/filtered section: $($line.Trim())" "WARN"
        }
    }

    # Show applied user GPOs
    Write-Output ""
    Write-Log "Applied User GPOs:"
    $inUserSection = $false
    $inAppliedSection = $false
    foreach ($line in $gpResult) {
        if ($line -match 'USER SETTINGS') { $inUserSection = $true }
        if ($inUserSection -and $line -match 'Applied Group Policy Objects') { $inAppliedSection = $true; continue }
        if ($inAppliedSection -and $line -match '^\s*$') { break }
        if ($inAppliedSection -and $line.Trim()) {
            Write-Output "    $($line.Trim())"
        }
    }
    Write-Output ""

    # --- 7. User OU placement ---
    Write-Output "--- 7. USER OU PLACEMENT ---"
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(sAMAccountName=$UserName)"
        $searcher.PropertiesToLoad.Add('distinguishedName') | Out-Null
        $adResult = $searcher.FindOne()
        if ($adResult) {
            $userDN = $adResult.Properties['distinguishedname'][0]
            Write-Log "User DN: $userDN"
            $inTargetOU = $userDN -like "*$TargetOU"
            Write-Log "In target OU: $inTargetOU"
            if (-not $inTargetOU) {
                Write-Log "User is NOT in the OU targeted by the GPO" "WARN"
                $script:Issues += "User not in target OU"
            }
        } else {
            Write-Log "User '$UserName' not found in AD" "WARN"
        }
    } catch {
        Write-Log "Error querying AD: $($_.Exception.Message)" "ERROR"
    }
    Write-Output ""

    # --- 8. AD site assignment ---
    Write-Output "--- 8. AD SITE ASSIGNMENT ---"
    try {
        $site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
        Write-Log "Computer AD site: $($site.Name)"
    } catch {
        Write-Log "Could not determine AD site - $($_.Exception.Message)" "WARN"
    }
    $regSite = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DynamicSiteName' -ErrorAction SilentlyContinue
    if ($regSite) {
        Write-Log "DynamicSiteName (registry): $($regSite.DynamicSiteName)"
    }
    Write-Output ""

    # --- 9. Installed printers ---
    Write-Output "--- 9. INSTALLED PRINTERS ---"
    Get-Printer -ErrorAction SilentlyContinue | ForEach-Object {
        $conn = if ($_.Type -eq 'Connection') { "(network)" } else { "(local)" }
        Write-Output "    $($_.Name) $conn - $($_.DriverName)"
    }
    Write-Output ""

    # --- 10. Summary ---
    Write-Output "=== SUMMARY ==="
    if ($script:Issues.Count -eq 0) {
        Write-Log "No obvious issues detected. Try: gpupdate /force + logoff/logon cycle."
        exit 0
    } else {
        Write-Log "Issues found:" "WARN"
        foreach ($issue in $script:Issues) {
            Write-Output "    - $issue"
        }
        exit 1
    }
} catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    Write-Log "At: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" "ERROR"
    exit 1
}
