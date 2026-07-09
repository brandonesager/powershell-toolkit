<#
.SYNOPSIS
    Diagnoses CCH ProSystem fx Scan server services, ports, and firewall rules.
.DESCRIPTION
    Checks CCH Scan services by name pattern, verifies that scan ports 29901-29905
    are in LISTENING state, reports Windows Firewall rules matching those ports,
    and confirms the CCH Scan installation folder exists.
    Diagnostic only -- makes no changes.

    Deploy via RMM to any CCH Scan server. Pass -ComputerName to note the target
    in output when running centrally; the script always executes locally.
.PARAMETER ComputerName
    Display name for the target machine in log output. Defaults to $env:COMPUTERNAME.
    The script runs locally regardless of this value.
.EXAMPLE
    .\Get-CCHProSystemDiagnostic.ps1
.EXAMPLE
    .\Get-CCHProSystemDiagnostic.ps1 -ComputerName PROSYS-SERVER
.NOTES
    Context:    RMM (SYSTEM)
    Platform:   Windows 10/11/Server, PS 5.1
    PS 5.1 compatible.
.KEYWORDS
    CCH, ProSystem, scan, diagnostic, ports, firewall, services
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
}

try {
    Write-Log "=== CCH PROSYSTEM FX SCAN SERVER DIAGNOSTICS ===" "INFO"
    Write-Log "Computer: $ComputerName" "INFO"
    Write-Host ""

    # Section 1: CCH-related Services
    Write-Log "--- SECTION 1: CCH SERVICES ---" "INFO"
    $cchServices = Get-Service | Where-Object {
        $_.Name -match 'scan|cch|printscan|axcess|pdflyer' -or
        $_.DisplayName -match 'scan|cch|printscan|axcess|pdflyer'
    }

    if ($cchServices) {
        foreach ($svc in $cchServices) {
            Write-Log "  $($svc.Name) | $($svc.DisplayName) | Status: $($svc.Status) | StartType: $($svc.StartType)" "INFO"
        }
    } else {
        Write-Log "  No CCH-related services found by name pattern" "WARN"
    }
    Write-Host ""

    # Section 2: Listening Ports (29901-29905)
    Write-Log "--- SECTION 2: CCH SCAN PORTS (29901-29905) ---" "INFO"
    $listeners = netstat -an | Select-String "LISTENING"
    $cchPorts = @(29901, 29902, 29903, 29904, 29905)
    $foundPorts = @()

    foreach ($port in $cchPorts) {
        $match = $listeners | Where-Object { $_ -match ":$port\s" }
        if ($match) {
            Write-Log "  Port $port : LISTENING" "INFO"
            $foundPorts += $port
        } else {
            Write-Log "  Port $port : NOT LISTENING" "WARN"
        }
    }

    Write-Log "  All listeners in 29xxx range:" "INFO"
    $rangeListeners = $listeners | Where-Object { $_ -match ":29\d{3}\s" }
    if ($rangeListeners) {
        foreach ($l in $rangeListeners) {
            Write-Log "    $l" "INFO"
        }
    } else {
        Write-Log "    None found in 29xxx range" "WARN"
    }
    Write-Host ""

    # Section 3: Windows Firewall Rules for CCH Scan Ports
    Write-Log "--- SECTION 3: FIREWALL RULES FOR CCH PORTS ---" "INFO"
    $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match 'scan|cch|29901|29902|29903|29904|29905'
    }

    if ($fwRules) {
        foreach ($rule in $fwRules) {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            $ports = if ($portFilter) { $portFilter.LocalPort } else { "N/A" }
            Write-Log "  Rule: $($rule.DisplayName) | Enabled: $($rule.Enabled) | Direction: $($rule.Direction) | Ports: $ports" "INFO"
        }
    } else {
        Write-Log "  No firewall rules found matching 'scan', 'cch', or ports 29901-29905" "WARN"
    }

    Write-Log "  Checking inbound rules for ports 29901-29905..." "INFO"
    foreach ($port in $cchPorts) {
        $portRules = Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $port -or $_.LocalPort -eq "Any" }
        if ($portRules) {
            foreach ($pf in $portRules) {
                $parentRule = Get-NetFirewallRule -AssociatedNetFirewallPortFilter $pf -ErrorAction SilentlyContinue
                if ($parentRule) {
                    Write-Log "    Port $port -> Rule: $($parentRule.DisplayName) | Action: $($parentRule.Action) | Enabled: $($parentRule.Enabled)" "INFO"
                }
            }
        }
    }
    Write-Host ""

    # Section 4: CCH Scan Installation Path Check
    Write-Log "--- SECTION 4: CCH SCAN INSTALLATION ---" "INFO"
    $scanPaths = @(
        "C:\CCH ProSystem fx Scan",
        "C:\Program Files\CCH ProSystem fx Scan",
        "C:\Program Files (x86)\CCH ProSystem fx Scan"
    )

    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            Write-Log "  FOUND: $path" "INFO"
            $serverPath = Join-Path $path "Server"
            if (Test-Path $serverPath) {
                Write-Log "    Server folder exists: $serverPath" "INFO"
            }
        }
    }
    Write-Host ""

    # Summary
    Write-Log "=== SUMMARY ===" "INFO"
    $servicesOK = if ($cchServices) { ($cchServices | Where-Object { $_.Status -eq 'Running' }).Count } else { 0 }
    $portsOK = $foundPorts.Count

    Write-Log "  CCH Services Running: $servicesOK" "INFO"
    Write-Log "  CCH Scan Ports Listening: $portsOK / 5" "INFO"

    if ($portsOK -eq 0) {
        Write-Log "  ISSUE: No CCH Scan ports are listening!" "WARN"
        Write-Log "  -> Check if CCH Scan Server service is installed and running" "INFO"
    }

    Write-Output "SUCCESS: Diagnostics completed"
    exit 0

} catch {
    Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
