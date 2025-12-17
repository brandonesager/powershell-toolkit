<#
.SYNOPSIS
    Analyzes .eml files for potential security breaches and correlates with Entra ID sign-in logs

.DESCRIPTION
    Comprehensive email security analysis tool that:
    - Analyzes .eml files for authentication failures and suspicious patterns
    - Connects to Microsoft 365 via Microsoft Graph PowerShell
    - Gathers Entra ID sign-in logs for correlation analysis
    - Focuses on Business Email Compromise (BEC) detection

.PARAMETER Path
    Path to directory containing .eml files or specific .eml file

.PARAMETER FocusUser
    Specific user to focus analysis on (e.g., "kari")

.PARAMETER ExportReport
    Export detailed findings to CSV report in script directory

.PARAMETER IncludeSignInLogs
    Include Entra ID sign-in log analysis (requires Microsoft Graph connection)

.PARAMETER DaysBack
    Number of days to look back for sign-in logs (default: 7)

.EXAMPLES
    Example 1: Run with defaults in current directory
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-EmailBreachAnalysis.ps1'

    Example 2: Analyze specific directory with focused user
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-EmailBreachAnalysis.ps1' -Path 'c:\evidence\emails' -FocusUser 'kari' -ExportReport

    Example 3: Include sign-in logs from last 14 days
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-EmailBreachAnalysis.ps1' -Path 'c:\evidence\emails' -IncludeSignInLogs -DaysBack 14 -ExportReport

.NOTES
    Author: Brandon Sager
    Date: 2025-12-16
    
    Version : 1.0
    
    Requires:
    - PowerShell 7.0+
    - Microsoft.Graph.Authentication module
    - Microsoft.Graph.Reports module
    - Microsoft.Graph.Users module
    - Microsoft Graph permissions for sign-in log access
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Users



param(
    [Parameter(Mandatory = $false)]
    [string]$Path = ".",
    
    [Parameter(Mandatory = $false)]
    [string]$FocusUser = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSignInLogs,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 7
)

function Write-SecurityAlert {
    param([string]$Message, [string]$Severity = "HIGH")
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Cyan" }
        "LOW" { "Green" }
        default { "White" }
    }
    Write-Host "[$Severity] $Message" -ForegroundColor $color
}

function Connect-To365Services {
    Write-Host "Connecting to Microsoft 365 services..." -ForegroundColor Cyan
    
    try {
        # Check if already connected to Microsoft Graph
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "AuditLog.Read.All", "User.Read.All", "Directory.Read.All"
            Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        } else {
            Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
        }
        
        return $true
    } catch {
        Write-Error "Failed to connect to Microsoft 365: $($_.Exception.Message)"
        return $false
    }
}

function Get-EntraSignInLogs {
    param(
        [string]$UserPrincipalName,
        [int]$DaysBack = 7
    )
    
    Write-Host "Gathering Entra ID sign-in logs for analysis..." -ForegroundColor Cyan
    
    try {
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $filter = "createdDateTime ge $startDate"
        if (-not [string]::IsNullOrEmpty($UserPrincipalName)) {
            $filter += " and userPrincipalName eq '$UserPrincipalName'"
        }
        
        Write-Host "Retrieving sign-in logs from $startDate..." -ForegroundColor Yellow
        
        $signInLogs = Get-MgAuditLogSignIn -Filter $filter -All

        Write-Host "Retrieved $($signInLogs.Count) sign-in events" -ForegroundColor Green
        return $signInLogs
        
    } catch {
        Write-Warning "Failed to retrieve sign-in logs: $($_.Exception.Message)"
        return @()
    }
}

function Test-SuspiciousSignIns {
    param([array]$SignInLogs, [string]$FocusUser)
    
    $suspiciousSignIns = @()
    
    foreach ($signIn in $SignInLogs) {
        $riskScore = 0
        $riskFactors = @()
        
        # Check for failed sign-ins
        if ($signIn.Status.ErrorCode -ne 0) {
            $riskScore += 15
            $riskFactors += "Failed sign-in attempt (Code: $($signIn.Status.ErrorCode))"
        }
        
        # Check for unusual locations
        if ($signIn.Location.CountryOrRegion -and $signIn.Location.CountryOrRegion -notin @("United States", "US")) {
            $riskScore += 20
            $riskFactors += "Sign-in from unusual location: $($signIn.Location.CountryOrRegion)"
        }
        
        # Check for risky IP addresses (basic heuristics)
        if ($signIn.IpAddress -match "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)" -eq $false -and
            $signIn.Location.CountryOrRegion -ne "United States") {
            $riskScore += 10
            $riskFactors += "External IP from foreign country: $($signIn.IpAddress)"
        }
        
        # Check for unusual applications
        if ($signIn.AppDisplayName -like "*Office*" -or $signIn.AppDisplayName -like "*Outlook*") {
            if ($signIn.Status.ErrorCode -ne 0) {
                $riskScore += 25
                $riskFactors += "Failed Office/Outlook access attempt"
            }
        }
        
        # Check for focus user specific risks
        if (-not [string]::IsNullOrEmpty($FocusUser) -and 
            $signIn.UserPrincipalName -like "*$FocusUser*") {
            $riskScore += 20
            $riskFactors += "Activity involving focus user: $FocusUser"
        }
        
        # Check for impossible travel
        # (This is simplified - in practice you'd need to compare with previous locations)
        
        if ($riskScore -gt 0) {
            $suspiciousSignIn = [PSCustomObject]@{
                DateTime = $signIn.CreatedDateTime
                UserPrincipalName = $signIn.UserPrincipalName
                IpAddress = $signIn.IpAddress
                Location = "$($signIn.Location.City), $($signIn.Location.CountryOrRegion)"
                Application = $signIn.AppDisplayName
                Status = $signIn.Status.ErrorCode
                RiskScore = $riskScore
                RiskFactors = ($riskFactors -join "; ")
                DeviceInfo = $signIn.DeviceDetail.DisplayName
            }
            $suspiciousSignIns += $suspiciousSignIn
        }
    }
    
    return $suspiciousSignIns
}

function Test-AuthenticationFailures {
    param([string]$Content)
    
    $failures = @()
    
    # Check SPF failures
    if ($Content -match "spf=fail|SPF.*fail") {
        $failures += "SPF Authentication Failed"
    }
    
    # Check DMARC failures
    if ($Content -match "dmarc=fail") {
        $failures += "DMARC Authentication Failed"
    }
    
    # Check DKIM failures
    if ($Content -match "dkim=fail") {
        $failures += "DKIM Authentication Failed"
    }
    
    # Check for authentication bypasses
    if ($Content -match "compauth=fail|authentication.*fail") {
        $failures += "General Authentication Bypass Detected"
    }
    
    return $failures
}

function Test-SuspiciousPatterns {
    param([string]$Content, [string]$FileName)
    
    $suspiciousIndicators = @()
    
    # BEC/Phishing indicators
    $phishingPatterns = @(
        "urgent.*payment", "wire.*transfer", "invoice.*attached", 
        "bank.*details", "account.*update", "suspended.*account",
        "verify.*identity", "click.*here", "update.*payment",
        "remittance.*summary", "PO.*payment"
    )
    
    foreach ($pattern in $phishingPatterns) {
        if ($Content -match $pattern) {
            $suspiciousIndicators += "Potential BEC/Phishing Pattern: $pattern"
        }
    }
    
    # Check for suspicious attachments
    if ($Content -match "X-MS-Has-Attach:\s*yes|has-attachment") {
        $suspiciousIndicators += "Email contains attachments - requires manual review"
    }
    
    # Check for spoofed domains
    if ($Content -match "From:.*@(?!.*\.(com|org|net|gov|edu))") {
        $suspiciousIndicators += "Potentially suspicious sender domain"
    }
    
    # Check for reply-to mismatch
    $fromMatch = [regex]::Match($Content, "From:.*?<(.+?)>")
    $replyToMatch = [regex]::Match($Content, "Reply-To:.*?<(.+?)>")
    
    if ($fromMatch.Success -and $replyToMatch.Success -and 
        $fromMatch.Groups[1].Value -ne $replyToMatch.Groups[1].Value) {
        $suspiciousIndicators += "Reply-To address differs from sender"
    }
    
    return $suspiciousIndicators
}

function Get-EmailMetadata {
    param([string]$Content)
    
    $metadata = @{}
    
    # Extract key headers
    $headers = @("From", "To", "Subject", "Date", "Message-ID", "Return-Path")
    
    foreach ($header in $headers) {
        $pattern = "${header}:\s*(.+?)(?=\r?\n(?!\s))"
        $match = [regex]::Match($Content, $pattern, [regex]::RegexOptions::IgnoreCase -bor [regex]::RegexOptions::Singleline)
        if ($match.Success) {
            $metadata[$header] = $match.Groups[1].Value.Trim()
        }
    }
    
    # Extract sender IP if available
    $ipPattern = "sender IP is (\d+\.\d+\.\d+\.\d+)"
    $ipMatch = [regex]::Match($Content, $ipPattern)
    if ($ipMatch.Success) {
        $metadata["SenderIP"] = $ipMatch.Groups[1].Value
    }
    
    return $metadata
}

function Test-FocusUserCompromise {
    param([string]$Content, [string]$FocusUser)
    
    if ([string]::IsNullOrEmpty($FocusUser)) {
        return @()
    }
    
    $compromiseIndicators = @()
    
    # Check if focus user is sender
    if ($Content -match "From:.*$FocusUser") {
        $compromiseIndicators += "Email sent from focus user: $FocusUser"
    }
    
    # Check for focus user in authentication failures
    if ($Content -match "$FocusUser.*fail|fail.*$FocusUser") {
        $compromiseIndicators += "Authentication failures involving: $FocusUser"
    }
    
    # Check for unusual sending patterns
    if ($Content -match "From:.*$FocusUser.*" -and $Content -match "urgent|payment|invoice") {
        $compromiseIndicators += "Focus user sending suspicious content patterns"
    }
    
    return $compromiseIndicators
}

# Get script directory for exports
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Main analysis logic
Write-Host "Email Security Breach Analysis Tool with Entra ID Integration" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Connect to Microsoft 365 if sign-in logs requested
$signInLogs = @()
$suspiciousSignIns = @()

if ($IncludeSignInLogs) {
    $connected = Connect-To365Services
    if ($connected) {
        $signInLogs = Get-EntraSignInLogs -UserPrincipalName $(if ($FocusUser) { "$FocusUser@*" } else { "" }) -DaysBack $DaysBack
        $suspiciousSignIns = Test-SuspiciousSignIns -SignInLogs $signInLogs -FocusUser $FocusUser
        
        Write-Host "Sign-in Analysis Summary:" -ForegroundColor Yellow
        Write-Host "Total sign-ins analyzed: $($signInLogs.Count)"
        Write-Host "Suspicious sign-ins found: $($suspiciousSignIns.Count)" -ForegroundColor $(if ($suspiciousSignIns.Count -gt 0) { "Red" } else { "Green" })
        Write-Host ""
    }
}

# Find .eml files
$emlFiles = @()
if (Test-Path $Path -PathType Container) {
    $emlFiles = Get-ChildItem -Path $Path -Filter "*.eml" -Recurse
} elseif (Test-Path $Path -PathType Leaf -and $Path.EndsWith(".eml")) {
    $emlFiles = @(Get-Item $Path)
} else {
    Write-Error "Invalid path or no .eml files found"
    exit 1
}

Write-Host "Found $($emlFiles.Count) .eml file(s) for analysis" -ForegroundColor Green
Write-Host ""

$allFindings = @()

foreach ($file in $emlFiles) {
    Write-Host "Analyzing: $($file.Name)" -ForegroundColor Yellow
    Write-Host "=" * 50
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
        
        # Extract metadata
        $metadata = Get-EmailMetadata -Content $content
        
        # Test for authentication failures
        $authFailures = Test-AuthenticationFailures -Content $content
        
        # Test for suspicious patterns
        $suspiciousPatterns = Test-SuspiciousPatterns -Content $content -FileName $file.Name
        
        # Test focus user compromise
        $focusUserIndicators = @()
        if (-not [string]::IsNullOrEmpty($FocusUser)) {
            $focusUserIndicators = Test-FocusUserCompromise -Content $content -FocusUser $FocusUser
        }
        
        # Calculate risk score
        $riskScore = 0
        $riskScore += $authFailures.Count * 20
        $riskScore += $suspiciousPatterns.Count * 15
        $riskScore += $focusUserIndicators.Count * 25
        
        # Determine overall risk level
        $riskLevel = switch ($riskScore) {
            { $_ -ge 75 } { "CRITICAL" }
            { $_ -ge 50 } { "HIGH" }
            { $_ -ge 25 } { "MEDIUM" }
            default { "LOW" }
        }
        
        # Display findings
        Write-Host "Risk Level: $riskLevel (Score: $riskScore)" -ForegroundColor $(
            switch ($riskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
            }
        )
        
        Write-Host ""
        Write-Host "Email Metadata:" -ForegroundColor White
        foreach ($key in $metadata.Keys) {
            Write-Host "  ${key}: $($metadata[$key])"
        }
        
        if ($authFailures.Count -gt 0) {
            Write-Host ""
            Write-SecurityAlert "Authentication Issues Detected:" "CRITICAL"
            $authFailures | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        }
        
        if ($suspiciousPatterns.Count -gt 0) {
            Write-Host ""
            Write-SecurityAlert "Suspicious Patterns Found:" "HIGH"
            $suspiciousPatterns | ForEach-Object { Write-Host "   $_" -ForegroundColor Yellow }
        }
        
        if ($focusUserIndicators.Count -gt 0) {
            Write-Host ""
            Write-SecurityAlert "Focus User ($FocusUser) Compromise Indicators:" "CRITICAL"
            $focusUserIndicators | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        }
        
        # Correlate with sign-in data
        $correlatedSignIns = @()
        if ($suspiciousSignIns.Count -gt 0 -and -not [string]::IsNullOrEmpty($FocusUser)) {
            $emailDate = if ($metadata["Date"]) { 
                try { [DateTime]::Parse($metadata["Date"]) } catch { $null }
            } else { $null }
            
            if ($emailDate) {
                $correlatedSignIns = $suspiciousSignIns | Where-Object {
                    $signInDate = [DateTime]::Parse($_.DateTime)
                    $timeDiff = [Math]::Abs(($emailDate - $signInDate).TotalHours)
                    $timeDiff -le 24 -and $_.UserPrincipalName -like "*$FocusUser*"
                }
                
                if ($correlatedSignIns.Count -gt 0) {
                    Write-SecurityAlert "CORRELATION ALERT: Suspicious sign-ins detected within 24 hours of this email!" "CRITICAL"
                    $riskScore += 50
                }
            }
        }
        
        # Store findings for export
        $finding = [PSCustomObject]@{
            FileName = $file.Name
            FilePath = $file.FullName
            RiskLevel = $riskLevel
            RiskScore = $riskScore
            From = $metadata["From"]
            To = $metadata["To"] 
            Subject = $metadata["Subject"]
            Date = $metadata["Date"]
            SenderIP = $metadata["SenderIP"]
            AuthFailures = ($authFailures -join "; ")
            SuspiciousPatterns = ($suspiciousPatterns -join "; ")
            FocusUserIndicators = ($focusUserIndicators -join "; ")
            CorrelatedSignIns = ($correlatedSignIns.Count)
            AnalysisDate = Get-Date
        }
        $allFindings += $finding
        
    } catch {
        Write-Error "Failed to analyze $($file.Name): $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host ""
}

# Detailed sign-in analysis if available
if ($suspiciousSignIns.Count -gt 0) {
    Write-Host "SUSPICIOUS SIGN-IN ACTIVITIES" -ForegroundColor Red
    Write-Host "=============================" -ForegroundColor Red
    
    $suspiciousSignIns | Sort-Object RiskScore -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host " $($_.DateTime): $($_.UserPrincipalName)" -ForegroundColor Yellow
        Write-Host "  IP: $($_.IpAddress) | Location: $($_.Location)" -ForegroundColor Gray
        Write-Host "  Risk: $($_.RiskScore) | Factors: $($_.RiskFactors)" -ForegroundColor Gray
        Write-Host ""
    }
}

# Summary
Write-Host "ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$lowCount = ($allFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count

Write-Host "Critical Risk: $criticalCount" -ForegroundColor Red
Write-Host "High Risk: $highCount" -ForegroundColor Yellow
Write-Host "Medium Risk: $mediumCount" -ForegroundColor Cyan
Write-Host "Low Risk: $lowCount" -ForegroundColor Green

# Enhanced threat assessment with sign-in correlation
$overallThreatLevel = "LOW"
if ($criticalCount -gt 0 -or $suspiciousSignIns.Count -ge 5) {
    $overallThreatLevel = "CRITICAL"
} elseif ($highCount -gt 0 -or $suspiciousSignIns.Count -ge 2) {
    $overallThreatLevel = "HIGH"
} elseif ($mediumCount -gt 0 -or $suspiciousSignIns.Count -ge 1) {
    $overallThreatLevel = "MEDIUM"
}

Write-Host ""
Write-Host "OVERALL THREAT LEVEL: $overallThreatLevel" -ForegroundColor $(switch ($overallThreatLevel) {
    "CRITICAL" { "Red" }
    "HIGH" { "Yellow" }
    "MEDIUM" { "Cyan" }
    default { "Green" }
})

if ($overallThreatLevel -in @("CRITICAL", "HIGH")) {
    Write-Host ""
    Write-SecurityAlert "POTENTIAL SECURITY BREACH DETECTED!" "CRITICAL"
    Write-SecurityAlert "Immediate investigation recommended" "CRITICAL"
    
    if ($suspiciousSignIns.Count -gt 0) {
        Write-SecurityAlert "Review sign-in anomalies for $FocusUser immediately" "CRITICAL"
    }
}

# Export report if requested
if ($ExportReport) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $emailReportPath = Join-Path $ScriptDir "EmailSecurityReport_$timestamp.csv"
    $signInReportPath = Join-Path $ScriptDir "SignInAnalysisReport_$timestamp.csv"
    
    $allFindings | Export-Csv -Path $emailReportPath -NoTypeInformation
    Write-Host ""
    Write-Host "Email analysis report exported to: $emailReportPath" -ForegroundColor Green
    
    if ($suspiciousSignIns.Count -gt 0) {
        $suspiciousSignIns | Export-Csv -Path $signInReportPath -NoTypeInformation
        Write-Host "Sign-in analysis report exported to: $signInReportPath" -ForegroundColor Green
    }
    
    # Create combined summary report
    $summaryReportPath = Join-Path $ScriptDir "CombinedSecuritySummary_$timestamp.txt"
    $summaryReport = @"
SECURITY BREACH ANALYSIS SUMMARY
================================
Analysis Date: $(Get-Date)
Focus User: $FocusUser
Days Analyzed: $DaysBack

EMAIL ANALYSIS:
--------------
Emails Analyzed: $($allFindings.Count)
Critical Risk: $criticalCount
High Risk: $highCount
Medium Risk: $mediumCount
Low Risk: $lowCount

SIGN-IN ANALYSIS:
----------------
Sign-ins Analyzed: $($signInLogs.Count)
Suspicious Sign-ins: $($suspiciousSignIns.Count)

"@
    
    if ($criticalCount -gt 0 -or $highCount -gt 0 -or $suspiciousSignIns.Count -gt 0) {
        $summaryReport += "
RECOMMENDATIONS:
---------------
"
        if ($criticalCount -gt 0) {
            $summaryReport += " IMMEDIATE ACTION REQUIRED: Critical email threats detected
"
        }
        if ($suspiciousSignIns.Count -gt 0) {
            $summaryReport += " Review suspicious sign-in activities immediately
"
        }
        $summaryReport += " Consider resetting passwords for affected users
"
        $summaryReport += " Enable MFA if not already configured
"
        $summaryReport += " Review conditional access policies
"
    }
    
    $summaryReport | Out-File -FilePath $summaryReportPath -Encoding UTF8
    Write-Host "Combined summary report exported to: $summaryReportPath" -ForegroundColor Green
}

Write-Host ""
# Final security assessment
if (($criticalCount -gt 0 -or $highCount -gt 0) -and $suspiciousSignIns.Count -gt 0) {
    Write-Host ""
    Write-SecurityAlert "MULTI-VECTOR ATTACK DETECTED!" "CRITICAL"
    Write-SecurityAlert "Both email and sign-in anomalies found - possible coordinated breach" "CRITICAL"
}

Write-Host ""
Write-Host "Analysis completed." -ForegroundColor Green
Write-Host "Script location: $ScriptDir" -ForegroundColor Gray
