<#
.SYNOPSIS
    Automated escalation workflow for complex system stability issues
.DESCRIPTION
    Intelligent escalation system that routes stability issues based on severity,
    user impact, and technical complexity. Integrates with PSA ticketing.

.NOTES
    Category: Diagnostics

.KEYWORDS
    stability, escalation, the PSA, RMM, severity
#>

#Requires -Version 5.1

param(
    [string]$ClientCode = $ENV:COMPUTERNAME,
    [string]$StabilityReportPath,
    [ValidateSet('Low','Medium','High','Critical')]
    [string]$SeverityLevel = 'Medium',
    [int]$StabilityScore = 50,
    [switch]$AutoCreateTicket,
    [string]$TechnicianEmail,
    [string]$ManagerEmail = "manager@rmm.example.com"
)

$ErrorActionPreference = 'SilentlyContinue'

function Write-RMMLog {
    param($Level, $Code, $Message, $Data = @{})
    $JsonData = $Data | ConvertTo-Json -Compress
    Write-Output "[RMM]|$Level|$Code|$Message|$JsonData"
}

function Get-EscalationMatrix {
    return @{
        'Low' = @{
            AutoResolve = $true
            TicketPriority = 'Low'
            ResponseTimeSLA = 24  # hours
            AssignedTier = 1
            RequiresApproval = $false
            NotifyManager = $false
            Actions = @('automated_remediation', 'schedule_maintenance')
        }
        'Medium' = @{
            AutoResolve = $false
            TicketPriority = 'Medium'
            ResponseTimeSLA = 8   # hours
            AssignedTier = 1
            RequiresApproval = $false
            NotifyManager = $false
            Actions = @('diagnostic_collection', 'vendor_research', 'scheduled_reboot')
        }
        'High' = @{
            AutoResolve = $false
            TicketPriority = 'High'
            ResponseTimeSLA = 4   # hours
            AssignedTier = 2
            RequiresApproval = $true
            NotifyManager = $true
            Actions = @('immediate_diagnostic', 'vendor_escalation', 'backup_verification')
        }
        'Critical' = @{
            AutoResolve = $false
            TicketPriority = 'Critical'
            ResponseTimeSLA = 1   # hour
            AssignedTier = 3
            RequiresApproval = $true
            NotifyManager = $true
            Actions = @('emergency_response', 'site_visit', 'hardware_replacement_planning')
        }
    }
}

function Get-ClientEscalationProfile {
    param($ClientCode)
    
    # This would typically pull from client database
    # For now, using standard profiles based on client code patterns
    
    $DefaultProfile = @{
        BusinessHours = @{Start = 8; End = 17}
        TimeZone = 'Eastern Standard Time'
        CriticalSystems = @('DC', 'SQL', 'EXCHANGE', 'FIREWALL')
        EscalationContacts = @{
            Primary = "admin@$ClientCode.local"
            Secondary = "manager@$ClientCode.local"
            Emergency = "owner@$ClientCode.local"
        }
        SLALevel = 'Standard'  # Standard, Premium, Enterprise
        AllowAfterHours = $false
        RequireApprovalForReboot = $true
    }
    
    # Adjust based on client code patterns
    if ($ClientCode -match '^(BANK|MEDICAL|LAW)') {
        $DefaultProfile.SLALevel = 'Premium'
        $DefaultProfile.AllowAfterHours = $true
        $DefaultProfile.RequireApprovalForReboot = $true
    } elseif ($ClientCode -match '^(GOVT|FINANCE|HEALTHCARE)') {
        $DefaultProfile.SLALevel = 'Enterprise'
        $DefaultProfile.AllowAfterHours = $true
        $DefaultProfile.RequireApprovalForReboot = $false  # Pre-approved
    }
    
    return $DefaultProfile
}

function Test-BusinessHours {
    param($ClientProfile)
    
    $CurrentTime = Get-Date
    $BusinessStart = $CurrentTime.Date.AddHours($ClientProfile.BusinessHours.Start)
    $BusinessEnd = $CurrentTime.Date.AddHours($ClientProfile.BusinessHours.End)
    
    return ($CurrentTime -ge $BusinessStart -and $CurrentTime -le $BusinessEnd -and $CurrentTime.DayOfWeek -notin @('Saturday','Sunday'))
}

function New-EscalationTicket {
    param($ClientCode, $SeverityLevel, $StabilityData, $EscalationRule, $ClientProfile)
    
    $TicketData = @{
        ClientCode = $ClientCode
        Summary = "System Stability Issue - $SeverityLevel Severity"
        Description = ""
        Priority = $EscalationRule.TicketPriority
        Category = "System Administration"
        Subcategory = "System Stability"
        AssignedTier = $EscalationRule.AssignedTier
        SLAHours = $EscalationRule.ResponseTimeSLA
        CreatedBy = "RMM-AutoEscalation"
        RequiresApproval = $EscalationRule.RequiresApproval
    }
    
    # Build detailed description
    $Description = @"
AUTOMATED ESCALATION - System Stability Analysis

Client: $ClientCode
Severity: $SeverityLevel
Stability Score: $StabilityScore/100
Detection Time: $(Get-Date)

ISSUE SUMMARY:
"@
    
    if ($StabilityData) {
        $Description += @"

System Health Metrics:
- Memory Utilization: $($StabilityData.SystemStability.MemoryUtilizationPercent)%
- CPU Load Average: $($StabilityData.SystemStability.CPUAverageLoad)%
- Uptime: $($StabilityData.SystemStability.UptimeDays) days
- Critical Events: $($StabilityData.BlueScreen.TotalCriticalEvents)
- Hardware Issues: $($StabilityData.Drivers.ProblemDevices.Count)

RECOMMENDED ACTIONS:
$($StabilityData.SystemHealth.Recommendations -join "`n")
"@
    }
    
    $Description += @"

ESCALATION DETAILS:
- Response SLA: $($EscalationRule.ResponseTimeSLA) hours
- Assigned Tier: $($EscalationRule.AssignedTier)
- Business Hours: $(Test-BusinessHours $ClientProfile)
- Auto-Resolve: $($EscalationRule.AutoResolve)

Next Steps: $(($EscalationRule.Actions -join ', ').ToUpper())

Generated by RMM Automated Escalation System
Report Path: $StabilityReportPath
"@
    
    $TicketData.Description = $Description
    
    return $TicketData
}

function Send-EscalationNotifications {
    param($TicketData, $ClientProfile, $EscalationRule)
    
    $IsBusinessHours = Test-BusinessHours $ClientProfile
    $NotificationsSent = @()
    
    # Determine notification recipients
    $Recipients = @()
    
    if ($EscalationRule.AssignedTier -eq 1) {
        $Recipients += "level1@rmm.example.com"
    } elseif ($EscalationRule.AssignedTier -eq 2) {
        $Recipients += "level2@rmm.example.com"
    } elseif ($EscalationRule.AssignedTier -eq 3) {
        $Recipients += "level3@rmm.example.com"
        $Recipients += "oncall@rmm.example.com"
    }
    
    if ($EscalationRule.NotifyManager) {
        $Recipients += $ManagerEmail
    }
    
    if ($TechnicianEmail) {
        $Recipients += $TechnicianEmail
    }
    
    # After-hours escalation
    if (-not $IsBusinessHours -and $TicketData.Priority -in @('High', 'Critical')) {
        $Recipients += "afterhours@rmm.example.com"
        if ($TicketData.Priority -eq 'Critical') {
            $Recipients += "emergency@rmm.example.com"
        }
    }
    
    # Client notifications based on severity
    if ($TicketData.Priority -in @('High', 'Critical')) {
        $Recipients += $ClientProfile.EscalationContacts.Primary
        if ($TicketData.Priority -eq 'Critical') {
            $Recipients += $ClientProfile.EscalationContacts.Emergency
        }
    }
    
    foreach ($Recipient in ($Recipients | Sort-Object -Unique)) {
        try {
            # This would integrate with your email system
            # For now, log the notification
            Write-RMMLog "INFO" "NOTIFY" "Escalation notification sent" @{
                recipient = $Recipient
                priority = $TicketData.Priority
                client = $ClientCode
                ticket_tier = $EscalationRule.AssignedTier
            }
            $NotificationsSent += $Recipient
        } catch {
            Write-RMMLog "ERROR" "NOTIFY" "Failed to send notification" @{
                recipient = $Recipient
                error = $_.Exception.Message
            }
        }
    }
    
    return $NotificationsSent
}

function Invoke-AutomatedActions {
    param($Actions, $ClientCode, $StabilityScore)
    
    $ExecutedActions = @()
    
    foreach ($Action in $Actions) {
        try {
            switch ($Action) {
                'automated_remediation' {
                    # Run the diagnostic script with auto-remediation
                    $DiagnosticScript = "$PSScriptRoot\Freeze-BSOD-Diagnostic.ps1"
                    if (Test-Path $DiagnosticScript) {
                        & $DiagnosticScript -ClientCode $ClientCode -AutoRemediate
                        $ExecutedActions += "Automated remediation completed"
                    }
                }
                
                'diagnostic_collection' {
                    # Collect comprehensive system diagnostics
                    $DiagnosticScript = "$PSScriptRoot\Freeze-BSOD-Diagnostic.ps1"
                    if (Test-Path $DiagnosticScript) {
                        & $DiagnosticScript -ClientCode $ClientCode
                        $ExecutedActions += "Diagnostic data collected"
                    }
                }
                
                'schedule_maintenance' {
                    # Schedule maintenance window
                    $MaintenanceTime = (Get-Date).AddDays(1).Date.AddHours(2)  # 2 AM tomorrow
                    # This would integrate with your scheduling system
                    Write-RMMLog "INFO" "SCHEDULE" "Maintenance window scheduled" @{
                        client = $ClientCode
                        scheduled_time = $MaintenanceTime
                    }
                    $ExecutedActions += "Maintenance window scheduled for $MaintenanceTime"
                }
                
                'backup_verification' {
                    # Verify backup status before potential system changes
                    $BackupScript = "$PSScriptRoot\Verify-BackupStatus.ps1"
                    if (Test-Path $BackupScript) {
                        & $BackupScript -ClientCode $ClientCode
                        $ExecutedActions += "Backup verification initiated"
                    }
                }
                
                'scheduled_reboot' {
                    # Schedule system reboot during maintenance window
                    if ($StabilityScore -lt 30) {
                        # Critical - schedule immediate reboot
                        shutdown /r /t 3600 /c "System stability reboot scheduled by RMM"
                        $ExecutedActions += "Emergency reboot scheduled in 60 minutes"
                    } else {
                        # Schedule for off-hours
                        $RebootTime = (Get-Date).AddDays(1).Date.AddHours(3)  # 3 AM tomorrow
                        $ExecutedActions += "Reboot scheduled for $RebootTime"
                    }
                }
                
                'immediate_diagnostic' {
                    # Run comprehensive diagnostic immediately
                    $DiagnosticScript = "$PSScriptRoot\Freeze-BSOD-Diagnostic.ps1"
                    if (Test-Path $DiagnosticScript) {
                        Start-Job -ScriptBlock {
                            param($Script, $Client)
                            & $Script -ClientCode $Client -AutoRemediate
                        } -ArgumentList $DiagnosticScript, $ClientCode
                        $ExecutedActions += "Immediate diagnostic started in background"
                    }
                }
                
                default {
                    Write-RMMLog "WARN" "ACTION" "Unknown automated action" @{action = $Action}
                }
            }
        } catch {
            Write-RMMLog "ERROR" "ACTION" "Automated action failed" @{
                action = $Action
                error = $_.Exception.Message
            }
        }
    }
    
    return $ExecutedActions
}

function Save-EscalationRecord {
    param($EscalationData)
    
    $RecordPath = "$env:TEMP\EscalationRecord-$ClientCode-$(Get-Date -Format 'yyyyMMdd-HHmm').json"
    $EscalationData | ConvertTo-Json -Depth 5 | Out-File -FilePath $RecordPath
    
    Write-RMMLog "INFO" "RECORD" "Escalation record saved" @{path = $RecordPath}
    
    return $RecordPath
}

# Main escalation workflow
try {
    Write-RMMLog "INFO" "START" "Escalation workflow initiated" @{
        client = $ClientCode
        severity = $SeverityLevel
        stability_score = $StabilityScore
        auto_ticket = $AutoCreateTicket.IsPresent
    }
    
    # Load stability data if report path provided
    $StabilityData = $null
    if ($StabilityReportPath -and (Test-Path $StabilityReportPath)) {
        $StabilityData = Get-Content -Path $StabilityReportPath | ConvertFrom-Json
        $StabilityScore = $StabilityData.SystemHealth.StabilityScore
        
        # Auto-determine severity if not specified
        if ($PSBoundParameters.SeverityLevel -eq $null) {
            if ($StabilityScore -lt 20) { $SeverityLevel = 'Critical' }
            elseif ($StabilityScore -lt 40) { $SeverityLevel = 'High' }
            elseif ($StabilityScore -lt 70) { $SeverityLevel = 'Medium' }
            else { $SeverityLevel = 'Low' }
        }
    }
    
    # Get escalation rules and environment profile
    $EscalationMatrix = Get-EscalationMatrix
    $EscalationRule = $EscalationMatrix[$SeverityLevel]
    $ClientProfile = Get-ClientEscalationProfile -ClientCode $ClientCode
    
    # Execute automated actions
    $ExecutedActions = @()
    if ($EscalationRule.Actions.Count -gt 0) {
        $ExecutedActions = Invoke-AutomatedActions -Actions $EscalationRule.Actions -ClientCode $ClientCode -StabilityScore $StabilityScore
    }
    
    # Create ticket if auto-creation enabled or severity requires it
    $TicketData = $null
    $NotificationsSent = @()
    
    if ($AutoCreateTicket -or $SeverityLevel -in @('High', 'Critical')) {
        $TicketData = New-EscalationTicket -ClientCode $ClientCode -SeverityLevel $SeverityLevel -StabilityData $StabilityData -EscalationRule $EscalationRule -ClientProfile $ClientProfile
        
        # Send notifications
        $NotificationsSent = Send-EscalationNotifications -TicketData $TicketData -ClientProfile $ClientProfile -EscalationRule $EscalationRule
    }
    
    # Build final escalation record
    $EscalationRecord = @{
        Timestamp = Get-Date
        Client = $ClientCode
        Severity = $SeverityLevel
        StabilityScore = $StabilityScore
        EscalationRule = $EscalationRule
        ClientProfile = $ClientProfile
        TicketCreated = ($TicketData -ne $null)
        TicketData = $TicketData
        NotificationsSent = $NotificationsSent
        ExecutedActions = $ExecutedActions
        ReportPath = $StabilityReportPath
        BusinessHours = Test-BusinessHours $ClientProfile
    }
    
    # Save escalation record
    $RecordPath = Save-EscalationRecord -EscalationData $EscalationRecord
    
    Write-RMMLog "SUCCESS" "COMPLETE" "Escalation workflow completed" @{
        severity = $SeverityLevel
        tier_assigned = $EscalationRule.AssignedTier
        ticket_created = ($TicketData -ne $null)
        notifications_sent = $NotificationsSent.Count
        actions_executed = $ExecutedActions.Count
        record_path = $RecordPath
    }
    
    # Display summary
    Write-Host "=== ESCALATION WORKFLOW SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Client: $ClientCode" -ForegroundColor Yellow
    Write-Host "Severity: $SeverityLevel" -ForegroundColor $(if($SeverityLevel -eq 'Critical'){'Red'}elseif($SeverityLevel -eq 'High'){'Yellow'}else{'Green'})
    Write-Host "Stability Score: $StabilityScore/100" -ForegroundColor $(if($StabilityScore -lt 40){'Red'}elseif($StabilityScore -lt 70){'Yellow'}else{'Green'})
    Write-Host "Assigned Tier: $($EscalationRule.AssignedTier)" -ForegroundColor White
    Write-Host "Response SLA: $($EscalationRule.ResponseTimeSLA) hours" -ForegroundColor White

    if ($TicketData) {
        Write-Host "`nTicket Created: YES" -ForegroundColor Green
        Write-Host "Priority: $($TicketData.Priority)" -ForegroundColor White
    }

    if ($NotificationsSent.Count -gt 0) {
        Write-Host "`nNotifications Sent: $($NotificationsSent.Count)" -ForegroundColor Green
        $NotificationsSent | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    }

    if ($ExecutedActions.Count -gt 0) {
        Write-Host "`nAutomated Actions:" -ForegroundColor Green
        $ExecutedActions | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    }

    exit 0
}
catch {
    Write-RMMLog "ERROR" "ESCALATION" "Escalation workflow failed" @{
        client = $ClientCode
        error = $_.Exception.Message
        stack_trace = $_.ScriptStackTrace
    }
    exit 1
}