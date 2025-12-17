<#
.SYNOPSIS
    Quick Task Scheduler audit to find stray/forgotten tasks

.DESCRIPTION
    Fast scan of scheduled tasks to identify tasks that should likely be disabled
    .RMM_CATEGORY
    Maintenance
    .CLIENT_IMPACT
    None
    .EXECUTION_TIME
    2 minutes

.PARAMETER AutoDisable
    Enables auto disable handling.

.PARAMETER WhatIf
    Enables what if handling.

.EXAMPLES
    Example 1: Run with defaults
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-TaskSchedulerAudit.ps1'

    Example 2: Provide key parameters
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'c:\temp\Get-TaskSchedulerAudit.ps1' -AutoDisable -WhatIf

.NOTES
    Author: Brandon Sager
    Date: 12/26/2025
    
    Quick execution methods:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\Audit-TaskScheduler.ps1'
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & 'C:\temp\Audit-TaskScheduler.ps1' -AutoDisable
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$AutoDisable,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

try {
    "[RMM]|INFO|START|Task Scheduler audit started|{}"
    $StartTime = Get-Date

    # Quick scan - focus on root level tasks and common problem areas
    $AllTasks = Get-ScheduledTask | Where-Object {
        $_.TaskPath -eq '\' -or
        $_.TaskPath -like '\Microsoft\Office\*' -or
        $_.TaskPath -like '\Adobe\*' -or
        $_.TaskPath -like '\GoogleUpdateTaskMachine*'
    }

    $AuditResults = @()
    $TaskCount = 0

    foreach ($Task in $AllTasks) {
        $TaskCount++

        try {
            $TaskInfo = Get-ScheduledTaskInfo -TaskName $Task.TaskName -ErrorAction SilentlyContinue

            # Quick risk assessment
            $RiskScore = 0
            $Issues = @()
            $Recommendation = "Keep"

            # Check if task points to non-existent file
            $FileExists = $true
            if ($Task.Actions.Execute) {
                $ExecutePath = $Task.Actions.Execute
                if ($ExecutePath -and !(Test-Path $ExecutePath -ErrorAction SilentlyContinue)) {
                    $RiskScore += 5
                    $Issues += "File not found"
                    $FileExists = $false
                }
            }

            # Check for generic task names
            if ($Task.TaskName -match "^(Task\d+|MyTask|UserTask|Test|Temp)") {
                $RiskScore += 3
                $Issues += "Generic name"
            }

            # Check for consistent failures
            if ($TaskInfo.LastTaskResult -ne 0 -and $TaskInfo.LastTaskResult -ne $null) {
                $RiskScore += 2
                $Issues += "Last run failed (Code: $($TaskInfo.LastTaskResult))"
            }

            # Check if disabled but has schedule
            if ($Task.State -eq "Disabled" -and $Task.Triggers.Count -gt 0) {
                $RiskScore += 1
                $Issues += "Disabled with active schedule"
            }

            # Check last run time - handle various date formats safely
            $DaysSinceLastRun = $null
            $LastRunTimeString = "Never"
            if ($TaskInfo.LastRunTime) {
                try {
                    # Parse the date safely, handle various formats
                    $LastRunDate = $null
                    if ($TaskInfo.LastRunTime -is [DateTime]) {
                        $LastRunDate = $TaskInfo.LastRunTime
                    } else {
                        $LastRunDate = [DateTime]::Parse($TaskInfo.LastRunTime.ToString())
                    }

                    # Check if it's a reasonable date (after year 2000)
                    if ($LastRunDate -gt (Get-Date "1/1/2000")) {
                        $DaysSinceLastRun = [math]::Round((Get-Date - $LastRunDate).TotalDays)
                        $LastRunTimeString = $LastRunDate.ToString("yyyy-MM-dd HH:mm")

                        if ($DaysSinceLastRun -gt 90 -and $Task.State -eq "Ready") {
                            $RiskScore += 2
                            $Issues += "Not run in $DaysSinceLastRun days"
                        }
                    } else {
                        $LastRunTimeString = "Invalid date"
                    }
                } catch {
                    $LastRunTimeString = "Parse error"
                }
            }

            # Determine recommendation
            if ($RiskScore -ge 5) {
                $Recommendation = "DISABLE"
            } elseif ($RiskScore -ge 3) {
                $Recommendation = "INVESTIGATE"
            }

            # Skip Microsoft system tasks for auto-disable
            if ($Task.Author -eq "Microsoft Corporation" -and $Recommendation -eq "DISABLE") {
                $Recommendation = "INVESTIGATE"
            }

            $AuditResults += [PSCustomObject]@{
                TaskName = $Task.TaskName
                TaskPath = $Task.TaskPath
                State = $Task.State
                Author = $Task.Author
                LastRunTime = $LastRunTimeString
                LastResult = $TaskInfo.LastTaskResult
                DaysSinceLastRun = $DaysSinceLastRun
                FileExists = $FileExists
                RiskScore = $RiskScore
                Issues = ($Issues -join "; ")
                Recommendation = $Recommendation
            }

        } catch {
            "[RMM]|WARN|TASK|Failed to analyze task|{`"task`":`"$($Task.TaskName)`",`"error`":`"$($_.Exception.Message)`"}"
        }
    }

    # Generate summary statistics
    $TotalTasks = $AuditResults.Count
    $DisableRecommended = ($AuditResults | Where-Object Recommendation -eq "DISABLE").Count
    $InvestigateRecommended = ($AuditResults | Where-Object Recommendation -eq "INVESTIGATE").Count
    $KeepRecommended = ($AuditResults | Where-Object Recommendation -eq "Keep").Count

    # Export results
    $ReportPath = "$env:USERPROFILE\Desktop\TaskScheduler-Audit-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    $AuditResults | Sort-Object RiskScore -Descending | Export-Csv -Path $ReportPath -NoTypeInformation

    "[RMM]|SUCCESS|REPORT|Audit report generated|{`"path`":`"$ReportPath`",`"total_tasks`":$TotalTasks,`"disable_recommended`":$DisableRecommended}"

    # Display summary
    Write-Host "`n=== TASK SCHEDULER AUDIT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total Tasks Analyzed: $TotalTasks" -ForegroundColor White
    Write-Host "Recommend DISABLE: $DisableRecommended" -ForegroundColor Red
    Write-Host "Recommend INVESTIGATE: $InvestigateRecommended" -ForegroundColor Yellow
    Write-Host "Recommend KEEP: $KeepRecommended" -ForegroundColor Green
    Write-Host "Report saved to: $ReportPath" -ForegroundColor Cyan

    # Show top risk tasks
    $TopRiskTasks = $AuditResults | Where-Object RiskScore -ge 3 | Sort-Object RiskScore -Descending | Select-Object -First 10
    if ($TopRiskTasks) {
        Write-Host "`n=== TOP RISK TASKS ===" -ForegroundColor Red
        $TopRiskTasks | Format-Table TaskName, State, RiskScore, Issues -Wrap
    }

    # Auto-disable functionality
    if ($AutoDisable) {
        $TasksToDisable = $AuditResults | Where-Object { $_.Recommendation -eq "DISABLE" -and $_.State -eq "Ready" }

        if ($TasksToDisable) {
            Write-Host "`n=== AUTO-DISABLE CANDIDATES ===" -ForegroundColor Yellow
            $TasksToDisable | Format-Table TaskName, Issues

            if (!$WhatIf) {
                $Confirm = Read-Host "Disable these $($TasksToDisable.Count) tasks? (y/N)"
                if ($Confirm -eq 'y' -or $Confirm -eq 'Y') {
                    foreach ($TaskToDisable in $TasksToDisable) {
                        try {
                            Disable-ScheduledTask -TaskName $TaskToDisable.TaskName -TaskPath $TaskToDisable.TaskPath
                            "[RMM]|SUCCESS|DISABLE|Task disabled|{`"task`":`"$($TaskToDisable.TaskName)`"}"
                            Write-Host "Disabled: $($TaskToDisable.TaskName)" -ForegroundColor Green
                        } catch {
                            "[RMM]|ERROR|DISABLE|Failed to disable task|{`"task`":`"$($TaskToDisable.TaskName)`",`"error`":`"$($_.Exception.Message)`"}"
                            Write-Host "Failed to disable: $($TaskToDisable.TaskName)" -ForegroundColor Red
                        }
                    }
                } else {
                    "[RMM]|INFO|DISABLE|Auto-disable cancelled by user|{}"
                }
            } else {
                Write-Host "WhatIf: Would disable $($TasksToDisable.Count) tasks" -ForegroundColor Yellow
            }
        } else {
            Write-Host "No tasks found for auto-disable" -ForegroundColor Green
        }
    }

    $Duration = [math]::Round((Get-Date - $StartTime).TotalSeconds, 1)
    "[RMM]|SUCCESS|COMPLETE|Task Scheduler audit completed|{`"duration_seconds`":$Duration,`"tasks_analyzed`":$TaskCount,`"report_path`":`"$ReportPath`"}"

    exit 0

} catch {
    "[RMM]|ERROR|EXCEPTION|Task Scheduler audit failed|{`"error`":`"$($_.Exception.Message)`",`"line`":`"$($_.InvocationInfo.ScriptLineNumber)`"}"
    exit 1
}
