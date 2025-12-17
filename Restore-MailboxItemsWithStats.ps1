<#
.SYNOPSIS
    Restore Mailbox Recoverable Items with Before/After Statistics

.DESCRIPTION
    Restores deleted items from Exchange Online mailbox recoverable items folder
    with comprehensive statistics tracking. Includes:
    - Before/after mailbox statistics for audit trail
    - Automatic role assignment (Discovery Management, Mailbox Import Export)
    - Progress tracking through 6-stage workflow
    - Managed Folder Assistant triggering

    Useful for recovering accidentally deleted emails or investigating data loss.

.NOTES
    Author: Brandon Sager
    Version: 1.0

    Requirements:
    - PowerShell 5.1+
    - ExchangeOnlineManagement module
    - Exchange Admin permissions

    Warning: Role assignments can take up to 60 minutes to propagate in M365.
#>

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement



[CmdletBinding(SupportsShouldProcess)]
param()

# Execution Policy Setup
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch {}
}

$TranscriptPath = "C:\Temp"
if (-not (Test-Path $TranscriptPath)) { New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null }
$ScriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$TranscriptFile = Join-Path $TranscriptPath "PS-Transcript_$($env:COMPUTERNAME)_$ScriptBaseName`_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($PID).log"
Start-Transcript -Path $TranscriptFile -Force

function Test-ScriptDependencies {
    param([string[]]$RequiredModules = @())
    foreach ($Module in $RequiredModules) {
        if ([string]::IsNullOrWhiteSpace($Module)) { continue }
        if (-not (Get-Module -ListAvailable -Name $Module)) {
            Write-Warning "Installing module: $Module"
            Install-Module -Name $Module -Scope CurrentUser -Force -AllowClobber
        }
    }
}

try {
    Write-Host "Starting $ScriptBaseName (Exchange)..." -ForegroundColor Green
    Write-Verbose "Transcript logging to: $TranscriptFile"

    Test-ScriptDependencies -RequiredModules @('ExchangeOnlineManagement')
    
    # CORE SCRIPT LOGIC - REFACTORED FROM ORIGINAL
    <#
    Gets initial mailbox stats, grants necessary roles, restores recoverable items,
    starts Managed Folder Assistant, and gets final stats for comparison.

    EDIT THE VARIABLES in the section below before running.
    - Assumes you are already connected to Exchange Online PowerShell.
    - WARNING: Role assignments in M365 can take up to 60 minutes to propagate.
    #>

    $adminUserUPN = "admin@contoso.com"          # <-- Put the UPN of the admin account needing roles here
    $targetMailbox = "SharedMailbox"             # <-- Put the Identity (Email, Alias, Name) of the target mailbox here

    $discoveryGroup = "Discovery Management"
    $importExportRole = "Mailbox Import Export"

    $waitBeforeFinalStatsSeconds = 10

    $statsBefore = $null
    $initialItemCount = $null
    $initialTotalSize = $null
    $initialDeletedItemCount = $null
    $initialDeletedSize = $null

    $statsAfter = $null

    Write-Host "Starting script for Admin '$adminUserUPN' targeting Mailbox '$targetMailbox' at $(Get-Date)..." -ForegroundColor Cyan

    if (-not $adminUserUPN -like "*@*" -or $targetMailbox -eq "" ) {
         Write-Error "Please ensure valid values are set for `$adminUserUPN` and `$targetMailbox` in the script before running."

         return
    }

    try {

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 1/6: Gathering Initial Statistics..." -PercentComplete 0
        Write-Host "`n--- Stage 1: Gathering Initial Statistics for '$targetMailbox' ---"
        try {
            $statsBefore = Get-MailboxStatistics -Identity $targetMailbox -ErrorAction Stop
            $initialItemCount = $statsBefore.ItemCount
            $initialTotalSize = $statsBefore.TotalItemSize
            $initialDeletedItemCount = $statsBefore.DeletedItemCount # Items in Recoverable Items
            $initialDeletedSize = $statsBefore.TotalDeletedItemSize # Size of Recoverable Items

            Write-Host "Initial Primary Item Count : $initialItemCount"
            Write-Host "Initial Primary Total Size : $initialTotalSize"
            Write-Host "Initial Recoverable Items Count: $initialDeletedItemCount"
            Write-Host "Initial Recoverable Items Size : $initialDeletedSize"
            Write-Host "---------------------------------------------------------"
        } catch {
            Write-Error "Failed to gather initial statistics: $_"
            return
        }

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 2/6: Checking/Granting Roles..." -PercentComplete 16
        Write-Host "`n--- Stage 2: Checking/Granting required roles for '$adminUserUPN' ---"

        Write-Host "Checking membership in '$discoveryGroup' group..."
            $currentMembers = Get-RoleGroupMember -Identity $discoveryGroup -ErrorAction SilentlyContinue
            if ($null -eq $currentMembers -or $currentMembers.Name -notcontains $adminUserUPN) {
                Write-Host "User '$adminUserUPN' not found in '$discoveryGroup'. Adding..." -ForegroundColor Yellow
                Add-RoleGroupMember -Identity $discoveryGroup -Member $adminUserUPN -ErrorAction Stop
                Write-Host "Successfully added '$adminUserUPN' to '$discoveryGroup'." -ForegroundColor Green
            } else {
                Write-Host "User '$adminUserUPN' is already a member of '$discoveryGroup'."
            }

        Write-Host "Checking direct assignment of '$importExportRole' role..."
            $existingAssignment = Get-ManagementRoleAssignment -RoleAssignee $adminUserUPN -Role $importExportRole -ErrorAction SilentlyContinue
            if ($null -eq $existingAssignment) {
                Write-Host "Role '$importExportRole' not directly assigned to '$adminUserUPN'. Assigning..." -ForegroundColor Yellow
                New-ManagementRoleAssignment -User $adminUserUPN -Role $importExportRole -ErrorAction Stop
                Write-Host "Successfully assigned '$importExportRole' role directly to '$adminUserUPN'." -ForegroundColor Green
            } else {
                Write-Host "User '$adminUserUPN' already has the '$importExportRole' role assigned."
            }

        Write-Host "`n---------------------------------------------------------------------"
        Write-Host "IMPORTANT: Role assignments checked/initiated (if necessary)." -ForegroundColor Yellow
        Write-Host "These changes can take up to 60 MINUTES to fully propagate across Microsoft 365." -ForegroundColor Yellow
        Write-Host "The 'Restore-RecoverableItems' command (Stage 3) might FAIL if run immediately." -ForegroundColor Yellow
        Write-Host "Consider waiting or running the restore in a new PowerShell session later." -ForegroundColor Yellow
        Read-Host "Press Enter to attempt Stage 3 (Restore) anyway, or Ctrl+C to exit"
        Write-Host "---------------------------------------------------------------------`n"

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 3/6: Restoring Recoverable Items for '$targetMailbox'..." -PercentComplete 33
        Write-Host "`n--- Stage 3: Attempting to restore recoverable items for '$targetMailbox' ---"
        Write-Host "(This step might take a while. No percentage progress available.)"
        Restore-RecoverableItems -Identity $targetMailbox -ResultSize Unlimited -ErrorAction Stop
            Write-Host "Restore-RecoverableItems command submitted successfully for '$targetMailbox'." -ForegroundColor Green

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 4/6: Starting Managed Folder Assistant for '$targetMailbox'..." -PercentComplete 50
        Write-Host "`n--- Stage 4: Starting Managed Folder Assistant for '$targetMailbox' ---"
        Start-ManagedFolderAssistant -Identity $targetMailbox -ErrorAction Stop
            Write-Host "Managed Folder Assistant successfully queued for processing '$targetMailbox'." -ForegroundColor Green

         Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 5/6: Waiting briefly before final statistics check..." -PercentComplete 66
         Write-Host "`n--- Stage 5: Waiting $waitBeforeFinalStatsSeconds seconds before final stats check ---"
         Start-Sleep -Seconds $waitBeforeFinalStatsSeconds # Now uses the variable

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Stage 6/6: Gathering Final Statistics & Comparing..." -PercentComplete 83
        Write-Host "`n--- Stage 6: Gathering Final Statistics for '$targetMailbox' ---"
        Write-Host "(Note: Stats taken shortly after commands. Background processing like MFA may take longer to fully reflect.)" -ForegroundColor Yellow
        $statsAfter = Get-MailboxStatistics -Identity $targetMailbox -ErrorAction Stop

            Write-Host "Final Primary Item Count : $($statsAfter.ItemCount)"
            Write-Host "Final Primary Total Size : $($statsAfter.TotalItemSize)"
            Write-Host "Final Recoverable Items Count: $($statsAfter.DeletedItemCount)"
            Write-Host "Final Recoverable Items Size : $($statsAfter.TotalDeletedItemSize)"
            Write-Host "---------------------------------------------------------"

            if ($null -ne $statsBefore) {
                 Write-Host "`n--- Comparison (Final vs Initial) ---"

                 $itemCountChange = $statsAfter.ItemCount - $initialItemCount
                 $primarySizeChangeBytes = $statsAfter.TotalItemSize.ToBytes() - $statsBefore.TotalItemSize.ToBytes()
                 $deletedCountChange = $statsAfter.DeletedItemCount - $initialDeletedItemCount
                 $deletedSizeChangeBytes = $statsAfter.TotalDeletedItemSize.ToBytes() - $statsBefore.TotalDeletedItemSize.ToBytes()

                 $primarySizeChangeFormatted = [Microsoft.Exchange.Data.ByteQuantifiedSize]::FromBytes($primarySizeChangeBytes)
                 $deletedSizeChangeFormatted = [Microsoft.Exchange.Data.ByteQuantifiedSize]::FromBytes($deletedSizeChangeBytes)

                 Write-Host "Change in Primary Item Count : $itemCountChange"
                 Write-Host "Change in Primary Size       : $primarySizeChangeFormatted ($primarySizeChangeBytes bytes)"
                 Write-Host "Change in Recov. Items Count : $deletedCountChange"
                 Write-Host "Change in Recov. Items Size  : $deletedSizeChangeFormatted ($deletedSizeChangeBytes bytes)"
                 Write-Host "---------------------------------------------------------"
            } else {
                Write-Host "`nComparison skipped because initial statistics could not be gathered." -ForegroundColor Yellow
            }

        Write-Progress -Activity "Mailbox Recovery Script" -Status "Script Completed." -PercentComplete 100 -Completed
        Write-Host "`nScript execution finished at $(Get-Date)." -ForegroundColor Cyan

    } catch {
        Write-Error "A critical error occurred during script execution: $_"
        Write-Progress -Activity "Mailbox Recovery Script" -Status "Failed." -PercentComplete 100 -Completed
    }

    Write-Host "$ScriptBaseName completed successfully" -ForegroundColor Green

} catch {
    Write-Error "$ScriptBaseName failed: $_"
    exit 1
} finally {
    Stop-Transcript
}

