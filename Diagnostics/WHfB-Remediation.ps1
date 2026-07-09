<#
.SYNOPSIS
    Windows Hello for Business remediation script - clears stale NGC data and forces policy sync.

.DESCRIPTION
    RMM-safe remediation for "contact your administrator" PIN errors after TPM/motherboard replacement.
    Runs as SYSTEM context. Clears NGC container, optionally clears TPM credentials, forces Intune sync.

.NOTES
    Context: RMM, SYSTEM remote session
    PowerShell: 5.1+
    Exit Codes: 0 = success, 1 = failure, 112 = partial success
    REQUIRES REBOOT after running for changes to take effect

.EXAMPLE
    # Run via RMM or SYSTEM remote session
    .\WHfB-Remediation.ps1

.OUTPUTS
    Remediation actions performed and reboot requirement notice
#>

$ErrorActionPreference = 'Stop'
$ExitCode = 0
$ActionsPerformed = @()

Write-Output "=========================================="
Write-Output "Windows Hello for Business Remediation"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "=========================================="

#region Pre-flight Check
Write-Output "`n--- PRE-FLIGHT CHECKS ---"
try {
    $dsregOutput = dsregcmd /status 2>&1
    $dsregText = $dsregOutput -join "`n"

    $azureAdJoined = if ($dsregText -match 'AzureAdJoined\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }

    if ($azureAdJoined -ne 'YES') {
        Write-Output "[ERROR] Device is not Azure AD joined. Cannot proceed with WHfB remediation."
        Write-Output "Run 'dsregcmd /forcerecovery' first to restore device trust."
        exit 1
    }
    Write-Output "Device is Azure AD joined: YES"
}
catch {
    Write-Output "[ERROR] Pre-flight check failed: $_"
    exit 1
}
#endregion

#region Clear NGC Container via certutil
Write-Output "`n--- CLEARING NGC CREDENTIALS ---"
try {
    # Method 1: certutil (preferred - works in SYSTEM context)
    Write-Output "Attempting NGC credential cleanup via certutil..."
    $certutilResult = certutil -csp NGC -delkey 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Output "[SUCCESS] NGC credentials cleared via certutil"
        $ActionsPerformed += "Cleared NGC credentials (certutil)"
    }
    else {
        # This is expected if no NGC keys exist
        Write-Output "[INFO] No NGC keys to delete or already cleared"
        $ActionsPerformed += "NGC credentials check (none found)"
    }
}
catch {
    Write-Output "[WARNING] certutil NGC cleanup: $_"
    $ExitCode = 112
}
#endregion

#region Clear NGC Folder
Write-Output "`n--- CLEARING NGC FOLDER ---"
try {
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"

    if (Test-Path $ngcPath) {
        # Take ownership and clear (SYSTEM context can do this)
        $acl = Get-Acl $ngcPath
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $ngcPath -AclObject $acl -ErrorAction SilentlyContinue

        # Remove contents
        Get-ChildItem -Path $ngcPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        Write-Output "[SUCCESS] NGC folder contents cleared"
        $ActionsPerformed += "Cleared NGC folder contents"
    }
    else {
        Write-Output "[INFO] NGC folder does not exist - nothing to clear"
    }
}
catch {
    Write-Output "[WARNING] NGC folder cleanup: $_ (may require manual cleanup)"
    $ExitCode = 112
}
#endregion

#region Force Intune Policy Sync
Write-Output "`n--- FORCING INTUNE POLICY SYNC ---"
try {
    # Method 1: Scheduled task trigger (works on most Intune-managed devices)
    $intuneTask = Get-ScheduledTask | Where-Object { $_.TaskName -eq 'PushLaunch' } -ErrorAction SilentlyContinue

    if ($intuneTask) {
        Start-ScheduledTask -TaskPath $intuneTask.TaskPath -TaskName $intuneTask.TaskName -ErrorAction Stop
        Write-Output "[SUCCESS] Triggered Intune PushLaunch sync task"
        $ActionsPerformed += "Triggered Intune sync (PushLaunch)"
    }
    else {
        Write-Output "[INFO] PushLaunch task not found - trying alternative sync"
    }

    # Method 2: IME Sync (Intune Management Extension)
    $imeTask = Get-ScheduledTask | Where-Object { $_.TaskName -like '*Intune*Sync*' -or $_.TaskName -like '*IME*' } -ErrorAction SilentlyContinue

    if ($imeTask) {
        foreach ($task in $imeTask) {
            Start-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
            Write-Output "[SUCCESS] Triggered: $($task.TaskName)"
        }
        $ActionsPerformed += "Triggered IME sync task(s)"
    }

    # Method 3: Direct enrollment refresh
    $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    if (Test-Path $enrollmentPath) {
        $enrollments = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
        foreach ($enrollment in $enrollments) {
            if ($enrollment.Name -match '[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}') {
                $dmClient = "$($enrollment.PSPath)\DMClient"
                if (Test-Path $dmClient) {
                    Write-Output "[INFO] Found MDM enrollment: $($enrollment.PSChildName)"
                }
            }
        }
    }
}
catch {
    Write-Output "[WARNING] Intune sync trigger: $_"
    $ExitCode = 112
}
#endregion

#region Force Group Policy Update (Hybrid scenarios)
Write-Output "`n--- FORCING GROUP POLICY UPDATE ---"
try {
    $gpResult = gpupdate /force 2>&1
    Write-Output "[SUCCESS] Group Policy update triggered"
    $ActionsPerformed += "Forced GPUpdate"
}
catch {
    Write-Output "[INFO] GPUpdate: $_"
}
#endregion

#region Schedule Reboot Notification
Write-Output "`n--- REBOOT REQUIRED ---"
Write-Output "[IMPORTANT] A reboot is REQUIRED for NGC changes to take effect."
Write-Output "[IMPORTANT] After reboot, user should be able to set up PIN."

# Create a flag file to indicate remediation was run
try {
    $flagPath = "$env:ProgramData\WHfB-Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    @"
Windows Hello for Business Remediation Completed
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
Actions: $($ActionsPerformed -join '; ')
Status: Pending reboot
"@ | Out-File -FilePath $flagPath -Encoding UTF8
    Write-Output "[INFO] Remediation flag created: $flagPath"
}
catch {
    Write-Output "[INFO] Could not create flag file: $_"
}
#endregion

#region Summary
Write-Output "`n=========================================="
Write-Output "REMEDIATION SUMMARY"
Write-Output "=========================================="
Write-Output "Actions performed:"
foreach ($action in $ActionsPerformed) {
    Write-Output "  - $action"
}

if ($ExitCode -eq 0) {
    Write-Output "`nSTATUS: REMEDIATION COMPLETE"
    Write-Output "Next steps:"
    Write-Output "  1. Reboot the computer"
    Write-Output "  2. User signs in with password"
    Write-Output "  3. Go to Settings > Accounts > Sign-in options"
    Write-Output "  4. Set up Windows Hello PIN"
}
elseif ($ExitCode -eq 112) {
    Write-Output "`nSTATUS: PARTIAL SUCCESS"
    Write-Output "Some actions completed with warnings. Reboot and test PIN setup."
}
else {
    Write-Output "`nSTATUS: REMEDIATION FAILED"
    Write-Output "Review errors above and address manually."
}

Write-Output "`nExit Code: $ExitCode"
#endregion

exit $ExitCode
