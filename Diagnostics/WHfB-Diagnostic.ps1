<#
.SYNOPSIS
    Windows Hello for Business diagnostic script - checks NGC prerequisites, TPM health, and policy status.

.DESCRIPTION
    RMM-safe diagnostic for "contact your administrator" PIN errors after TPM/motherboard replacement.
    Runs as SYSTEM context. Outputs structured diagnostic data for analysis.

.NOTES
    Context: RMM, SYSTEM remote session
    PowerShell: 5.1+
    Exit Codes: 0 = ready, 1 = critical issue, 112 = partial/warning

.EXAMPLE
    # Run via RMM or SYSTEM remote session
    .\WHfB-Diagnostic.ps1

.OUTPUTS
    Structured text output with device trust, TPM, NGC, and policy status
#>

$ErrorActionPreference = 'Continue'
$ExitCode = 0
$Results = @{}

Write-Output "=========================================="
Write-Output "Windows Hello for Business Diagnostic"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "=========================================="

#region Device Join Status
Write-Output "`n--- DEVICE JOIN STATUS ---"
try {
    $dsregOutput = dsregcmd /status 2>&1
    $dsregText = $dsregOutput -join "`n"

    # Parse key values
    $azureAdJoined = if ($dsregText -match 'AzureAdJoined\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    $domainJoined = if ($dsregText -match 'DomainJoined\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    $keySignTest = if ($dsregText -match 'KeySignTest\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    $deviceAuthStatus = if ($dsregText -match 'DeviceAuthStatus\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }

    Write-Output "AzureAdJoined: $azureAdJoined"
    Write-Output "DomainJoined: $domainJoined"
    Write-Output "KeySignTest: $keySignTest"
    Write-Output "DeviceAuthStatus: $deviceAuthStatus"

    $Results['AzureAdJoined'] = $azureAdJoined
    $Results['KeySignTest'] = $keySignTest

    if ($azureAdJoined -ne 'YES') {
        Write-Output "[WARNING] Device not Azure AD joined - WHfB requires AAD join"
        $ExitCode = 112
    }
    if ($keySignTest -ne 'PASSED') {
        Write-Output "[WARNING] KeySignTest not passed - device trust may be broken"
        $ExitCode = 112
    }
}
catch {
    Write-Output "[ERROR] Failed to get dsregcmd status: $_"
    $ExitCode = 1
}
#endregion

#region NGC Prerequisites (Verbose)
Write-Output "`n--- NGC PREREQUISITE CHECK ---"
try {
    $dsregVerbose = dsregcmd /status /verbose 2>&1
    $verboseText = $dsregVerbose -join "`n"

    # Find NGC Prerequisite Check section
    $ngcSection = $false
    $ngcResults = @()

    foreach ($line in $dsregVerbose) {
        if ($line -match 'Ngc Prerequisite Check') {
            $ngcSection = $true
            continue
        }
        if ($ngcSection -and $line -match '^\s*$') {
            break
        }
        if ($ngcSection -and $line -match ':\s*(YES|NO|WillProvision|WillNotProvision)') {
            $ngcResults += $line.Trim()
            Write-Output $line.Trim()
        }
    }

    # Check critical values
    if ($verboseText -match 'PreReqResult\s*:\s*(\w+)') {
        $preReqResult = $Matches[1]
        Write-Output "`nPreReqResult: $preReqResult"
        $Results['PreReqResult'] = $preReqResult

        if ($preReqResult -ne 'WillProvision') {
            Write-Output "[CRITICAL] PreReqResult is NOT 'WillProvision' - PIN setup will fail"
            $ExitCode = 1
        }
    }

    if ($verboseText -match 'PolicyEnabled\s*:\s*(\w+)') {
        $policyEnabled = $Matches[1]
        Write-Output "PolicyEnabled: $policyEnabled"
        $Results['PolicyEnabled'] = $policyEnabled

        if ($policyEnabled -ne 'YES') {
            Write-Output "[CRITICAL] WHfB policy not enabled on device"
            $ExitCode = 1
        }
    }
}
catch {
    Write-Output "[ERROR] Failed to get NGC prerequisites: $_"
    $ExitCode = 1
}
#endregion

#region TPM Status
Write-Output "`n--- TPM STATUS ---"
try {
    $tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction Stop

    if ($tpm) {
        Write-Output "TPM Present: YES"
        Write-Output "TPM Activated: $($tpm.IsActivated_InitialValue)"
        Write-Output "TPM Enabled: $($tpm.IsEnabled_InitialValue)"
        Write-Output "TPM Owned: $($tpm.IsOwned_InitialValue)"
        Write-Output "TPM Version: $($tpm.SpecVersion)"

        $Results['TPMPresent'] = $true
        $Results['TPMReady'] = $tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue

        if (-not ($tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue)) {
            Write-Output "[WARNING] TPM not fully ready"
            $ExitCode = 112
        }
    }
    else {
        Write-Output "TPM Present: NO"
        Write-Output "[CRITICAL] No TPM found - WHfB requires TPM"
        $Results['TPMPresent'] = $false
        $ExitCode = 1
    }
}
catch {
    Write-Output "[ERROR] Failed to query TPM: $_"
    $ExitCode = 1
}
#endregion

#region Registry Policy Check
Write-Output "`n--- WHfB REGISTRY POLICIES ---"
try {
    $passportPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    $pinComplexityPath = "$passportPath\PINComplexity"

    if (Test-Path $passportPath) {
        $passportPolicies = Get-ItemProperty -Path $passportPath -ErrorAction SilentlyContinue
        Write-Output "PassportForWork policy exists: YES"

        if ($null -ne $passportPolicies.UsePassportForWork) {
            Write-Output "UsePassportForWork: $($passportPolicies.UsePassportForWork)"
            $Results['UsePassportForWork'] = $passportPolicies.UsePassportForWork

            if ($passportPolicies.UsePassportForWork -eq 0) {
                Write-Output "[CRITICAL] Windows Hello for Business is DISABLED by policy"
                $ExitCode = 1
            }
        }
        else {
            Write-Output "UsePassportForWork: Not configured"
        }

        if ($null -ne $passportPolicies.UseTPM) {
            Write-Output "UseTPM: $($passportPolicies.UseTPM)"
        }
    }
    else {
        Write-Output "PassportForWork policy exists: NO"
        Write-Output "[INFO] No WHfB policy applied via GPO/Intune - using defaults"
    }

    if (Test-Path $pinComplexityPath) {
        $pinPolicies = Get-ItemProperty -Path $pinComplexityPath -ErrorAction SilentlyContinue
        Write-Output "`nPIN Complexity Settings:"
        Write-Output "  MinimumPINLength: $($pinPolicies.MinimumPINLength)"
        Write-Output "  MaximumPINLength: $($pinPolicies.MaximumPINLength)"

        # Check for impossible settings
        if ($pinPolicies.MinimumPINLength -gt $pinPolicies.MaximumPINLength) {
            Write-Output "[CRITICAL] Impossible PIN policy: Min ($($pinPolicies.MinimumPINLength)) > Max ($($pinPolicies.MaximumPINLength))"
            $ExitCode = 1
        }
    }
}
catch {
    Write-Output "[ERROR] Failed to check registry policies: $_"
}
#endregion

#region NGC Container Check
Write-Output "`n--- NGC CONTAINER STATUS ---"
try {
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"

    if (Test-Path $ngcPath) {
        $ngcItems = Get-ChildItem -Path $ngcPath -Recurse -ErrorAction SilentlyContinue
        $ngcCount = ($ngcItems | Measure-Object).Count
        Write-Output "NGC folder exists: YES"
        Write-Output "NGC items count: $ngcCount"

        if ($ngcCount -gt 0) {
            Write-Output "[INFO] NGC container has data - may need clearing if stale"
            $Results['NGCHasData'] = $true
        }
        else {
            Write-Output "[INFO] NGC container empty - ready for new provisioning"
            $Results['NGCHasData'] = $false
        }
    }
    else {
        Write-Output "NGC folder exists: NO"
        Write-Output "[INFO] NGC folder does not exist - will be created on PIN setup"
        $Results['NGCHasData'] = $false
    }
}
catch {
    Write-Output "[WARNING] Cannot access NGC folder (permission issue expected): $_"
}
#endregion

#region Event Log Check
Write-Output "`n--- RECENT WHfB EVENTS ---"
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" -MaxEvents 10 -ErrorAction SilentlyContinue

    if ($events) {
        Write-Output "Recent User Device Registration events:"
        foreach ($event in $events) {
            $msg = $event.Message -replace "`r`n", " " -replace "`n", " "
            if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) + "..." }
            Write-Output "  [$($event.TimeCreated)] ID:$($event.Id) - $msg"
        }
    }
    else {
        Write-Output "[INFO] No recent User Device Registration events found"
    }
}
catch {
    Write-Output "[INFO] Could not retrieve WHfB events: $_"
}
#endregion

#region Summary
Write-Output "`n=========================================="
Write-Output "DIAGNOSTIC SUMMARY"
Write-Output "=========================================="

$issues = @()
if ($Results['AzureAdJoined'] -ne 'YES') { $issues += "Device not Azure AD joined" }
if ($Results['KeySignTest'] -ne 'PASSED') { $issues += "KeySignTest failed" }
if ($Results['PreReqResult'] -ne 'WillProvision') { $issues += "NGC PreReqResult not WillProvision" }
if ($Results['PolicyEnabled'] -ne 'YES') { $issues += "WHfB policy not enabled" }
if ($Results['UsePassportForWork'] -eq 0) { $issues += "WHfB disabled by policy" }
if ($Results['TPMPresent'] -eq $false) { $issues += "No TPM detected" }

if ($issues.Count -eq 0) {
    Write-Output "STATUS: ALL CHECKS PASSED"
    Write-Output "WHfB should be ready for PIN setup."
}
else {
    Write-Output "STATUS: ISSUES DETECTED"
    Write-Output "Issues found:"
    foreach ($issue in $issues) {
        Write-Output "  - $issue"
    }
    Write-Output "`nRecommendation: Run WHfB-Remediation.ps1"
}

Write-Output "`nExit Code: $ExitCode"
#endregion

exit $ExitCode
