<#
.SYNOPSIS
    Windows Hello for Business verification script - confirms PIN setup is available.

.DESCRIPTION
    RMM-safe verification to confirm WHfB is ready for PIN setup after remediation.
    Runs as SYSTEM context. Quick pass/fail check for support validation.

.NOTES
    Context: RMM, SYSTEM remote session
    PowerShell: 5.1+
    Exit Codes: 0 = ready for PIN setup, 1 = not ready

.EXAMPLE
    # Run via RMM or SYSTEM remote session to verify WHfB readiness
    .\WHfB-Verification.ps1

.OUTPUTS
    Pass/fail status for each prerequisite check
#>

$ErrorActionPreference = 'Continue'
$AllPassed = $true
$Checks = @()

Write-Output "=========================================="
Write-Output "Windows Hello for Business Verification"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "=========================================="

#region Check 1: Device Trust
Write-Output "`n[CHECK 1] Device Trust Status"
try {
    $dsregOutput = dsregcmd /status 2>&1
    $dsregText = $dsregOutput -join "`n"

    $azureAdJoined = if ($dsregText -match 'AzureAdJoined\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    $keySignTest = if ($dsregText -match 'KeySignTest\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }

    if ($azureAdJoined -eq 'YES' -and $keySignTest -eq 'PASSED') {
        Write-Output "  [PASS] AzureAdJoined: YES, KeySignTest: PASSED"
        $Checks += @{ Name = "Device Trust"; Status = "PASS" }
    }
    else {
        Write-Output "  [FAIL] AzureAdJoined: $azureAdJoined, KeySignTest: $keySignTest"
        $Checks += @{ Name = "Device Trust"; Status = "FAIL" }
        $AllPassed = $false
    }
}
catch {
    Write-Output "  [FAIL] Error: $_"
    $Checks += @{ Name = "Device Trust"; Status = "ERROR" }
    $AllPassed = $false
}
#endregion

#region Check 2: NGC Prerequisites
Write-Output "`n[CHECK 2] NGC Prerequisites"
try {
    $dsregVerbose = dsregcmd /status /verbose 2>&1
    $verboseText = $dsregVerbose -join "`n"

    $preReqResult = if ($verboseText -match 'PreReqResult\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }
    $policyEnabled = if ($verboseText -match 'PolicyEnabled\s*:\s*(\w+)') { $Matches[1] } else { 'Unknown' }

    if ($preReqResult -eq 'WillProvision') {
        Write-Output "  [PASS] PreReqResult: WillProvision"
        $Checks += @{ Name = "NGC PreReq"; Status = "PASS" }
    }
    else {
        Write-Output "  [FAIL] PreReqResult: $preReqResult (expected: WillProvision)"
        Write-Output "         PolicyEnabled: $policyEnabled"
        $Checks += @{ Name = "NGC PreReq"; Status = "FAIL" }
        $AllPassed = $false
    }
}
catch {
    Write-Output "  [FAIL] Error: $_"
    $Checks += @{ Name = "NGC PreReq"; Status = "ERROR" }
    $AllPassed = $false
}
#endregion

#region Check 3: TPM Ready
Write-Output "`n[CHECK 3] TPM Status"
try {
    $tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction Stop

    if ($tpm -and $tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue) {
        Write-Output "  [PASS] TPM present, activated, and enabled"
        $Checks += @{ Name = "TPM Ready"; Status = "PASS" }
    }
    else {
        Write-Output "  [FAIL] TPM not ready"
        $Checks += @{ Name = "TPM Ready"; Status = "FAIL" }
        $AllPassed = $false
    }
}
catch {
    Write-Output "  [FAIL] Error: $_"
    $Checks += @{ Name = "TPM Ready"; Status = "ERROR" }
    $AllPassed = $false
}
#endregion

#region Check 4: WHfB Not Disabled
Write-Output "`n[CHECK 4] WHfB Policy Not Disabled"
try {
    $passportPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"

    if (Test-Path $passportPath) {
        $passportPolicies = Get-ItemProperty -Path $passportPath -ErrorAction SilentlyContinue

        if ($null -eq $passportPolicies.UsePassportForWork -or $passportPolicies.UsePassportForWork -ne 0) {
            Write-Output "  [PASS] WHfB not disabled by policy"
            $Checks += @{ Name = "WHfB Policy"; Status = "PASS" }
        }
        else {
            Write-Output "  [FAIL] WHfB disabled by policy (UsePassportForWork = 0)"
            $Checks += @{ Name = "WHfB Policy"; Status = "FAIL" }
            $AllPassed = $false
        }
    }
    else {
        Write-Output "  [PASS] No explicit WHfB policy (using defaults)"
        $Checks += @{ Name = "WHfB Policy"; Status = "PASS" }
    }
}
catch {
    Write-Output "  [WARN] Could not check policy: $_"
    $Checks += @{ Name = "WHfB Policy"; Status = "WARN" }
}
#endregion

#region Check 5: PIN Reset Capability
Write-Output "`n[CHECK 5] PIN Reset Capability"
try {
    $dsregOutput = dsregcmd /status 2>&1
    $dsregText = $dsregOutput -join "`n"

    $canReset = if ($dsregText -match 'CanReset\s*:\s*(.+)') { $Matches[1].Trim() } else { 'Unknown' }

    if ($canReset -match 'Destructive' -or $canReset -match 'NonDestructive') {
        Write-Output "  [PASS] CanReset: $canReset"
        $Checks += @{ Name = "PIN Reset"; Status = "PASS" }
    }
    else {
        Write-Output "  [INFO] CanReset: $canReset (may need initial PIN setup first)"
        $Checks += @{ Name = "PIN Reset"; Status = "INFO" }
    }
}
catch {
    Write-Output "  [INFO] Could not check PIN reset capability"
    $Checks += @{ Name = "PIN Reset"; Status = "INFO" }
}
#endregion

#region Check 6: Recent Remediation
Write-Output "`n[CHECK 6] Remediation Status"
try {
    $flagFiles = Get-ChildItem -Path "$env:ProgramData" -Filter "WHfB-Remediation-*.txt" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1

    if ($flagFiles) {
        $flagContent = Get-Content -Path $flagFiles.FullName -Raw
        Write-Output "  [INFO] Remediation was run: $($flagFiles.Name)"
        $Checks += @{ Name = "Remediation"; Status = "RUN" }
    }
    else {
        Write-Output "  [INFO] No remediation flag found (may not be needed)"
        $Checks += @{ Name = "Remediation"; Status = "N/A" }
    }
}
catch {
    Write-Output "  [INFO] Could not check remediation status"
}
#endregion

#region Summary
Write-Output "`n=========================================="
Write-Output "VERIFICATION SUMMARY"
Write-Output "=========================================="

$passCount = ($Checks | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = ($Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
$totalChecks = $Checks.Count

Write-Output "Results: $passCount/$totalChecks checks passed"
Write-Output ""

foreach ($check in $Checks) {
    $icon = switch ($check.Status) {
        'PASS' { '[+]' }
        'FAIL' { '[-]' }
        'WARN' { '[!]' }
        'INFO' { '[i]' }
        'ERROR' { '[X]' }
        default { '[?]' }
    }
    Write-Output "  $icon $($check.Name): $($check.Status)"
}

Write-Output ""

if ($AllPassed) {
    Write-Output "STATUS: READY FOR PIN SETUP"
    Write-Output ""
    Write-Output "User instructions:"
    Write-Output "  1. Open Settings (Win + I)"
    Write-Output "  2. Go to Accounts > Sign-in options"
    Write-Output "  3. Click 'Windows Hello PIN' or 'PIN (Windows Hello)'"
    Write-Output "  4. Click 'Set up' and follow prompts"
    Write-Output ""
    Write-Output "If PIN setup still shows 'contact your administrator':"
    Write-Output "  - Wait 15 minutes for policy sync"
    Write-Output "  - Or run: Settings > Accounts > Access work or school > [account] > Info > Sync"
    exit 0
}
else {
    Write-Output "STATUS: NOT READY - ISSUES DETECTED"
    Write-Output ""
    Write-Output "Recommended actions:"

    foreach ($check in ($Checks | Where-Object { $_.Status -eq 'FAIL' })) {
        switch ($check.Name) {
            'Device Trust' { Write-Output "  - Run 'dsregcmd /forcerecovery' to restore device trust" }
            'NGC PreReq' { Write-Output "  - Run WHfB-Remediation.ps1 and reboot" }
            'TPM Ready' { Write-Output "  - Check TPM in tpm.msc, may need BIOS configuration" }
            'WHfB Policy' { Write-Output "  - Check Intune/GPO - WHfB is disabled by policy" }
        }
    }
    exit 1
}
#endregion
