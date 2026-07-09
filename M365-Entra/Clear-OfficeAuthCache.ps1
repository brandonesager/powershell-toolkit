# Clear-OfficeAuthCache.ps1
# Purpose: Full Office authentication cache reset for persistent sign-in prompts,
#          account picker loops, and activation failures
# Clears WAM broker tokens, Office licensing cache, OneAuth, IdentityCache,
# Credential Manager entries, and HKCU Identity registry key
#
# Run in user context (SYSTEM remote session while user is logged in, or as the affected user)
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#
# After running: user will be prompted to sign in fresh on next Office launch (expected)

$ErrorActionPreference = 'SilentlyContinue'

Write-Host 'Clearing Office authentication caches...' -ForegroundColor Cyan

# 1. WAM token broker caches (all user profiles — safe to run as SYSTEM)
$wamPaths = @(
    'AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts',
    'AppData\Local\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\AC\TokenBroker\Accounts'
)
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    foreach ($rel in $wamPaths) {
        $p = Join-Path $_.FullName $rel
        if (Test-Path $p) {
            Remove-Item "$p\*" -Force -Recurse
        }
    }
}
Write-Host '  [1] WAM token broker caches cleared'

# 2. Office licensing cache (all user profiles — safe to run as SYSTEM)
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    $p = Join-Path $_.FullName 'AppData\Local\Microsoft\Office\Licensing'
    if (Test-Path $p) { Remove-Item "$p\*" -Force -Recurse }
}
Write-Host '  [2] Office licensing cache cleared'

# 3. OneAuth cache (user context required — run as affected user or in their session)
$oneAuth = Join-Path $env:LOCALAPPDATA 'Microsoft\OneAuth'
if (Test-Path $oneAuth) {
    Remove-Item $oneAuth -Force -Recurse
    Write-Host '  [3] OneAuth cache cleared'
} else {
    Write-Host '  [3] OneAuth cache not found (may need to run as affected user)'
}

# 4. IdentityCache (user context required)
$idCache = Join-Path $env:LOCALAPPDATA 'Microsoft\IdentityCache'
if (Test-Path $idCache) {
    Remove-Item $idCache -Force -Recurse
    Write-Host '  [4] IdentityCache cleared'
} else {
    Write-Host '  [4] IdentityCache not found'
}

# 5. HKCU Identity registry key (user context required)
$regKey = 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity'
if (Test-Path $regKey) {
    Remove-Item $regKey -Force -Recurse
    Write-Host '  [5] Office Identity registry key removed'
} else {
    Write-Host '  [5] Office Identity registry key not found'
}

# 6. Credential Manager — Office/Microsoft entries (user context required)
$credTargets = cmdkey /list 2>$null |
    Where-Object { $_ -match 'MicrosoftOffice|MicrosoftAccount|Office16|Office15' } |
    ForEach-Object { ($_ -split 'Target: ')[1].Trim() }

foreach ($target in $credTargets) {
    if ($target) {
        cmdkey /delete:$target 2>$null | Out-Null
        Write-Host "  [6] Removed credential: $target"
    }
}
if (-not $credTargets) { Write-Host '  [6] No Office/Microsoft credentials found in Credential Manager' }

Write-Host ''
Write-Host 'Cache reset complete.' -ForegroundColor Green
Write-Host 'User should sign into Office fresh. They will see one sign-in prompt — this is expected.'
