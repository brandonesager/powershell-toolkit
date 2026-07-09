<#
.SYNOPSIS
    Test-ClientDeviceCompliance — Read-only audit of Contoso device join, MDM, Egnyte, Edge, apps, and compliance

.DESCRIPTION
    Comprehensive read-only audit for Contoso workstations. Checks device join and MDM status
    (dsregcmd, enrollment URLs, IME), Egnyte trusted site zone mappings, optional Entra group
    membership via Graph, Edge policies, .NET versions, power settings, deployed applications
    inventory (M365, Adobe, SentinelOne, Panini, Yardi, Zoom), and desktop file presence.
    Makes no changes. Designed for SYSTEM context via RMM.

.NOTES
    Category: Environment-Specific
.KEYWORDS
    Contoso, audit, compliance, device, Intune, Egnyte, RMM, SYSTEM, diagnose
#>

# --- Safety ---
$ErrorActionPreference = 'Stop'
if (-not ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -ge 1)) {
  Write-Host "FAIL: Requires Windows PowerShell 5.1. Detected $($PSVersionTable.PSVersion)"
  exit 1
}
Write-Host "OK: PowerShell 5.1 detected ($($PSVersionTable.PSVersion))"
Write-Host "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name) (SYSTEM expected)"

function Get-RegistryValue {
  param([string]$Path,[string]$Name)
  try {
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    $item.$Name
  } catch { $null }
}

function Test-RegKeyExists { param([string]$Path) try { [void](Get-Item -LiteralPath $Path -ErrorAction Stop); $true } catch { $false } }

function Write-YesNo { param([string]$label,[bool]$cond,[string]$detail = $null)
  $status = if ($cond) { "YES" } else { "NO" }
  if ($detail) { Write-Host "$label: $status ($detail)" } else { Write-Host "$label: $status" }
}

Write-Host "`n=== 1) Device Join & MDM ==="
# 1a) dsregcmd /status
try {
  $ds = & dsregcmd /status 2>&1
  Write-Host "[dsregcmd /status]"
  $ds | ForEach-Object { Write-Host $_ }
} catch {
  Write-Host "WARN: dsregcmd not available: $($_.Exception.Message)"
}

# 1b) Discovery URL configured?
$expectedDiscoveryUrl = 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'
$enrollBase = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$foundUrls = @()
if (Test-RegKeyExists $enrollBase) {
  Get-ChildItem -LiteralPath $enrollBase | ForEach-Object {
    $u1 = Get-RegistryValue -Path $_.PsPath -Name 'DiscoveryServiceFullURL'
    $u2 = Get-RegistryValue -Path $_.PsPath -Name 'EnrollmentServerUrl'
    $u3 = Get-RegistryValue -Path $_.PsPath -Name 'AuthPolicy' # presence hint
    if ($u1) { $foundUrls += $u1 }
    if ($u2) { $foundUrls += $u2 }
  }
}
$foundUrls = $foundUrls | Sort-Object -Unique
if ($foundUrls.Count -gt 0) {
  Write-Host "MDM discovery/enrollment URLs found:"
  $foundUrls | ForEach-Object { Write-Host " - $_" }
  Write-YesNo "Expected discovery URL present" ($foundUrls -contains $expectedDiscoveryUrl)
} else {
  Write-Host "MDM discovery/enrollment URLs found: NONE"
}

# 1c) Intune Management Extension present and running?
$svc = Get-Service -ErrorAction SilentlyContinue 'IntuneManagementExtension'
if ($svc) {
  Write-Host "IME Service: $($svc.Status)"
} else {
  Write-Host "IME Service: NOT FOUND"
}
$imeLogDir = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
Write-YesNo "IME log directory exists" (Test-Path $imeLogDir)

Write-Host "`n=== 2) Egnyte Trusted Locations (Trusted Sites zone) ==="
# Check Trusted Sites zone mappings under policy and user hives. Read-only.
$pathsToCheck = @(
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains',
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'
)
$targets = @(
 @{Display='https://*.egnyte.com'; DomainKey='egnyte.com'; Protocol='https'; Zone=2}, # 2 = Trusted Sites
 @{Display='file://egnytedrive';  DomainKey='egnytedrive'; Protocol='file';  Zone=2}
)

foreach ($p in $pathsToCheck) {
  Write-Host "Checking: $p"
  if (Test-RegKeyExists $p) {
    foreach ($t in $targets) {
      $present = $false
      # wildcard subdomains typically stored as subkey '*.egnyte.com' or direct protocol value at egnyte.com
      $key1 = Join-Path $p $($t.DomainKey)
      $key2 = Join-Path $p ("*." + $t.DomainKey)
      $val1 = if (Test-RegKeyExists $key1) { Get-RegistryValue -Path $key1 -Name $t.Protocol } else { $null }
      $val2 = if (Test-RegKeyExists $key2) { Get-RegistryValue -Path $key2 -Name $t.Protocol } else { $null }
      if ($val1 -eq $t.Zone -or $val2 -eq $t.Zone) { $present = $true }
      Write-YesNo (" - {0} mapped to Trusted Sites" -f $t.Display) $present ("val=$($val1,$val2 -join ',')")
    }
  } else { Write-Host " - path not found" }
}

# "Require server verification (https:) for all sites in this zone)" checkbox state (Trusted Sites = zone 2)
# Checkbox unchecked => allow http in Trusted Sites. This is controlled by Flags bitmask in HKCU Zones\2.
# We can only check HKCU of the running account (SYSTEM). Report best-effort and policy override if present.
$zone2FlagsHKCU = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
$flags = Get-RegistryValue -Path $zone2FlagsHKCU -Name 'Flags'
if ($null -ne $flags) {
  # Bit 0x200 (512) enforces HTTPS requirement when set. Unchecked means bit is 0.
  $httpsRequired = [bool]($flags -band 0x200)
  Write-Host ("Trusted Sites HTTPS required (HKCU): " + ($(if ($httpsRequired) { "ENFORCED" } else { "NOT ENFORCED" })))
} else {
  Write-Host "Trusted Sites Flags (HKCU): not set for this account"
}
# Policy-based site-to-zone assignment can override per-user flags; we reported policy mappings above.

Write-Host "`n=== 3) Entra group membership: 'Intune MDM Devices' (optional read) ==="
# Optional read-only check with Graph if ENV vars exist. No writes.
$tenantId = $env:GRAPH_TENANT_ID
$clientId = $env:GRAPH_CLIENT_ID
$clientSecret = $env:GRAPH_CLIENT_SECRET
$groupName = $env:INTUNE_GROUP_NAME; if ([string]::IsNullOrWhiteSpace($groupName)) { $groupName = 'Intune MDM Devices' }
if ($tenantId -and $clientId -and $clientSecret) {
  try {
    Add-Type -AssemblyName System.Web
    $body = "grant_type=client_credentials&client_id=$clientId&client_secret=$([System.Web.HttpUtility]::UrlEncode($clientSecret))&scope=https://graph.microsoft.com/.default"
    $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
    $hdr = @{ Authorization = "Bearer $($tok.access_token)" }
    # Get device by deviceId (AAD DeviceId is in dsregcmd output; also in registry)
    $deviceReg = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot' -Name 'AzureActiveDirectoryDeviceId'
    if (-not $deviceReg) {
      $deviceReg = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -Name 'DeviceIdentifier' # may be null
    }
    Write-Host "Device AAD Id: $deviceReg"
    $grp = Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$([System.Uri]::EscapeDataString($groupName))'"
    if ($grp.value.Count -lt 1) { Write-Host "Group '$groupName' not found"; }
    else {
      $gid = $grp.value[0].id
      $isMember = $false
      if ($deviceReg) {
        $chk = Invoke-RestMethod -Headers $hdr -Method Post -Uri "https://graph.microsoft.com/v1.0/groups/$gid/checkMemberObjects" -Body (@{ ids = @($deviceReg) } | ConvertTo-Json) -ContentType 'application/json'
        $isMember = ($chk.value -contains $deviceReg)
      }
      Write-YesNo "Device is member of '$groupName'" $isMember
    }
  } catch {
    Write-Host "WARN: Graph check failed: $($_.Exception.Message)"
  }
} else {
  Write-Host "Skipped. Set GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET to enable read-only membership check."
}

Write-Host "`n=== 4) Microsoft Edge policies ==="
$edgePol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$restore = Get-RegistryValue -Path $edgePol -Name 'RestoreOnStartup'       # 4 = SpecificPages
$urls    = Get-RegistryValue -Path "$edgePol\RestoreOnStartupURLs" -Name '1'
$signin  = Get-RegistryValue -Path $edgePol -Name 'BrowserSignin'          # 1 or 2 enables MS account/Work account
$favbar  = Get-RegistryValue -Path $edgePol -Name 'FavoritesBarEnabled'    # 1 = show
$newtab  = Get-RegistryValue -Path $edgePol -Name 'NewTabPageLocation'
Write-Host "RestoreOnStartup: $restore  URLs[1]: $urls"
Write-Host "BrowserSignin: $signin"
Write-Host "FavoritesBarEnabled: $favbar"
Write-Host "NewTabPageLocation: $newtab"

Write-Host "`n=== 5) .NET and OS Features ==="
# .NET 4.x version
$rel = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release'
$ver = switch ($rel) {
  {$_ -ge 533320} { '4.8.1 or later' ; break }
  {$_ -ge 528040} { '4.8' ; break }
  {$_ -ge 461808} { '4.7.2' ; break }
  {$_ -ge 461308} { '4.7.1' ; break }
  {$_ -ge 460798} { '4.7' ; break }
  default { 'Unknown' }
}
Write-Host ".NET v4 Release: $rel ($ver)"
# .NET 3.5 feature
try {
  $fx3 = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop)
  Write-Host "Feature NetFx3: $($fx3.State)"
} catch { Write-Host "Feature NetFx3: UNKNOWN ($($_.Exception.Message))" }

Write-Host "`n=== 6) Power Settings (Lid close on AC) ==="
try {
  $scheme = (powercfg /getactivescheme) 2>&1
  $guid = ($scheme | Select-String -Pattern 'GUID:\s*([a-f0-9\-]+)').Matches.Groups[1].Value
  Write-Host "Active Power Scheme: $guid"
  $q = (powercfg /q $guid SUB_BUTTONS LIDACTION) 2>&1
  # AC index value is the last hex number on the "Current AC Power Setting Index" line
  $acLine = $q | Select-String -Pattern 'Current AC Power Setting Index:\s*0x([0-9a-f]+)'
  if ($acLine) {
    $ac = [Convert]::ToInt32($acLine.Matches[0].Groups[1].Value,16)
    # 0=Do nothing, 1=Sleep, 2=Hibernate, 3=Shut down
    $map = @{0='DoNothing';1='Sleep';2='Hibernate';3='Shutdown'}
    Write-Host "Lid close action (AC): $ac ($($map[$ac]))"
  } else {
    Write-Host "Lid close action (AC): UNKNOWN"
  }
} catch { Write-Host "Power query failed: $($_.Exception.Message)" }

Write-Host "`n=== 7) Applications Inventory ==="
$uninstRoots = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$appNeedles = @(
  'Microsoft 365 Apps','Microsoft Office','Microsoft 365 Apps for business',
  'Adobe Acrobat Reader','Company Portal','Egnyte','Egnyte WebEdit',
  'SentinelOne','Panini','Yardi CheckScan','Zoom','Zoom Workplace'
)
$found = @()
foreach ($r in $uninstRoots) {
  if (Test-RegKeyExists $r) {
    Get-ChildItem $r | ForEach-Object {
      $dn = Get-RegistryValue -Path $_.PsPath -Name 'DisplayName'
      if ($dn) {
        $dv = Get-RegistryValue -Path $_.PsPath -Name 'DisplayVersion'
        foreach ($needle in $appNeedles) {
          if ($dn -like "*$needle*") {
            $found += [pscustomobject]@{Name=$dn; Version=$dv}
          }
        }
      }
    }
  }
}
$found | Sort-Object Name -Unique | ForEach-Object { Write-Host (" - {0} [{1}]" -f $_.Name, $_.Version) }

# Office sanity
$hasM365 = ($found.Name -like '*Microsoft 365 Apps*').Count -gt 0
$hasOEM  = ($found.Name -like '*Microsoft Office*' -and -not $hasM365)
Write-YesNo "Correct Office present (Microsoft 365 Apps for business)" $hasM365
Write-YesNo "OEM Office remnants detected" $hasOEM

# SentinelOne service
$sentSvc = Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'Sentinel*'}
if ($sentSvc) { $sentSvc | ForEach-Object { Write-Host "Sentinel service: $($_.Name) = $($_.Status)" } }
else { Write-Host "Sentinel service: NOT FOUND" }

# Panini drivers hint
$panini = $found | Where-Object { $_.Name -like '*Panini*' }
Write-Host ("Panini drivers: " + $(if ($panini) { ($panini | ForEach-Object { "$($_.Name) [$($_.Version)]" }) -join '; ' } else { 'NOT FOUND' }))

# Yardi CheckScan versions
$yardi = $found | Where-Object { $_.Name -like '*Yardi CheckScan*' }
if ($yardi) {
  $versions = ($yardi.Version | Sort-Object -Unique) -join ', '
  Write-Host "Yardi CheckScan versions installed: $versions"
  Write-YesNo "Target version 70.8.9.25 present" ($yardi.Version -contains '70.8.9.25')
  Write-YesNo "Old version 70.8.9.20 present" ($yardi.Version -contains '70.8.9.20')
} else {
  Write-Host "Yardi CheckScan: NOT FOUND"
}

Write-Host "`n=== 8) Zoom for Outlook add-in (signals) ==="
# The modern "Zoom for Outlook" is an Office web add-in deployed via M365 Integrated Apps.
# Local signals are limited: check for Teams/Office WEF catalogs and Zoom registry footprints.
$wef = 'HKCU:\Software\Microsoft\Office\16.0\WEF\TrustedCatalogs'
if (Test-RegKeyExists $wef) { Write-Host "Office WEF TrustedCatalogs present (HKCU)" } else { Write-Host "Office WEF TrustedCatalogs (HKCU): not found" }
$zoomPlugin = $found | Where-Object { $_.Name -like '*Zoom*Outlook*' -or $_.Name -like '*Zoom Plugin for Outlook*' }
if ($zoomPlugin) { Write-Host "Legacy Zoom Outlook plugin entries: present (deprecated model)" } else { Write-Host "Legacy Zoom Outlook plugin: not detected" }
Write-Host "Note: Cloud-deployed Office web add-ins cannot be fully verified from endpoint without user context."

Write-Host "`n=== 9) Copy file check: 'Email Signatures Guidelines' on desktops ==="
$hits = @()
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notin @('All Users','Default','Default User','Public') } |
  ForEach-Object {
    $p = Join-Path $_.FullName 'Desktop'
    if (Test-Path $p) {
      $f = Get-ChildItem $p -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Email*Signatures*Guidelines*' }
      if ($f) { $hits += $f.FullName }
    }
  }
if ($hits.Count -gt 0) {
  Write-Host "Found on desktops:"
  $hits | ForEach-Object { Write-Host " - $_" }
} else {
  Write-Host "No matching file found on user desktops."
}

Write-Host "`n=== Summary ==="
Write-Host " - dsregcmd printed above."
Write-Host " - MDM URLs reported. Expected URL: $expectedDiscoveryUrl"
Write-Host " - IME service/logs status reported."
Write-Host " - Egnyte Trusted Sites mappings and HTTPS requirement flag reported."
Write-Host " - Optional Entra group membership check skipped unless Graph ENV provided."
Write-Host " - Edge policy signals printed."
Write-Host " - .NET and NetFx3 feature status printed."
Write-Host " - Lid-close action on AC printed."
Write-Host " - App inventory printed including M365 Apps, Adobe Reader, Company Portal, Egnyte, SentinelOne, Panini, Yardi, Zoom."
Write-Host " - Zoom for Outlook signals printed."
Write-Host " - Desktop copy check printed."
Write-Host "End of read-only audit."
