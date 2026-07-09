<#
.SYNOPSIS
    Set-EgnyteTrustedSitesLocalPolicy — Applies or removes Egnyte trusted site entries via local policy registry keys

.DESCRIPTION
    Manages HKLM policy-level ZoneMap and ZoneMapKey entries for Egnyte trusted sites.
    Adds or removes https://*.egnyte.com and file://EgnyteDrive as Zone 2 (Trusted Sites).
    Uses reg.exe for direct HKLM writes. Run as SYSTEM via SYSTEM remote session or RMM.
    Supports -Remove switch to undo changes. Includes verification pass.

.PARAMETER Remove
    Switch to remove the trusted site entries instead of adding them.

.NOTES
    Category: Environment-Specific
.KEYWORDS
    Egnyte, trusted sites, registry, policy, remediate, SYSTEM
#>

param(
  [switch]$Remove
)

# ---- Header ----
Write-Output ("PSVersion: {0}" -f $PSVersionTable.PSVersion)
Write-Output ("RunningAs: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name))
Write-Output ("Mode: {0}" -f ($(if($Remove){"REMOVE"}else{"ADD"})))
Write-Output ""

# ---- Paths ----
$Base    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
$ZMK     = "$Base\ZoneMapKey"
$ZM      = "$Base\ZoneMap"
$DomStar = "$ZM\Domains\egnyte.com\*"
$RangeK  = "$ZM\Ranges\EgnyteDrive"

# ---- Helpers ----
$global:OK = 0; $global:FAIL = 0
function Invoke-Reg {
  param([string]$RegArgs, [string]$Label)
  $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $RegArgs" -NoNewWindow -PassThru -Wait
  if ($p.ExitCode -eq 0) { $script:OK++ ; Write-Output ("OK   {0}" -f $Label) }
  else                   { $script:FAIL++; Write-Output ("FAIL {0} (ExitCode {1})" -f $Label,$p.ExitCode) }
}

function Bool {
  param([bool]$v) ; if ($v) { 'True' } else { 'False' }
}

# ---- Apply or Remove ----
if (-not $Remove) {
  # Ensure keys then set values
  Invoke-Reg "reg.exe add `"$ZMK`" /f"                          "Ensure $ZMK"
  Invoke-Reg "reg.exe add `"$ZMK`" /v `"https://*.egnyte.com`" /t REG_DWORD /d 2 /f"  "ZoneMapKey add https://*.egnyte.com = 2"
  Invoke-Reg "reg.exe add `"$ZMK`" /v `"file://EgnyteDrive`"   /t REG_DWORD /d 2 /f"  "ZoneMapKey add file://EgnyteDrive = 2"

  Invoke-Reg "reg.exe add `"$DomStar`" /f"                                       "Ensure $DomStar"
  Invoke-Reg "reg.exe add `"$DomStar`" /v https /t REG_DWORD /d 2 /f"            "ZoneMap Domains egnyte.com\* https=2"

  Invoke-Reg "reg.exe add `"$RangeK`" /f"                                        "Ensure $RangeK"
  Invoke-Reg "reg.exe add `"$RangeK`" /v `":Range`" /t REG_SZ /d `"file://EgnyteDrive`" /f" "ZoneMap Ranges :Range=file://EgnyteDrive"
  Invoke-Reg "reg.exe add `"$RangeK`" /v file /t REG_DWORD /d 2 /f"              "ZoneMap Ranges file=2"
}
else {
  # Remove values/keys
  Invoke-Reg "reg.exe delete `"$ZMK`" /v `"https://*.egnyte.com`" /f"            "ZoneMapKey remove https://*.egnyte.com"
  Invoke-Reg "reg.exe delete `"$ZMK`" /v `"file://EgnyteDrive`" /f"              "ZoneMapKey remove file://EgnyteDrive"

  Invoke-Reg "reg.exe delete `"$DomStar`" /v https /f"                            "ZoneMap Domains egnyte.com\* remove https"
  Invoke-Reg "reg.exe delete `"$RangeK`" /f"                                      "ZoneMap Ranges remove EgnyteDrive key"
}

Write-Output ""

# ---- Verification (reads back and prints booleans) ----
$zmkKey = Get-Item -Path "Registry::$ZMK" -ErrorAction SilentlyContinue
$zmk_https = $false; $zmk_file = $false
if ($zmkKey) {
  try { $zmk_https = ((Get-ItemProperty -Path "Registry::$ZMK" -Name "https://*.egnyte.com" -ErrorAction SilentlyContinue)."https://*.egnyte.com" -eq 2) } catch {}
  try { $zmk_file  = ((Get-ItemProperty -Path "Registry::$ZMK" -Name "file://EgnyteDrive"   -ErrorAction SilentlyContinue)."file://EgnyteDrive"   -eq 2) } catch {}
}

$dom_https = $false
try { $dom_https = ((Get-ItemProperty -Path "Registry::$DomStar" -Name https -ErrorAction SilentlyContinue).https -eq 2) } catch {}

$range_ok = $false
try {
  $rp = Get-ItemProperty -Path "Registry::$RangeK" -ErrorAction SilentlyContinue
  if ($rp -and ($rp.":Range" -eq "file://EgnyteDrive") -and ($rp.file -eq 2)) { $range_ok = $true }
} catch {}

Write-Output ("Verify ZoneMapKey   https://*.egnyte.com : {0}" -f (Bool $zmk_https))
Write-Output ("Verify ZoneMapKey   file://EgnyteDrive   : {0}" -f (Bool $zmk_file))
Write-Output ("Verify ZoneMap      egnyte.com\* https=2 : {0}" -f (Bool $dom_https))
Write-Output ("Verify ZoneMapRange EgnyteDrive          : {0}" -f (Bool $range_ok))
Write-Output ""

# ---- Summary and exit code ----
Write-Output ("Summary: OK={0}  FAIL={1}" -f $OK,$FAIL)
if ($FAIL -gt 0) { exit 1 } else { exit 0 }
