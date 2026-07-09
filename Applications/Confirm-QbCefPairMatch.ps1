<#
.SYNOPSIS
    Verify that CefAdapter.dll and libcef.dll are a matched pair after a QB repair.

.DESCRIPTION
    After a QuickBooks Apps and Features Repair, confirms that CefAdapter.dll and
    libcef.dll in the QB install folder share the same LastWrite date. A date
    mismatch means a silent Intuit hotfix replaced CefAdapter without re-extracting
    libcef, which causes a STATUS_BREAKPOINT crash (0x80000003) at the fixed offset
    into libcef when the embedded CEF pane initializes.

    Reports:
      - CefAdapter.dll: path, size, LastWrite, file version, Authenticode status
      - libcef.dll: path, size, LastWrite, file version (Chromium build string)
      - Date delta between the two files in days
      - PASS/FAIL verdict: PASS if dates match within 1 day; FAIL otherwise
      - CEF sibling inventory (other files by LastWrite date for cross-check)

    Read-only. No changes to any file.

.PARAMETER QbInstallDir
    Path to the QuickBooks install directory.
    Default: "C:\Program Files\Intuit\QuickBooks Enterprise Solutions 24.0"

.NOTES
    Created: 2026-05-29
    Category: Applications
    Context: RMM shell (SYSTEM, PS 5.1 on QB host)

.KEYWORDS
    QuickBooks, CefAdapter, libcef, CEF, crash, mismatch, verify, RDS, repair
#>
#!ps
#maxlength=100000
#timeout=300000
#Requires -Version 5.1

param(
    [string]$QbInstallDir = 'C:\Program Files\Intuit\QuickBooks Enterprise Solutions 24.0'
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== Confirm-QbCefPairMatch ==="
Write-Output ("Host         : {0}" -f $env:COMPUTERNAME)
Write-Output ("Timestamp    : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("QB install   : {0}" -f $QbInstallDir)
Write-Output ""

if (-not (Test-Path $QbInstallDir)) {
    Write-Output ("ABORT: QB install dir not found: {0}" -f $QbInstallDir)
    Write-Output "       Set -QbInstallDir to the correct path (e.g. QB 2024 Pro uses 'QuickBooks 2024')."
    exit 1
}

# --- CefAdapter.dll ---
$cefAdapterPath = Join-Path $QbInstallDir 'CefAdapter.dll'
$cefAdapter = Get-Item $cefAdapterPath -ErrorAction SilentlyContinue
if (-not $cefAdapter) {
    Write-Output ("ABORT: CefAdapter.dll not found at {0}" -f $cefAdapterPath)
    exit 1
}

$cefAdapterSig = (Get-AuthenticodeSignature $cefAdapter.FullName -ErrorAction SilentlyContinue)

Write-Output "=== CefAdapter.dll ==="
Write-Output ("  Path        : {0}" -f $cefAdapter.FullName)
Write-Output ("  Size        : {0:N0} bytes" -f $cefAdapter.Length)
Write-Output ("  LastWrite   : {0}" -f $cefAdapter.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
Write-Output ("  FileVersion : {0}" -f $cefAdapter.VersionInfo.FileVersion)
Write-Output ("  Sig status  : {0}" -f $cefAdapterSig.Status)
Write-Output ""

# --- libcef.dll ---
$libcefPath = Join-Path $QbInstallDir 'libcef.dll'
$libcef = Get-Item $libcefPath -ErrorAction SilentlyContinue
if (-not $libcef) {
    Write-Output ("ABORT: libcef.dll not found at {0}" -f $libcefPath)
    exit 1
}

Write-Output "=== libcef.dll ==="
Write-Output ("  Path        : {0}" -f $libcef.FullName)
Write-Output ("  Size        : {0:N0} bytes" -f $libcef.Length)
Write-Output ("  LastWrite   : {0}" -f $libcef.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
Write-Output ("  FileVersion : {0}" -f $libcef.VersionInfo.FileVersion)
Write-Output ("  ProdVersion : {0}" -f $libcef.VersionInfo.ProductVersion)
Write-Output ""

# --- Date delta verdict ---
$deltaDays = [math]::Abs(($cefAdapter.LastWriteTime - $libcef.LastWriteTime).TotalDays)
Write-Output "=== Pair match verdict ==="
Write-Output ("  CefAdapter LastWrite : {0}" -f $cefAdapter.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
Write-Output ("  libcef LastWrite     : {0}" -f $libcef.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
Write-Output ("  Date delta           : {0:F1} days" -f $deltaDays)

if ($deltaDays -le 1) {
    Write-Output "  VERDICT: PASS - dates match within 1 day. CEF pair is consistent."
    $exitCode = 0
} else {
    Write-Output ("  VERDICT: FAIL - {0:F1}-day gap. CefAdapter and libcef are from different builds." -f $deltaDays)
    Write-Output "  This mismatch causes STATUS_BREAKPOINT (0x80000003) crashes on CEF pane init."
    Write-Output "  Run Apps and Features > QuickBooks > Change > Repair to restore a matched pair."
    $exitCode = 1
}

# --- CEF sibling inventory (spot-check for outlier dates) ---
Write-Output ""
Write-Output "=== CEF sibling inventory ==="
$siblings = Get-ChildItem $QbInstallDir -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^(CefAdapter|libcef|cef_|CefSharp|chrome_elf|libEGL|libGLESv2|snapshot_blob|v8_context_snapshot|icudtl)'
}

if ($siblings) {
    $siblings | Sort-Object LastWriteTime | ForEach-Object {
        Write-Output ("  {0,-40} {1}  {2,12:N0} bytes" -f $_.Name, $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.Length)
    }
    $dates = $siblings | ForEach-Object { $_.LastWriteTime.Date } | Select-Object -Unique
    if ($dates.Count -gt 1) {
        Write-Output ""
        Write-Output ("  WARNING: {0} distinct LastWrite dates across CEF siblings. Look for outliers above." -f $dates.Count)
    }
} else {
    Write-Output "  No CEF siblings found."
}

Write-Output ""
Write-Output "=== Done ==="
exit $exitCode
