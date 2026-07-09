<#
.SYNOPSIS
    Windows 11 in-place upgrade pre-flight compatibility scan.

.DESCRIPTION
    Mounts a Win11 24H2 ISO, runs setup.exe /compat scanonly, interprets the
    exit code, and parses CompatData XML for BlockMigration entries when blockers
    are detected. Dismounts ISO when complete.

.NOTES
    Requires ISO staged at C:\Temp\Win11_24H2.iso (7 GB).
    Download: https://www.microsoft.com/en-us/software-download/windows11

#>

#!ps
#maxlength=100000
#timeout=300000

$isoPath = 'C:\Temp\Win11_24H2.iso'

if (-not (Test-Path $isoPath)) {
    Write-Output "ERROR: ISO not found at $isoPath"
    Write-Output "Stage the Win11 24H2 ISO to C:\Temp\ before running."
    Write-Output "Download: https://www.microsoft.com/en-us/software-download/windows11"
    exit 1
}

Write-Output "=== Win11 Pre-Flight Compatibility Scan ==="
Write-Output ""

# Mount ISO
Write-Output "Mounting ISO..."
$mount = Mount-DiskImage -ImagePath $isoPath -PassThru
$drive = ($mount | Get-Volume).DriveLetter

if (-not $drive) {
    Write-Output "ERROR: ISO mounted but no drive letter assigned"
    Dismount-DiskImage -ImagePath $isoPath | Out-Null
    exit 1
}

$setup = "${drive}:\setup.exe"
if (-not (Test-Path $setup)) {
    Write-Output "ERROR: setup.exe not found at $setup"
    Dismount-DiskImage -ImagePath $isoPath | Out-Null
    exit 1
}

Write-Output "Mounted at ${drive}:\"

# Create log directory
$logDir = 'C:\Logs\Win11Compat'
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Run compatibility scan (2-3 minutes typical)
Write-Output "Running compatibility scan (2-3 min)..."
Write-Output ""

$proc = Start-Process -FilePath $setup `
    -ArgumentList '/auto upgrade /quiet /compat scanonly /copylogs C:\Logs\Win11Compat' `
    -Wait -PassThru
$exitCode = $proc.ExitCode
$hexCode = '0x{0:X8}' -f $exitCode

Write-Output "=== Results ==="
Write-Output "Exit code: $hexCode"
Write-Output ""

switch ($hexCode) {
    '0xC1900210' {
        Write-Output "PASS: No compatibility issues. Safe to proceed with upgrade."
    }
    '0xC1900208' {
        Write-Output "BLOCKED: Compatibility issues detected."
        Write-Output ""
        $compatDir = 'C:\$WINDOWS.~BT\Sources\Panther'
        $compatFiles = @(Get-ChildItem "$compatDir\CompatData_*.xml" -ErrorAction SilentlyContinue)
        if ($compatFiles.Count -gt 0) {
            Write-Output "Compat data files ($($compatFiles.Count)):"
            foreach ($f in $compatFiles) {
                Write-Output "  $($f.FullName)"
                try {
                    $xml = [xml](Get-Content $f.FullName -Raw)
                    $blockers = $xml.SelectNodes('//*[@BlockMigration="True"]')
                    if ($blockers.Count -gt 0) {
                        Write-Output "  Blockers ($($blockers.Count)):"
                        foreach ($b in $blockers) {
                            $snippet = $b.OuterXml
                            if ($snippet.Length -gt 300) { $snippet = $snippet.Substring(0, 300) + '...' }
                            Write-Output "    $snippet"
                        }
                    } else {
                        Write-Output "  No BlockMigration=True entries in XML"
                    }
                } catch {
                    Write-Output "  (could not parse XML: $_)"
                }
            }
        } else {
            Write-Output "No compat data files found at $compatDir"
            Write-Output "Check logs at $logDir"
        }
    }
    '0xC1900200' {
        Write-Output "FAIL: Hardware requirements not met (TPM 2.0 / Secure Boot / CPU)."
    }
    '0xC1900204' {
        Write-Output "FAIL: Migration choice not available for this edition."
    }
    default {
        Write-Output "UNEXPECTED: Exit code $hexCode not in known set."
        Write-Output "Check logs at $logDir"
    }
}

# Dismount ISO
Write-Output ""
Write-Output "Dismounting ISO..."
Dismount-DiskImage -ImagePath $isoPath | Out-Null
Write-Output "Done."
