<#
.SYNOPSIS
    Check-EgnyteTrustedSites — Audits Egnyte trusted site zone mappings across all user hives and policies

.DESCRIPTION
    Reads (never writes) IE/Edge ZoneMap registry keys to verify Egnyte trusted site
    configuration. Checks user hives (loading NTUSER.DAT if needed), EscDomains,
    and policy-level ZoneMap/ZoneMapKey entries for https://*.egnyte.com and
    file://EgnyteDrive. Designed for SYSTEM context via SYSTEM remote session or RMM.

.NOTES
    Category: Environment-Specific
.KEYWORDS
    Egnyte, trusted sites, registry, audit, diagnose, ZoneMap
#>

Write-Output "PSVersion: $($PSVersionTable.PSVersion)"
Write-Output "RunningAs: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Output ""

function Get-UserProfiles {
    $plRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    Get-ChildItem $plRoot -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^S-1-5-21-'
    } | ForEach-Object {
        $sid = $_.PSChildName
        $pip = (Get-ItemProperty -Path $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($pip) {
            [PSCustomObject]@{ SID=$sid; UserName=(Split-Path $pip -Leaf); ProfilePath=$pip }
        }
    }
}

function Mount-Hive {
    param($Sid,$Path)
    if (-not (Test-Path "Registry::HKEY_USERS\$Sid")) {
        if (Test-Path $Path) {
            & reg.exe load "HKU\$Sid" "$Path" | Out-Null
            return $true
        }
    }
    return $false
}

function Unmount-Hive {
    param($Sid,$Mounted)
    if ($Mounted) { & reg.exe unload "HKU\$Sid" | Out-Null }
}

function Test-Domain {
    param($Root)
    foreach ($k in @("Domains\egnyte.com","Domains\egnyte.com\*")) {
        $path = Join-Path $Root $k
        if (Test-Path $path) {
            $p = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if ($p.https -eq 2) { return $true }
        }
    }
    return $false
}

function Test-Drive {
    param($Root)
    $ranges = Join-Path $Root "Ranges"
    if (Test-Path $ranges) {
        foreach ($rk in Get-ChildItem $ranges) {
            $p = Get-ItemProperty $rk.PSPath -ErrorAction SilentlyContinue
            if ($p.":Range" -match "^file://egnytedrive$" -and $p.file -eq 2) { return $true }
        }
    }
    return $false
}

function Test-Esc {
    param($Root)
    foreach ($k in @("EscDomains\egnyte.com","EscDomains\egnyte.com\*")) {
        $path = Join-Path $Root $k
        if (Test-Path $path) {
            $p = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if ($p.https -eq 2) { return $true }
        }
    }
    return $false
}

# --- Check User Hives
$profiles = Get-UserProfiles
foreach ($prof in $profiles) {
    $sid = $prof.SID
    $mounted = Mount-Hive $sid (Join-Path $prof.ProfilePath "NTUSER.DAT")
    $root = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"

    $domain=$false; $drive=$false; $esc=$false
    if (Test-Path $root) {
        $domain = Test-Domain $root
        $drive  = Test-Drive  $root
        $esc    = Test-Esc    $root
    }

    Write-Output "User: $($prof.UserName) (SID $sid)"
    Write-Output "  TrustedDomain  https://*.egnyte.com : $domain"
    Write-Output "  TrustedRange   file://EgnyteDrive   : $drive"
    Write-Output "  EscDomains                       : $esc"
    Write-Output ""

    Unmount-Hive $sid $mounted
}

# --- Policy ZoneMapKey (GPO Site to Zone Assignment List)
$polPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"
if (Test-Path $polPath) {
    $dom=$false;$drv=$false
    foreach ($n in (Get-ItemProperty $polPath).PSObject.Properties.Name) {
        $v=(Get-ItemProperty $polPath).$n
        if ($v -eq 2) {
            if ($n -like "https://*.egnyte.com*") { $dom=$true }
            if ($n -like "file://egnytedrive*")   { $drv=$true }
        }
    }
    Write-Output "Policy ZoneMapKey: Domain=$dom Drive=$drv"
}
