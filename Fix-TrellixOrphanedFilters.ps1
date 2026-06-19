<#
.SYNOPSIS
    Removes orphaned Trellix/McAfee DLP class filter drivers (UpperFilters/LowerFilters)
    that brick network (WiFi/Ethernet) and USB devices after a failed DLP uninstall.

.DESCRIPTION
    A failed Trellix DLP (formerly McAfee DLP) uninstall can leave its kernel filter-driver
    name registered in the UpperFilters / LowerFilters values under device CLASS keys:

        HKLM\SYSTEM\CurrentControlSet\Control\Class\{ClassGUID}

    On reboot Windows tries to load that filter SERVICE for every device in the class. Because
    the DLP driver file/service is gone, the load fails and Windows fails the whole device
    (Code 39) - taking down WiFi, Ethernet and USB at once.

    This script SURGICALLY removes a filter entry only when BOTH:
        1. Name-matched   - the entry is a Trellix/McAfee driver (hdlp*, mfe*, mcafee, trellix)
        2. Owner absent   - the PRODUCT that owns that driver is NOT installed

    Why "owner absent" and not "is the .sys file there": uninstallers routinely leave the
    driver file (e.g. System32\drivers\hdlpdbk.sys) behind, so file-on-disk is NOT proof the
    product is healthy. The reliable signal is whether the owning product is actually installed
    (Uninstall entry) or its service is running. This accounts for every leftover variant -
    stray files, dangling service keys, missing ImagePath folders - with one rule:

        hdlpdbk / hdlpflt are owned by DLP.
        mfehidk is shared (DLP or ENS) - only cleared when NEITHER is installed, protecting ENS.

    If the owning product IS installed (even if the device looks broken), the entry is LEFT
    ALONE - that is the product owner's repair to make, not ours. Driver file/service details
    are still logged for forensics. Other filters in the same multi-string value are preserved;
    only the orphaned string is removed. Affected keys are exported to a .reg backup first.

.PARAMETER WhatIf
    Report what WOULD be removed, change nothing. ALWAYS run this first.

.PARAMETER NoReboot
    Apply the fix but do not reboot.

.PARAMETER RebootDelaySeconds
    Seconds to wait before the reboot that completes the fix (default 30).
    No end-user notification is shown - a technician runs this directly.

.PARAMETER Force
    Skip the interactive confirmation prompt before making changes.

.EXAMPLE
    # 1) Dry run - see what it would do
    powershell -ExecutionPolicy Bypass -File .\Fix-TrellixOrphanedFilters.ps1 -WhatIf

.EXAMPLE
    # 2) Apply and reboot to complete the fix
    powershell -ExecutionPolicy Bypass -File .\Fix-TrellixOrphanedFilters.ps1

.NOTES
    Run elevated (Administrator). Local, no network required.

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$NoReboot,
    [int]$RebootDelaySeconds = 30,
    [switch]$Force
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Which PRODUCT owns each driver. We clear a filter only when its owning product
# is NOT installed - so stray driver files on disk no longer fool the check.
#   hdlpdbk - DLP Device Blocking Filter Driver (THE driver that blocks NIC/USB) -> DLP
#   hdlpflt - DLP file-system filter                                             -> DLP
#   mfehidk - shared McAfee/Trellix hook driver                                  -> DLP or ENS
# Any other hdlp*/mfe*/mcafee/trellix driver falls back to "any McAfee/Trellix product".
$DriverOwnerPatterns = @{
    'hdlpdbk' = 'Data Loss Prevention|DLP'
    'hdlpflt' = 'Data Loss Prevention|DLP'
    'mfehidk' = 'Data Loss Prevention|DLP|Endpoint Security|Threat Prevention|VirusScan|Host Intrusion|Firewall'
}
$DefaultOwnerPattern = 'McAfee|Trellix'

# Filter value names to inspect on each device key.
$FilterValueNames = @('UpperFilters', 'LowerFilters')

$Stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$LogPath = Join-Path $env:WINDIR "Temp\TrellixFilterFix-$Stamp.log"
$BakPath = Join-Path $env:WINDIR "Temp\TrellixFilterFix-$Stamp.backup.reg"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Is this filter name a Trellix/McAfee driver? (broad, to catch every variant)
function Test-IsTrellixName {
    param([string]$Name)
    return ($Name -match '^(hdlp|mfe)' -or $Name -match '(?i)mcafee|trellix')
}

# Snapshot installed products + running services once (used to judge "owner present").
function Get-OwnerContext {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $script:InstalledProducts = @(Get-ItemProperty $roots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | Select-Object DisplayName, UninstallString, InstallLocation)
    $script:RunningServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' } | Select-Object Name, PathName)
    Write-Log ("Installed McAfee/Trellix products: " +
        (($script:InstalledProducts | Where-Object { $_.DisplayName -match 'McAfee|Trellix|DLP|Data Loss' } |
          ForEach-Object DisplayName) -join '; ')) 'INFO'
}

# Is the product that OWNS this driver currently installed / running?
function Test-OwningProductPresent {
    param([string]$DriverName)
    $pattern = $DriverOwnerPatterns[$DriverName.ToLower()]
    if (-not $pattern) { $pattern = $DefaultOwnerPattern }
    $prod = $script:InstalledProducts | Where-Object { $_.DisplayName -match $pattern } | Select-Object -First 1
    if ($prod) { return @{ Present = $true; Reason = "installed product '$($prod.DisplayName)'" } }
    $svc = $script:RunningServices | Where-Object { $_.PathName -match $pattern } | Select-Object -First 1
    if ($svc) { return @{ Present = $true; Reason = "running service '$($svc.Name)'" } }
    return @{ Present = $false; Reason = "no installed product or running service matches /$pattern/" }
}

# Resolve a service driver file path from its ImagePath (or the kernel default).
function Resolve-DriverPath {
    param([string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $null }
    $p = $ImagePath.Trim('"')
    $p = $p -replace '(?i)^\\SystemRoot\\', "$env:WINDIR\"
    $p = $p -replace '(?i)^\\\?\?\\', ''
    $p = $p -replace '(?i)^System32\\', "$env:WINDIR\System32\"
    $p = [Environment]::ExpandEnvironmentVariables($p)
    if ($p -notmatch '^[a-zA-Z]:\\' -and $p -notmatch '^\\\\') {
        $p = Join-Path $env:WINDIR $p   # relative -> under %WINDIR%
    }
    return $p
}

# Forensic detail only (logged, NOT decisive): does the driver actually resolve?
function Get-DriverDetail {
    param([string]$Name)
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $keyExists = Test-Path $svcPath
    $img = if ($keyExists) { (Get-ItemProperty $svcPath -ErrorAction SilentlyContinue).ImagePath } else { $null }
    if ([string]::IsNullOrWhiteSpace($img)) { $img = "System32\drivers\$Name.sys" }
    $file = Resolve-DriverPath -ImagePath $img
    $fileExists = [bool]($file -and (Test-Path -LiteralPath $file -ErrorAction SilentlyContinue))
    return "svcKey=$keyExists; imagePathFile=$fileExists ($file)"
}

# THE decision: clear a name-matched filter ONLY when its owning product is absent.
function Test-FilterShouldClear {
    param([string]$FilterName)
    if (-not (Test-IsTrellixName $FilterName)) {
        return @{ Clear = $false; Reason = "not a Trellix/McAfee driver" }
    }
    $own    = Test-OwningProductPresent -DriverName $FilterName
    $detail = Get-DriverDetail -Name $FilterName
    if ($own.Present) {
        return @{ Clear = $false; Reason = "owner present - $($own.Reason); leaving to product owner [$detail]" }
    }
    return @{ Clear = $true; Reason = "owner ABSENT - $($own.Reason); orphaned [$detail]" }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Log "Trellix orphaned-filter remediation starting. Log: $LogPath"
if ($WhatIf) { Write-Log "MODE: DRY RUN (-WhatIf) - no changes will be made." 'WARN' }

if (-not (Test-IsAdmin)) {
    Write-Log "Must be run as Administrator. Aborting." 'ERROR'
    exit 2
}

# Snapshot installed products / running services up front (used by the decision).
Get-OwnerContext

# Discover every device key that has a filter value: all CLASS keys + all device
# INSTANCE (Enum) keys. The name-match + owner-absent guard makes a broad scan safe.
$scanRoots = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Class',
    'HKLM:\SYSTEM\CurrentControlSet\Enum'
)

$keysWithFilters = foreach ($root in $scanRoots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $props = $_.GetValueNames()
                $props -contains 'UpperFilters' -or $props -contains 'LowerFilters'
            }
    }
}

$plannedChanges = New-Object System.Collections.Generic.List[object]

foreach ($key in $keysWithFilters) {
    $psPath = "Registry::$($key.Name)"
    foreach ($valName in $FilterValueNames) {
        $current = $null
        try { $current = (Get-ItemProperty -Path $psPath -Name $valName -ErrorAction Stop).$valName } catch { continue }
        if (-not $current) { continue }
        $current = @($current)   # force array

        $toRemove = @()
        foreach ($entry in $current) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $r = Test-FilterShouldClear -FilterName $entry
            if ($r.Clear) {
                $toRemove += $entry
                Write-Log "ORPHAN: '$entry' in $valName of $($key.PSChildName)  [$($r.Reason)]" 'WARN'
            } else {
                Write-Log "keep:   '$entry' in $valName of $($key.PSChildName)  [$($r.Reason)]"
            }
        }

        if ($toRemove.Count -gt 0) {
            $remaining = @($current | Where-Object { $toRemove -notcontains $_ })
            $plannedChanges.Add([pscustomobject]@{
                Path      = $psPath
                RegName   = $key.Name
                Value     = $valName
                Removing  = $toRemove
                Remaining = $remaining
            })
        }
    }
}

if ($plannedChanges.Count -eq 0) {
    Write-Log "No orphaned Trellix/McAfee filter entries found. Nothing to do." 'OK'
    exit 0
}

Write-Log "Found $($plannedChanges.Count) filter value(s) needing repair." 'WARN'

if ($WhatIf) {
    Write-Log "Dry run complete. Re-run without -WhatIf to apply." 'OK'
    exit 0
}

if (-not $Force) {
    $ans = Read-Host "Apply these changes? Type YES to continue"
    if ($ans -ne 'YES') { Write-Log "Aborted by operator." 'WARN'; exit 1 }
}

# Backup the affected keys before changing anything.
try {
    $regKeyPaths = $plannedChanges | ForEach-Object { ($_.RegName -replace '^HKEY_LOCAL_MACHINE','HKLM') } | Select-Object -Unique
    foreach ($rk in $regKeyPaths) {
        & reg.exe export ($rk -replace '^HKLM','HKLM') $BakPath /y *>> $LogPath
    }
    Write-Log "Backup written to $BakPath" 'OK'
} catch {
    Write-Log "Backup step failed: $($_.Exception.Message)" 'WARN'
}

# Apply.
$applied = 0
foreach ($chg in $plannedChanges) {
    try {
        if ($chg.Remaining.Count -eq 0) {
            Remove-ItemProperty -Path $chg.Path -Name $chg.Value -ErrorAction Stop
            Write-Log "Removed empty $($chg.Value) on $($chg.RegName)" 'OK'
        } else {
            Set-ItemProperty -Path $chg.Path -Name $chg.Value -Value ([string[]]$chg.Remaining) -Type MultiString -ErrorAction Stop
            Write-Log "Updated $($chg.Value) on $($chg.RegName) -> kept: $($chg.Remaining -join ', ')" 'OK'
        }
        $applied++
    } catch {
        Write-Log "FAILED to update $($chg.Value) on $($chg.RegName): $($_.Exception.Message)" 'ERROR'
    }
}

Write-Log "Applied $applied of $($plannedChanges.Count) change(s)." 'OK'

if ($NoReboot) {
    Write-Log "Done. -NoReboot set; reboot manually to rebuild the device stacks." 'OK'
    exit 0
}

# Tech-run: reboot to complete the fix. No end-user notification - a technician
# is running this directly. (PR/remediation script keeps the user warning.)
Write-Log "Rebooting in $RebootDelaySeconds s to complete the fix (cancel: shutdown /a)." 'WARN'
& shutdown.exe /r /t $RebootDelaySeconds /c "Trellix orphaned-filter fix applied - restarting to complete repair."
Write-Log "Reboot scheduled." 'OK'
exit 0
