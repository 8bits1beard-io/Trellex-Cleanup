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

    This script SURGICALLY removes only filter entries that are BOTH:
        1. Unresolvable  - the named service is missing, OR its driver .sys file is missing, AND
        2. Name-matched  - the name matches a Trellix/McAfee pattern (mfe*, hdlp*, mcafee*, trellix*)

    Both conditions are required. A healthy Trellix install resolves fine and is left untouched.
    Shared drivers still owned by another product (e.g. mfehidk owned by Trellix ENS) resolve
    fine and are left untouched. Other legitimate filters in the same multi-string value are
    preserved - only the dead string is removed.

    The original values are exported to a .reg backup before any change.

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

# Known Trellix/McAfee DLP class-filter drivers we will consider for removal.
#   hdlpdbk - DLP Device Blocking Filter Driver (THE driver that blocks NIC/USB)
#   hdlpflt - DLP file-system filter (kept for completeness)
#   mfehidk - shared McAfee/Trellix hook driver (often owned by ENS)
# An entry is removed ONLY if it is in this list AND its driver is actually gone
# (see Test-FilterOrphaned). So a healthy install is never touched. Matched
# case-insensitively against the start of the filter entry. Add names as needed.
$TrellixPatterns = @('hdlpdbk', 'hdlpflt', 'mfehidk')

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

# Is this filter name a Trellix/McAfee one?
function Test-IsTrellixName {
    param([string]$Name)
    foreach ($p in $TrellixPatterns) {
        if ($Name -match ("^" + [regex]::Escape($p))) { return $true }
    }
    return $false
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

# A filter is "orphaned" if its service key is missing, OR the service's driver file
# is missing. (A lingering service key with a deleted .sys still bricks the device.)
function Test-FilterOrphaned {
    param([string]$FilterName)
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$FilterName"
    if (-not (Test-Path $svcPath)) {
        return @{ Orphaned = $true; Reason = "service key missing" }
    }
    $svc = Get-ItemProperty -Path $svcPath -ErrorAction SilentlyContinue
    $img = $svc.ImagePath
    if ([string]::IsNullOrWhiteSpace($img)) {
        # Kernel driver with no ImagePath -> default System32\drivers\<name>.sys
        $img = "System32\drivers\$FilterName.sys"
    }
    $file = Resolve-DriverPath -ImagePath $img
    if ($file -and (Test-Path -LiteralPath $file)) {
        return @{ Orphaned = $false; Reason = "resolves to $file" }
    }
    return @{ Orphaned = $true; Reason = "driver file missing ($file)" }
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

# Discover every device key that has a filter value: all CLASS keys + all device
# INSTANCE (Enum) keys. The orphaned+name-match guard makes a broad scan safe.
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
            if (-not (Test-IsTrellixName $entry)) { continue }       # guard 1: name
            $r = Test-FilterOrphaned -FilterName $entry
            if ($r.Orphaned) {                                        # guard 2: unresolvable
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
