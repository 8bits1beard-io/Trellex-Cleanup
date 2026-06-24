<#
.SYNOPSIS
    Intune Remediations REMEDIATION script (pairs with Detect-TrellixOrphanedFilters.ps1).
    Surgically removes orphaned Trellix/McAfee DLP class filter drivers, backs up the
    affected keys to a .reg file, logs everything, warns the user, and reboots in 5 min.

.DESCRIPTION
    Removes a filter entry only when BOTH:
        1. Name-matched - it is a Trellix/McAfee driver (hdlp*, mfe*, mcafee, trellix), AND
        2. Owner absent - the PRODUCT that owns that driver is NOT installed
    Driver files left on disk no longer fool the check - the decision is product presence
    (Uninstall entry / running service), not file-on-disk. hdlpdbk/hdlpflt are owned by DLP;
    mfehidk is shared, so it is removed only when neither DLP nor ENS is installed. If the
    owning product IS installed, the entry is left to the product owner. Only the orphaned
    string is removed; other filters in the value are kept; affected keys are backed up first.

.PARAMETER WhatIf
    Pilot mode: report what WOULD be removed and exit. Makes NO registry changes,
    no backup, no user warning, and no reboot. Use this to validate the decision on
    a sample machine before deploying through Intune.

.EXAMPLE
    # Deployed as the Intune Remediations remediation script (run as SYSTEM, 64-bit PowerShell).
    # Runs only on devices the detection script flagged; applies the fix and reboots in 5 min.

.EXAMPLE
    # Pilot the decision on one machine first - reports only, makes no changes and no reboot.
    powershell -ExecutionPolicy Bypass -File .\Remediate-TrellixOrphanedFilters.ps1 -WhatIf

.NOTES
    Runs in SYSTEM context (no interactive prompt). Backup + log under %WINDIR%\Temp.
    Exit 0 = success (or dry run). Exit 1 = error.

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Which PRODUCT owns each driver. A filter is removed only when its owning product
# is NOT installed - so stray driver files on disk no longer fool the check.
$DriverOwnerPatterns = @{
    'hdlpdbk' = 'Data Loss Prevention|DLP'
    'hdlpflt' = 'Data Loss Prevention|DLP'
    'mfehidk' = 'Data Loss Prevention|DLP|Endpoint Security|Threat Prevention|VirusScan|Host Intrusion|Firewall'
}
# Fallback owner for any other hdlp*/mfe*/mcafee/trellix driver: any McAfee/Trellix product.
$DefaultOwnerPattern = 'McAfee|Trellix'

# Filter values to inspect on each device key.
$FilterValueNames  = @('UpperFilters', 'LowerFilters')

# Seconds before the controlled reboot (5 minutes - user is warned, runs unattended).
$RebootDelaySeconds = 300

# Timestamped log + registry backup paths under %WINDIR%\Temp.
$Stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$LogPath = Join-Path $env:WINDIR "Temp\TrellixFilterRemediate-$Stamp.log"
$BakPath = Join-Path $env:WINDIR "Temp\TrellixFilterRemediate-$Stamp.backup.reg"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Append a timestamped line to the log file.
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

# Is this filter name a Trellix/McAfee driver? (broad, to catch every variant)
function Test-IsTrellixName {
    param([string]$Name)
    return ($Name -match '^(hdlp|mfe)' -or $Name -match '(?i)mcafee|trellix')
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
    if ($p -notmatch '^[a-zA-Z]:\\' -and $p -notmatch '^\\\\') { $p = Join-Path $env:WINDIR $p }
    return $p
}

# Snapshot installed products + running services once (used to judge "owner present").
function Get-OwnerContext {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $script:InstalledProducts = @(Get-ItemProperty $roots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | Select-Object DisplayName, InstallLocation)
    $script:RunningServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' } | Select-Object Name, PathName)
}

# Is the product that OWNS this driver currently installed or running?
function Test-OwningProductPresent {
    param([string]$DriverName)
    $pattern = $DriverOwnerPatterns[$DriverName.ToLower()]
    if (-not $pattern) { $pattern = $DefaultOwnerPattern }
    if ($script:InstalledProducts | Where-Object { $_.DisplayName -match $pattern }) { return @{ Present = $true;  Reason = "installed/owned (/$pattern/)" } }
    if ($script:RunningServices  | Where-Object { $_.PathName    -match $pattern }) { return @{ Present = $true;  Reason = "owner service running (/$pattern/)" } }
    return @{ Present = $false; Reason = "no owning product installed (/$pattern/)" }
}

# Forensic detail only (logged, not decisive).
function Get-DriverDetail {
    param([string]$Name)
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $keyExists = Test-Path $svcPath
    $img = if ($keyExists) { (Get-ItemProperty $svcPath -ErrorAction SilentlyContinue).ImagePath } else { $null }
    if ([string]::IsNullOrWhiteSpace($img)) { $img = "System32\drivers\$Name.sys" }
    $file = Resolve-DriverPath -ImagePath $img
    $fileExists = [bool]($file -and (Test-Path -LiteralPath $file -ErrorAction SilentlyContinue))
    return "svcKey=$keyExists; imagePathFile=$fileExists"
}

# THE decision: clear a name-matched filter only when its owning product is absent.
function Test-FilterOrphaned {
    param([string]$FilterName)
    $own = Test-OwningProductPresent -DriverName $FilterName
    $detail = Get-DriverDetail -Name $FilterName
    if ($own.Present) { return @{ Orphaned = $false; Reason = "$($own.Reason) [$detail]" } }
    return @{ Orphaned = $true; Reason = "$($own.Reason) [$detail]" }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Log "Remediation start. Log: $LogPath"
if ($WhatIf) { Write-Log "MODE: DRY RUN (-WhatIf) - no changes, no backup, no reboot." 'WARN' }
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
                $n = $_.GetValueNames()
                $n -contains 'UpperFilters' -or $n -contains 'LowerFilters'
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
        $current = @($current)

        $toRemove = @()
        foreach ($entry in $current) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            if (-not (Test-IsTrellixName $entry)) { continue }
            $r = Test-FilterOrphaned -FilterName $entry
            if ($r.Orphaned) {
                $toRemove += $entry
                Write-Log "ORPHAN: '$entry' in $valName of $($key.Name)  [$($r.Reason)]" 'WARN'
            } else {
                Write-Log "keep:   '$entry' in $valName of $($key.Name)  [$($r.Reason)]"
            }
        }

        if ($toRemove.Count -gt 0) {
            $remaining = @($current | Where-Object { $toRemove -notcontains $_ })
            $plannedChanges.Add([pscustomobject]@{
                Path = $psPath; RegName = $key.Name; Value = $valName
                Removing = $toRemove; Remaining = $remaining
            })
        }
    }
}

if ($plannedChanges.Count -eq 0) {
    Write-Log "Nothing to remediate (no orphaned Trellix filters)." 'OK'
    exit 0
}

Write-Log "Found $($plannedChanges.Count) filter value(s) needing repair." 'WARN'

# Dry run: report only, then stop before any backup/change/reboot.
if ($WhatIf) {
    foreach ($chg in $plannedChanges) {
        Write-Log "WOULD remove [$($chg.Removing -join ', ')] from $($chg.Value) on $($chg.RegName)" 'WARN'
    }
    Write-Log "Dry run complete. Re-run without -WhatIf to apply." 'OK'
    exit 0
}

# Backup affected keys before changing anything.
try {
    $regKeyPaths = $plannedChanges | ForEach-Object { $_.RegName -replace '^HKEY_LOCAL_MACHINE','HKLM' } | Select-Object -Unique
    foreach ($rk in $regKeyPaths) { & reg.exe export $rk $BakPath /y *>> $LogPath }
    Write-Log "Backup written to $BakPath" 'OK'
} catch {
    Write-Log "Backup failed: $($_.Exception.Message)" 'ERROR'
    exit 1   # do not modify without a backup
}

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
        Write-Log "FAILED $($chg.Value) on $($chg.RegName): $($_.Exception.Message)" 'ERROR'
    }
}
Write-Log "Applied $applied of $($plannedChanges.Count) change(s)." 'OK'

# Warn the user, then controlled reboot in 5 minutes.
$mins = [math]::Round($RebootDelaySeconds / 60)
$msg  = "IT fix applied: a network/USB driver issue has been corrected. " +
        "This PC will restart in $mins minutes to complete the repair. Please save your work."
try { & msg.exe * /TIME:$RebootDelaySeconds $msg 2>$null } catch {}
& shutdown.exe /r /t $RebootDelaySeconds /c $msg
Write-Log "Reboot scheduled in $RebootDelaySeconds s (cancel: shutdown /a)." 'OK'
exit 0
