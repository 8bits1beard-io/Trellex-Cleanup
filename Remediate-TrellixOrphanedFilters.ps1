<#
.SYNOPSIS
    Intune Remediations REMEDIATION script (pairs with Detect-TrellixOrphanedFilters.ps1).
    Surgically removes orphaned Trellix/McAfee DLP class filter drivers, backs up the
    affected keys to a .reg file, logs everything, warns the user, and reboots in 5 min.

.DESCRIPTION
    Removes a filter entry only when it is BOTH:
        1. Unresolvable - service key missing OR driver .sys file missing, AND
        2. Name-matched - matches a Trellix/McAfee pattern (mfe*, hdlp*, mcafee*, trellix*)
    Only the dead string is removed; other filters in the multi-string value are kept.
    Healthy Trellix installs and shared drivers owned by other products (e.g. ENS mfehidk)
    resolve fine and are left untouched.

.NOTES
    Runs in SYSTEM context (no interactive prompt). Backup + log under %WINDIR%\Temp.
    Exit 0 = success. Exit 1 = error.

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

# Known Trellix/McAfee DLP class-filter drivers. hdlpdbk = DLP Device Blocking
# Filter Driver (the one that blocks NIC/USB). An entry is removed only if it is
# in this list AND its driver is actually gone (Test-FilterOrphaned), so a
# healthy install is never touched. Add names as needed.
$TrellixPatterns   = @('hdlpdbk', 'hdlpflt', 'mfehidk')
$FilterValueNames  = @('UpperFilters', 'LowerFilters')
$RebootDelaySeconds = 300   # 5 minutes

$Stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$LogPath = Join-Path $env:WINDIR "Temp\TrellixFilterRemediate-$Stamp.log"
$BakPath = Join-Path $env:WINDIR "Temp\TrellixFilterRemediate-$Stamp.backup.reg"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

function Test-IsTrellixName {
    param([string]$Name)
    foreach ($p in $TrellixPatterns) { if ($Name -match ("^" + [regex]::Escape($p))) { return $true } }
    return $false
}

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

function Test-FilterOrphaned {
    param([string]$FilterName)
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$FilterName"
    if (-not (Test-Path $svcPath)) { return @{ Orphaned = $true; Reason = "service key missing" } }
    $svc = Get-ItemProperty -Path $svcPath -ErrorAction SilentlyContinue
    $img = $svc.ImagePath
    if ([string]::IsNullOrWhiteSpace($img)) { $img = "System32\drivers\$FilterName.sys" }
    $file = Resolve-DriverPath -ImagePath $img
    if ($file -and (Test-Path -LiteralPath $file)) { return @{ Orphaned = $false; Reason = "resolves to $file" } }
    return @{ Orphaned = $true; Reason = "driver file missing ($file)" }
}

Write-Log "Remediation start. Log: $LogPath"

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
