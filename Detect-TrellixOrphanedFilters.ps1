<#
.SYNOPSIS
    Intune Remediations DETECTION script.
    Reports NON-COMPLIANT (exit 1) only when an orphaned Trellix/McAfee DLP class
    filter driver is present - i.e. a filter entry whose service/driver no longer
    exists and whose name matches a Trellix/McAfee pattern.

    A healthy Trellix install resolves fine -> COMPLIANT (exit 0) -> remediation
    never runs -> never shows as recurring/failed in Intune.

.NOTES
    Runs in SYSTEM context. Read-only. Logs to %WINDIR%\Temp.
    Exit 0 = compliant (no action). Exit 1 = non-compliant (run remediation).

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

# Known Trellix/McAfee DLP class-filter drivers. hdlpdbk = DLP Device Blocking
# Filter Driver (the one that blocks NIC/USB). An entry counts only if it is in
# this list AND its driver is actually gone (Test-FilterOrphaned), so a healthy
# install never flags. Add names as needed.
$TrellixPatterns  = @('hdlpdbk', 'hdlpflt', 'mfehidk')
$FilterValueNames = @('UpperFilters', 'LowerFilters')
$Stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$LogPath = Join-Path $env:WINDIR "Temp\TrellixFilterDetect-$Stamp.log"

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
    if (-not (Test-Path $svcPath)) { return $true }
    $svc = Get-ItemProperty -Path $svcPath -ErrorAction SilentlyContinue
    $img = $svc.ImagePath
    if ([string]::IsNullOrWhiteSpace($img)) { $img = "System32\drivers\$FilterName.sys" }
    $file = Resolve-DriverPath -ImagePath $img
    if ($file -and (Test-Path -LiteralPath $file)) { return $false }
    return $true
}

Write-Log "Detection start. Log: $LogPath"
$found = @()

$scanRoots = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Class',
    'HKLM:\SYSTEM\CurrentControlSet\Enum'
)

foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_
        $names = $key.GetValueNames()
        foreach ($valName in $FilterValueNames) {
            if ($names -notcontains $valName) { continue }
            $vals = @($key.GetValue($valName))
            foreach ($entry in $vals) {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                if (-not (Test-IsTrellixName $entry)) { continue }
                if (Test-FilterOrphaned $entry) {
                    $msg = "ORPHAN '$entry' in $valName of $($key.Name)"
                    Write-Log $msg 'WARN'
                    $found += $msg
                }
            }
        }
    }
}

if ($found.Count -gt 0) {
    Write-Log "NON-COMPLIANT: $($found.Count) orphaned entr(ies) found." 'WARN'
    Write-Output "Orphaned Trellix filter(s) found: $($found.Count)"
    exit 1
}

Write-Log "COMPLIANT: no orphaned Trellix filters." 'OK'
Write-Output "Compliant"
exit 0
