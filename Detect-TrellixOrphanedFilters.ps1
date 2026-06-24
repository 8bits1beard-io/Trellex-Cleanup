<#
.SYNOPSIS
    Intune Remediations DETECTION script (pairs with Remediate-TrellixOrphanedFilters.ps1).
    Reports NON-COMPLIANT (exit 1) only when an orphaned Trellix/McAfee filter entry is present.

.DESCRIPTION
    Read-only check. Scans every device CLASS and INSTANCE (Enum) key for UpperFilters/
    LowerFilters entries naming a Trellix/McAfee driver, then reports NON-COMPLIANT (exit 1)
    only when such an entry is orphaned - i.e. the PRODUCT that owns that driver is NOT
    installed (judged by the Installed Programs list and running services, not by whether the
    driver file is still on disk).

    A healthy install (owning product present) -> COMPLIANT (exit 0) -> remediation never
    runs -> never shows as recurring/failed in Intune. Shared drivers like mfehidk only flag
    when neither DLP nor ENS is installed. Makes no changes; logs every entry it keeps/flags.

.EXAMPLE
    # Deployed as the Intune Remediations detection script (run as SYSTEM, 64-bit PowerShell).
    # Takes no parameters; Intune reads the exit code to decide whether to remediate.

.EXAMPLE
    # Pilot manually on one machine and inspect the exit code (0 = compliant, 1 = non-compliant).
    powershell -ExecutionPolicy Bypass -File .\Detect-TrellixOrphanedFilters.ps1
    $LASTEXITCODE

.NOTES
    Runs in SYSTEM context. Read-only. Logs to %WINDIR%\Temp.
    Exit 0 = compliant (no action). Exit 1 = non-compliant (run remediation).

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Which PRODUCT owns each driver. A filter flags only when its owning product is
# NOT installed - so stray driver files on disk no longer fool the check.
$DriverOwnerPatterns = @{
    'hdlpdbk' = 'Data Loss Prevention|DLP'
    'hdlpflt' = 'Data Loss Prevention|DLP'
    'mfehidk' = 'Data Loss Prevention|DLP|Endpoint Security|Threat Prevention|VirusScan|Host Intrusion|Firewall'
}
# Fallback owner for any other hdlp*/mfe*/mcafee/trellix driver: any McAfee/Trellix product.
$DefaultOwnerPattern = 'McAfee|Trellix'

# Filter values to inspect on each device key.
$FilterValueNames = @('UpperFilters', 'LowerFilters')

# Timestamped log path under %WINDIR%\Temp.
$Stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$LogPath = Join-Path $env:WINDIR "Temp\TrellixFilterDetect-$Stamp.log"

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
    if ($script:InstalledProducts | Where-Object { $_.DisplayName -match $pattern }) { return $true }
    if ($script:RunningServices  | Where-Object { $_.PathName    -match $pattern }) { return $true }
    return $false
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

# Orphaned = name-matched Trellix driver whose owning product is NOT installed.
function Test-FilterOrphaned {
    param([string]$FilterName)
    if (-not (Test-IsTrellixName $FilterName)) { return $false }
    return (-not (Test-OwningProductPresent -DriverName $FilterName))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Log "Detection start. Log: $LogPath"
Get-OwnerContext
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
                    $msg = "ORPHAN '$entry' in $valName of $($key.Name) [$(Get-DriverDetail $entry); owner absent]"
                    Write-Log $msg 'WARN'
                    $found += $msg
                } else {
                    Write-Log "keep '$entry' in $valName of $($key.Name) [owner present]"
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
