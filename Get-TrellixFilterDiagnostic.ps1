<#
.SYNOPSIS
    READ-ONLY diagnostic for Trellix/McAfee DLP orphaned-filter investigation.
    Collects the facts needed to choose a reliable "is Trellix really gone?" signal,
    after finding that hdlpdbk.sys can linger on disk even when DLP is uninstalled.

.DESCRIPTION
    Makes NO changes. Gathers, for the current machine:
      1. The hdlpdbk service registration (ImagePath, Start, Type, running state)
      2. Every hdlpdbk.sys copy on disk (to spot stray leftovers vs. the real path)
      3. UpperFilters/LowerFilters contents on the NIC and USB device classes
      4. Whether a Trellix/McAfee DLP product is still installed (Uninstall keys)
      5. What remains in the Trellix/McAfee program/data folders

    Run this on a machine that NEEDED clearing and (ideally) one that is HEALTHY,
    then compare. The goal is to confirm whether "product installed" and/or the
    service's actual ImagePath is a better gate than "any hdlpdbk.sys exists".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-TrellixFilterDiagnostic.ps1

.EXAMPLE
    # Tee a copy to a file for sharing
    powershell -ExecutionPolicy Bypass -File .\Get-TrellixFilterDiagnostic.ps1 |
        Tee-Object "$env:WINDIR\Temp\TrellixDiag-$env:COMPUTERNAME.txt"

.NOTES
    Read-only - safe on healthy or broken machines. Run elevated for full visibility.

    Author:       Joshua Walderbach
    Contributors: Brandon Villines, Corey Heflin, TJ Walton
    Thanks:       Sanket Rana, Christopher Lamphere (testing & log research)
#>

[CmdletBinding()]
param()

$DriverName = 'hdlpdbk'
$ClassGuids = @(
    @{ Name = 'Net (WiFi/Ethernet)'; Guid = '{4D36E972-E325-11CE-BFC1-08002BE10318}' },
    @{ Name = 'USB controllers';     Guid = '{36FC9E60-C465-11CF-8056-444553540000}' }
)

function Write-Section { param([string]$Title) ; "`n==================== $Title ====================" }

"Trellix DLP filter diagnostic"
"Computer : $env:COMPUTERNAME"
"User     : $env:USERNAME"
"Windows  : $([Environment]::OSVersion.Version)"

# --- 1. hdlpdbk service registration -----------------------------------------
Write-Section "1. $DriverName service registration"
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
if (Test-Path $svcKey) {
    $svc = Get-ItemProperty $svcKey -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ServiceKeyExists = $true
        ImagePath        = $svc.ImagePath
        Start            = $svc.Start      # 0=Boot 1=System 2=Auto 3=Manual 4=Disabled
        Type             = $svc.Type
        DependOnService  = ($svc.DependOnService -join ', ')
    } | Format-List

    # Does the path the service ACTUALLY loads from exist?
    $img = $svc.ImagePath
    if ([string]::IsNullOrWhiteSpace($img)) { $img = "System32\drivers\$DriverName.sys" }
    $resolved = $img.Trim('"') `
        -replace '(?i)^\\SystemRoot\\', "$env:WINDIR\" `
        -replace '(?i)^\\\?\?\\', '' `
        -replace '(?i)^System32\\', "$env:WINDIR\System32\"
    $resolved = [Environment]::ExpandEnvironmentVariables($resolved)
    if ($resolved -notmatch '^[a-zA-Z]:\\' -and $resolved -notmatch '^\\\\') { $resolved = Join-Path $env:WINDIR $resolved }
    "Resolved ImagePath : $resolved"
    "Resolved file exists: $([bool](Test-Path -LiteralPath $resolved -ErrorAction SilentlyContinue))"
} else {
    "Service key NOT present: $svcKey"
}
"Service runtime state: " + (((Get-Service $DriverName -ErrorAction SilentlyContinue)).Status)

# --- 2. hdlpdbk.sys copies on disk -------------------------------------------
Write-Section "2. $DriverName.sys file copies on disk"
"(searching common driver locations; this confirms stray vs. real copies)"
$searchDirs = @("$env:WINDIR\System32\drivers", "$env:ProgramFiles\McAfee", "${env:ProgramFiles(x86)}\McAfee",
                "$env:ProgramData\McAfee", "$env:ProgramFiles\Trellix", "${env:ProgramFiles(x86)}\Trellix")
$hits = foreach ($d in $searchDirs) {
    if (Test-Path $d) { Get-ChildItem $d -Recurse -Filter "$DriverName.sys" -ErrorAction SilentlyContinue }
}
if ($hits) { $hits | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize }
else { "No $DriverName.sys found in the searched locations." }

# --- 3. Class filter values ---------------------------------------------------
Write-Section "3. UpperFilters / LowerFilters on device classes"
foreach ($c in $ClassGuids) {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$($c.Guid)"
    $up = (Get-ItemProperty $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters
    $lo = (Get-ItemProperty $k -Name LowerFilters -ErrorAction SilentlyContinue).LowerFilters
    [pscustomobject]@{
        Class        = $c.Name
        UpperFilters = ($up -join ', ')
        LowerFilters = ($lo -join ', ')
        HasHdlpdbk   = (($up + $lo) -match $DriverName).Count -gt 0
    } | Format-List
}

# --- 4. DLP product installed? ------------------------------------------------
Write-Section "4. Is a Trellix/McAfee DLP product installed?"
$uninstRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$dlp = Get-ItemProperty $uninstRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'DLP|Data Loss|Trellix|McAfee' } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
if ($dlp) { $dlp | Format-Table -AutoSize }
else { "No Trellix/McAfee/DLP product found in Uninstall keys (product appears REMOVED)." }

# Related services that indicate the DLP agent / McAfee framework is still present
Write-Section "4b. Related Trellix/McAfee services present"
$svcMatch = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'mfe|hdlp|mcafee|trellix|masvc|macmnsvc|DLP' } |
    Select-Object Name, State, StartMode, PathName
if ($svcMatch) { $svcMatch | Format-Table -AutoSize }
else { "No related McAfee/Trellix/DLP services found." }

# --- 5. Program/data folders --------------------------------------------------
Write-Section "5. Trellix/McAfee folders present"
$folders = @("$env:ProgramFiles\McAfee","${env:ProgramFiles(x86)}\McAfee","$env:ProgramData\McAfee",
             "$env:ProgramFiles\Trellix","${env:ProgramFiles(x86)}\Trellix","$env:ProgramData\Trellix")
foreach ($f in $folders) {
    if (Test-Path $f) {
        "PRESENT: $f"
        Get-ChildItem $f -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -HideTableHeaders
    }
}

Write-Section "END"
"Share sections 1, 2, and 4 - they reveal whether 'product installed' and the"
"service's real ImagePath are reliable signals vs. a stray System32\drivers copy."
