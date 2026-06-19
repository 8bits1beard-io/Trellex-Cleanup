# Trellix DLP Orphaned Filter Cleanup

PowerShell tooling to detect and safely remove **orphaned Trellix/McAfee DLP device
filter drivers** that block WiFi, Ethernet, and USB after a failed Trellix DLP uninstall.

When Trellix DLP is removed badly, it can leave its device-filter driver (`hdlpdbk`)
registered in the Windows registry while the product itself is gone. On the next reboot
Windows tries to load the missing filter and fails the whole device — taking down network
and USB at once. These scripts find and clear **only** those orphaned leftovers, and leave
healthy installs untouched.

> 📖 For the full mechanism, decision logic, and diagrams, see **[TECHNICAL.md](TECHNICAL.md)**.

---

## Scripts

| Script | Role | Runs as | Reboot |
|---|---|---|---|
| [`Detect-TrellixOrphanedFilters.ps1`](Detect-TrellixOrphanedFilters.ps1) | Intune **detection** (read-only check) | SYSTEM | No |
| [`Remediate-TrellixOrphanedFilters.ps1`](Remediate-TrellixOrphanedFilters.ps1) | Intune **remediation** (the fixer) | SYSTEM | Yes, 5 min (warns user) |
| [`Fix-TrellixOrphanedFilters.ps1`](Fix-TrellixOrphanedFilters.ps1) | **Tech** on-device rescue | Admin | Yes, 30 s |
| [`Get-TrellixFilterDiagnostic.ps1`](Get-TrellixFilterDiagnostic.ps1) | **Read-only** diagnostic (collects state) | Any (elevated best) | No |

**Two ways to use it:**

- **Prevention (automatic):** the **Detect + Remediate** pair runs via Intune Remediations
  to catch and defuse a machine *before* it bricks (while it still has a network).
- **Rescue (hands-on):** a tech runs **Fix-** locally on a machine that's *already* bricked
  and off-network, where Intune can't reach it.

## How it decides what to remove

It removes a filter entry **only when both** are true:

1. **Name match** — the entry is a Trellix/McAfee driver (`hdlp*`, `mfe*`, `mcafee`, `trellix`).
2. **Owner absent** — the **product that owns that driver is not installed** (checked via the
   Installed Programs list *and* running services).

It deliberately does **not** trust whether the driver `.sys` file is on disk — those get
left behind after uninstall and would give a false reading. Only the orphaned entry is
removed; any other filters in the same value are preserved. See **[TECHNICAL.md](TECHNICAL.md)**
for the ownership map and full logic.

## Quick start

### Rescue an already-bricked machine (tech, local admin)

```powershell
# Always dry-run first - reports only, changes nothing
powershell -ExecutionPolicy Bypass -File ".\Fix-TrellixOrphanedFilters.ps1" -WhatIf

# Apply the fix and reboot (30 s) to complete it
powershell -ExecutionPolicy Bypass -File ".\Fix-TrellixOrphanedFilters.ps1"
```

### Deploy prevention via Intune Remediations

- **Detection script:** `Detect-TrellixOrphanedFilters.ps1`
- **Remediation script:** `Remediate-TrellixOrphanedFilters.ps1`
- **Run as:** System  •  **64-bit PowerShell:** Yes  •  **Schedule:** frequent (e.g. hourly)

Pilot the remediation manually first (no changes, no reboot):

```powershell
powershell -ExecutionPolicy Bypass -File ".\Remediate-TrellixOrphanedFilters.ps1" -WhatIf
```

### Collect machine state (read-only)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Get-TrellixFilterDiagnostic.ps1" |
    Tee-Object "$env:WINDIR\Temp\TrellixDiag-$env:COMPUTERNAME.txt"
```

## Safety, backup & logging

- **Reversible:** before any change, `Fix-` and `Remediate-` export the affected keys to a
  timestamped `.reg` backup. Remediate **aborts if the backup fails**. To roll back:
  `reg import <file>.backup.reg` then reboot.
- **Logged:** every run writes a timestamped log under `%WINDIR%\Temp\` recording each entry
  it inspected, kept, or removed — and why.
- **Surgical:** only the orphaned Trellix string is removed; other filters are kept.

## Before you go wide

Owner detection matches the product's **display name** (e.g. "…Data Loss Prevention…"). Run
`Get-TrellixFilterDiagnostic.ps1` on one affected machine and one healthy machine and confirm
the decision looks right. If your environment's product name differs, adjust the owner
patterns at the top of each script. Details in **[TECHNICAL.md](TECHNICAL.md)**.

## Credits

- **Author:** Joshua Walderbach
- **Contributors:** Brandon Villines, Corey Heflin, TJ Walton
- **Thanks:** Sanket Rana, Christopher Lamphere (testing & log research)
