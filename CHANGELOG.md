# Changelog

All notable changes to HostBadger are written down here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are numbered major.minor: a new minor for new features and fixes, a
new major if the snapshot or the JSON Lines format ever breaks.

## [1.0] - 2026-10-07
First release.

### Collecting
- `Collect-HostSnapshot.ps1`, one self-contained, read-only collector for
  Windows PowerShell 5.1 and 7. It is made to be uploaded as an EDR cloud
  script and run through Real Time Response as SYSTEM, and it leaves a zip.
- It reads the host and OS, updates, Microsoft Defender, BitLocker, Secure
  Boot, LSA and credential protection, SMB, LLMNR, NetBIOS, the firewall,
  listening ports, RDP, local accounts and the local Administrators group,
  LAPS, UAC, PowerShell logging, the audit policy (`auditpol /backup`), the
  local security policy (`secedit /export`), a set of registry settings taken
  from the CIS Windows 11 benchmark, services, scheduled tasks and autoruns
  with the ACL of the programs they start.
- Each section is collected on its own, and a failure is recorded instead of
  stopping the run. Arguments that look like passwords are masked.

### Analyzing
- `HostBadger.ps1`, the offline analyzer, for one snapshot, a zip or a folder
  of them (the newest snapshot per host counts). It has 87 checks in ten
  areas, and it knows the role of the host: workstation, server or domain
  controller.
- A check whose data could not be collected, whose Defender is in passive
  mode or whose ACLs were skipped is listed as "not evaluated". A gap is never
  an all-clear.
- 34 checks follow a rule of the CIS Microsoft Windows 11 Enterprise Benchmark
  v3.0.0 and quote the rule number. The rule numbers and expected values come
  from the MIT-licensed ansible-lockdown/Windows-11-CIS role.
- EDR agents are recognised from the services (CrowdStrike Falcon,
  SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend
  Micro, Trellix, ESET, Symantec, Elastic, Cybereason, Cylance, Bitdefender,
  Huntress). A stopped agent is High, and `-ExpectedEdr` names the product
  every host should run. `-ExtraEdrServices` adds a product HostBadger does
  not know.
- The BitLocker checks understand Windows Home. `updates_stale` uses the
  Windows hotfix list, not the Windows Update history, which also holds
  Defender definitions, .NET and PowerShell updates.
- Windows lifecycle table (Windows 10, Windows 11, Windows Server 2012 to
  2025, by build and edition) for out-of-support and ending-soon findings.

### Reporting
- An HTML report with the hosts, the coverage gaps, the findings grouped by
  check (why it matters, remediation, MITRE technique, CIS rule), a filterable
  table, the comparison with a previous run (`-CompareTo`) and accepted risks
  (`-ExceptionsFile`). Also a findings CSV, and JSON Lines for a SIEM with a
  stable `finding_id` and one summary per host.
- A **Fix script** under each check that has a safe, standard fix: plain
  PowerShell with a Copy button, which prints "old -> new" and changes nothing
  until you set `$Apply = $true`. `-OutRemediation` also writes one file per
  host, with a rollback file. HostBadger never runs any of it.

### Optional AI step
- With `-SendToAI`, Gemini writes an executive summary, a remediation plan,
  quick wins, monitoring ideas, the hosts to work on first and a triage across
  the fleet. It is off unless you ask. Everything that identifies something is
  replaced by a token before sending, the collector's error messages never
  leave the machine, and a leak check refuses to send if a real name is left.
  `-AiDryRun` shows the exact prompt and sends nothing. The prompt and the
  reply are kept next to the report.

### Around it
- `Start-HostBadger.ps1`, a guided menu: collect this machine, analyze
  snapshots (it finds the ones in a `snapshots` folder by itself), collect and
  analyze, add an AI summary, run the safety review.
- `Test-HostBadgerSafety.ps1` reads the scripts without running them and fails
  on any command outside the reviewed list, any system change, `auditpol` or
  `secedit` used for more than reading, hidden code, and network code outside
  `lib/AI.ps1`.
- A synthetic fleet of five hosts, `tests/Run-Regression.ps1` (exact counts,
  every check fires, the "not evaluated" rule, roles, determinism, the safety
  review, the fix scripts run for real in a private registry branch, the AI
  step against a local mock endpoint, the launcher with typed answers) and
  `examples/` with a demo report.
- The README explains how to run the scripts with the execution policy
  bypassed, and how to set the Gemini API key.
