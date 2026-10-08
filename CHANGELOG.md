# Changelog

All notable changes to HostBadger are written down here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are numbered major.minor: a new minor for new features and fixes, a
new major if the snapshot or the JSON Lines format ever breaks.

## [Unreleased]
### Added
  **DISA STIG layer**: seven checks (`stig_windows11`, `stig_defender`,
  `stig_firewall`, `stig_edge`, `stig_chrome`, `stig_firefox`, `stig_office`)
  that judge 501 registry rules (Windows 11 V2R7, Defender V2R8, Firewall V2R2,
  Edge V2R5, Chrome V2R11, Firefox V6R7, Office 365 ProPlus V3R5), one finding
  per rule that differs. A value that is not configured counts. The data is
  `data\stig catalog.json`, built by `tools\Convert PowerStigData.ps1` from
  Microsoft PowerSTIG (MIT); the collector has a new `stig` section that reads
  exactly those values (HKLM, and the HKU hives of signed in users for the
  per user Office rules). Browser and Office rules apply only when the product
  is installed. ` SkipStig` leaves them out; the launcher asks.
  Seven more checks: `asr_other_rules_not_blocking` (13 more Microsoft ASR
  rules), `defender_protection_features_off` (behavior monitoring, downloaded
  files, script scanning, cloud protection, block at first sight),
  `hvci_off`, `powershell_module_logging_off`, `schannel_legacy_crypto_enabled`
  (SSL/TLS 1.0/1.1 and RC4/DES/3DES/NULL explicitly enabled),
  `ldap_server_signing_off` (domain controllers) and
  `print_point_and_print_weak` (PrintNightmare condition). New collector
  fields: Defender MAPS / block at first sight / script scanning, SCHANNEL,
  NTDS LDAP signing, Point and Print.
  `tools\New CoverageDoc.ps1` writes `COVERAGE.md` from the catalog.
  New category "DISA STIG" in the report.
  Compliance pie charts at the top of the report: DISA STIG rules judged versus
  failed, and CIS based checks applicable versus fired.
  ` HideCis` and ` HideStig` keep those findings out of the HTML listing (the
  charts still count them; CSV and JSON Lines keep them). The launcher asks.
  ` AiIncludeStig`: the STIG findings stay out of the Gemini prompt unless you
  ask for them, because hundreds of findings per host can make the request time
  out. The launcher asks, with that warning.
  Progress cursor (`| /   \`) in the collector and the analyzer for the steps
  that take time (collecting sections, reading snapshots, analyzing hosts,
  writing reports, preparing the AI prompt). It moves at each step, drawn only
  on an interactive console, so an EDR session or a log gets no extra output.
  The compliance charts sit right under the score cards.
  README: new summary and features sections; MooseAlto references removed.

  **Windows 10 STIG** (V3R6, 137 rules) as `stig_windows10`: a Windows 10 host is judged against its own STIG, a Windows 11 host against the Windows 11 one, a server against neither. 638 rules in total.
- **Pending Windows updates** (Collect-HostSnapshot.ps1 -CheckUpdates, opt-in): the Windows Update Agent searches for missing software updates (it contacts the WSUS server set by policy or Microsoft Update) and the check updates_pending reports each one, rated by Microsoft severity. The launcher asks and names the address.
- **Installed software** (new collector section software, always collected) listed in the report, with pie charts by publisher.
- **CISA KEV** (-KevFile or -KevOnline): installed software is matched to the Known Exploited Vulnerabilities catalog by vendor and product name (kev_software_match, new category Software). The catalog has no version ranges, so a finding is a lead to verify. -KevOnline makes one GET to www.cisa.gov and keeps a copy next to the report; the launcher asks and names the address. The program name in the finding is tokenized for the AI step.
- Charts: missing updates by severity, software and the KEV catalog.
- `service_binary_writable` is clearer and sharper: a folder-only finding now says the program itself is not writable but a DLL can be planted next to it, and the collector reads who may start the service (the SERVICE_START right in its security descriptor, administrators and SYSTEM only: otherwise it is unknown). A writable service folder that non-admin users can start is High instead of Medium.
- **service_path_ancestor_control**: a service program under a folder that a non-administrator owns or has full control of (the folder itself or any folder above it up to the drive root, outside the Windows directory). High when everyone has that control on a LocalSystem service, Medium otherwise; members of the local Administrators group are not reported. The collector reads the owner and the permission-changing rights of each parent folder (read only, cached).
- Fix: the text of a service finding under ProgramData contained a drive path, which made the AI leak check refuse to send the prompt. The text no longer has one, and a test covers it.
- Fix: `service_path_ancestor_control` fired on almost every service, with blank text ("...has  on..."). Two bugs: a leading comma on an already-built array in the collector (`return , $res`) wrapped it as a single element instead of returning it as-is, so the analyzer read .kind/.sid/.rights off the wrong object; and an empty array deep inside the snapshot could serialize as a bare `null` instead of `[]`. Both are fixed (the collector now normalizes `writableBy`/`ancestorControl` to `[]` when empty, and `Import-HostSnapshot` does the same for snapshots collected before this fix); members of the local Administrators group are correctly excluded, verified against a real run.

### Changed
  ` PerHost` writes one HTML report per host next to the fleet report
  (`<report>_<HOST>.html`). The guided menu asks for it (default yes) only when
  the snapshot folder holds more than one host.
  Several snapshots of one host now print a single line ("N snapshots, using
  the newest ...") instead of one "using the newer snapshot" line per file.

## [1.0]   2026 10 07
First release.

### Collecting
  `Collect HostSnapshot.ps1`, one self contained, read only collector for
  Windows PowerShell 5.1 and 7. It is made to be uploaded as an EDR cloud
  script and run through Real Time Response as SYSTEM, and it leaves a zip.
  It reads the host and OS, updates, Microsoft Defender, BitLocker, Secure
  Boot, LSA and credential protection, SMB, LLMNR, NetBIOS, the firewall,
  listening ports, RDP, local accounts and the local Administrators group,
  LAPS, UAC, PowerShell logging, the audit policy (`auditpol /backup`), the
  local security policy (`secedit /export`), a set of registry settings taken
  from the CIS Windows 11 benchmark, services, scheduled tasks and autoruns
  with the ACL of the programs they start.
  Each section is collected on its own, and a failure is recorded instead of
  stopping the run. Arguments that look like passwords are masked.

### Analyzing
  `HostBadger.ps1`, the offline analyzer, for one snapshot, a zip or a folder
  of them (the newest snapshot per host counts). It has 87 checks in ten
  areas, and it knows the role of the host: workstation, server or domain
  controller.
  A check whose data could not be collected, whose Defender is in passive
  mode or whose ACLs were skipped is listed as "not evaluated". A gap is never
  an all clear.
  34 checks follow a rule of the CIS Microsoft Windows 11 Enterprise Benchmark
  v3.0.0 and quote the rule number. The rule numbers and expected values come
  from the MIT licensed ansible lockdown/Windows 11 CIS role.
  EDR agents are recognised from the services (CrowdStrike Falcon,
  SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend
  Micro, Trellix, ESET, Symantec, Elastic, Cybereason, Cylance, Bitdefender,
  Huntress). A stopped agent is High, and ` ExpectedEdr` names the product
  every host should run. ` ExtraEdrServices` adds a product HostBadger does
  not know.
  The BitLocker checks understand Windows Home. `updates_stale` uses the
  Windows hotfix list, not the Windows Update history, which also holds
  Defender definitions, .NET and PowerShell updates.
  Windows lifecycle table (Windows 10, Windows 11, Windows Server 2012 to
  2025, by build and edition) for out of support and ending soon findings.

### Reporting
  An HTML report with the hosts, the coverage gaps, the findings grouped by
  check (why it matters, remediation, MITRE technique, CIS rule), a filterable
  table, the comparison with a previous run (` CompareTo`) and accepted risks
  (` ExceptionsFile`). Also a findings CSV, and JSON Lines for a SIEM with a
  stable `finding_id` and one summary per host.
  A **Fix script** under each check that has a safe, standard fix: plain
  PowerShell with a Copy button, which prints "old  > new" and changes nothing
  until you set `$Apply = $true`. ` OutRemediation` also writes one file per
  host, with a rollback file. HostBadger never runs any of it.

### Optional AI step
  With ` SendToAI`, Gemini writes an executive summary, a remediation plan,
  quick wins, monitoring ideas, the hosts to work on first and a triage across
  the fleet. It is off unless you ask. Everything that identifies something is
  replaced by a token before sending, the collector's error messages never
  leave the machine, and a leak check refuses to send if a real name is left.
  ` AiDryRun` shows the exact prompt and sends nothing. The prompt and the
  reply are kept next to the report.

### Around it
  `Start HostBadger.ps1`, a guided menu: collect this machine, analyze
  snapshots (it finds the ones in a `snapshots` folder by itself), collect and
  analyze, add an AI summary, run the safety review.
  `Test HostBadgerSafety.ps1` reads the scripts without running them and fails
  on any command outside the reviewed list, any system change, `auditpol` or
  `secedit` used for more than reading, hidden code, and network code outside
  `lib/AI.ps1`.
  A synthetic fleet of five hosts, `tests/Run Regression.ps1` (exact counts,
  every check fires, the "not evaluated" rule, roles, determinism, the safety
  review, the fix scripts run for real in a private registry branch, the AI
  step against a local mock endpoint, the launcher with typed answers) and
  `examples/` with a demo report.
  The README explains how to run the scripts with the execution policy
  bypassed, and how to set the Gemini API key.
