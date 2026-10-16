# Changelog

All notable changes to HostBadger are written down here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are numbered major.minor: a new minor for new features and fixes, a
new major if the snapshot or the JSON Lines format ever breaks.

## [1.5] - 2026-10-16
### Added
- Guided menu: it says at the start whether it runs as administrator. If not,
  options 1 and 3 are marked "with gaps", 6 and 7 "needs administrator", and at
  an interactive console it offers to restart itself elevated (Windows asks you
  to confirm, UAC), in the same folder (new `-StartIn` parameter).
  `Start-Process` (`-Verb RunAs` of the menu itself) and `Set-Location` are
  allowed by the safety review in `Start-HostBadger.ps1` only.
- Guided menu: catalogs kept by an earlier analysis (`<report>_kev.json`,
  `_drivers.json`, `_eol.json`, `_choco.json`, `_cve.json`, next to the new
  report or in `.\output`) are offered as the default, with their date and age
  (over a week: a fresh download is advised): Enter uses the newest copy, O
  downloads a fresh one, N goes without. The review screen shows the file used.
- Report: "Summary by framework" next to the summary by category, with one row
  for CIS, one for DISA STIG, one for the ACSC Essential Eight and one per
  Essential Eight strategy (severities, checks triggered, hosts). In the
  dashboard each Essential Eight strategy opens on the checks that are not
  clean (worst severity, findings, hosts) and the clean ones, and the CIS panel
  lists the CIS-based checks that are not clean with their rules. Each check in
  the details names the Essential Eight strategies it relates to.

### Changed
- Score: it measures exposure. The DISA STIG rules and `brave_policy_gaps`
  (compliance with a policy baseline, shown in their own dashboard panel) no
  longer lower it, and a `kev_software_match` on a program the CVE data judged
  by its version is listed but not counted twice (its Detail says so). On a
  home PC that is not managed against the STIG the score of the same snapshot
  went from 33 (E) to 48 (D).
- DISA STIG: a value that no policy sets, while the snapshot shows the setting
  in effect is the compliant one, is a Low finding instead of the rule's
  severity, with Found "not configured (in effect: ...)": the firewall profile
  on, inbound blocked by default, dropped packets logged; Defender PUA,
  real-time, behavior, download and script scanning, block at first sight, MAPS,
  network protection, and signatures at most 7 days old for the signature-age
  rules.
- Dashboard: the verdict follows the grades (A-B good, C-D partial, E-F weak)
  and so does the color of the score ring: 48 (grade D) read "weak protection"
  before.
- Report: DISA STIG is no longer a row of the summary by category (it is in
  the summary by framework).
- Documentation: the collector is described as runnable by any tool that runs
  a .ps1 on the hosts (an EDR's live response, an RMM, Configuration Manager or
  Intune, a Group Policy startup script, PowerShell remoting), not only by an
  EDR; the README has a PowerShell remoting example next to CrowdStrike RTR and
  notes on the execution policy for each kind of tool.
- Guided menu: option 4 is called "Analyze with an AI summary" (it runs a
  whole analysis, with the AI questions up front); after a collection (option
  1) it says that option 2 lists the new snapshot.

## [1.4] - 2026-10-15
### Added
- Guided menu: after the last question of an analysis it lists every answer,
  numbered, and lets you change any of them before the run (a yes/no flips, a
  path or a list is typed again, "-" clears it); Enter runs, Q cancels.
- Guided menu: at the end of an analysis it offers to open the report with the
  default program for .html (the browser), only at an interactive console
  (`Invoke-Item`, allowed by the safety review in `Start-HostBadger.ps1` only).
- Guided menu: saved progress. The answers of a run are written after every
  answer to `output\hostbadger-wizard-state.json`, so a run stopped halfway
  (Ctrl+C, a closed window) is offered at the next start and resumes with the
  answers it had, asking only the rest; a run that stopped during the analysis
  runs it again, and "collect and analyze" resumes after a finished collection.
  Never saved: passwords, the Gemini key, the menu choice and the YES of a
  remediation. An interrupted remediation is never resumed: the next start says
  whether it had begun applying and offers the restore. The file goes when a
  run finishes; `HOSTBADGER_NO_RESUME` turns the feature off (the tests do).

### Changed
- Guided menu: a snapshot is no longer encrypted by default; the question reads
  (p/c/N) and a password or a certificate has to be chosen.
- Dashboard: the CIS panel gives the number of findings that quote each benchmark,
  and says why a workstation can show Windows Server 2022: a check that follows
  a rule only the server benchmarks have (mDNS, 18.6.4.1) quotes the server rule.

## [1.3] - 2026-10-15
### Added
- Guided menu: "Remediate this machine" (option 6, as administrator) and
  "Restore a remediation backup" (option 7). The first collects and analyzes
  this machine into `output\remediation\<time>`, shows what its fix script
  would change, and applies it only after you type YES, with a System Restore
  point first where Windows has one; the script writes every previous value to
  a rollback file, which option 7 previews and puts back after YES. Preinstalled
  Store apps from the bloatware list can be removed there, one group at a time
  on an explicit yes (not reversible: they come back from the Store). This is
  the only part of HostBadger that changes a machine: the collector and the
  analyzer stay read-only, and `Test-HostBadgerSafety.ps1` allows the commands
  it needs in `Start-HostBadger.ps1` only and says so in its verdict.
- Dashboard tab, the first thing the HTML report shows (the full report moves
  to a Details tab): the hardening score and findings by severity, DISA STIG
  compliance by product with its release (rules met / judged), CIS-based
  compliance, the ACSC Essential Eight strategies with the related checks
  judged and clean (coverage of settings, not a maturity assessment: MFA and
  backups are not visible from a host), the hardening categories and the top
  risks with the attacks they enable. A fleet report has a selector for the
  fleet or one host. Print shows both tabs.
- Three checks from a gap analysis against AtlantHarden, with new read-only
  collector fields in `hardening`: `script_files_execute_on_open` (.js, .jse,
  .vbs, .vbe, .wsf, .wsh, .hta run on a double click instead of opening as
  text; Medium on workstations, with a fix that sets the extension to
  `txtfile`; the Windows Script Host types are not judged when WSH is
  disabled), `lolbin_outbound_not_blocked` (no outbound firewall block rule for
  certutil, mshta, wscript, cscript, regsvr32, wmic, bitsadmin, read from the
  local and Group Policy rule stores; no fix, an organizational choice) and
  `removable_media_execute_allowed` (Removable Disks: Deny execute access not
  set; workstations, no fix). A snapshot from before these fields is not
  judged on them.
- `brave_policy_gaps`: Brave is judged on the machine rules of the DISA Chrome
  STIG read under its own policy key (Brave reads the Chromium policies), and
  on three Brave policies of its own (TorDisabled Medium, BraveWalletDisabled
  and BraveRewardsDisabled Low). An adaptation, not a DISA STIG: it does not
  count in the STIG compliance figures. The collector reads those values and
  detects Brave (`stig.products.brave`).
- DISA STIG for Adobe Acrobat Reader DC Continuous V2R1 (26 registry rules) and
  Acrobat Pro DC Continuous V2R1 (22), from the PowerSTIG processed files, as
  one check type `stig_adobe` (ARDC / AADC rule IDs); judged only where the
  product is installed (new `stig.products.adobereader` / `adobepro`). 1,475
  STIG rules in 14 products.- `bloatware_installed` (Low): preinstalled games, consumer apps and antivirus
  trials from a curated list (OEM driver and firmware tools left out), from a
  new read-only collector section `appx` (the AppxAllUserStore registry key:
  package names, provisioned or not, and how many profiles have each; no user
  SIDs) and the Programs and Features list. A snapshot without the section is
  "not evaluated" for it.
- ASR: the two newer rules (block rebooting into Safe Mode, block copied or
  impersonated system tools) join the "other rules", and the web shell rule is
  judged where Exchange Server is installed (Microsoft's ASR reference).
- Remediation engine and fix snippets handle a key's default value
  (`(default)`), backed up and restored like any other value.
- Guided menu: asks whether to write one remediation script per host
  (`-OutRemediation`), in a folder next to the report, and says what they are
  (text files HostBadger never runs, previewing until `-Apply`, with a rollback).
- CIS Windows Server services: `service_should_be_disabled` now also judges
  member servers, where the server benchmarks list one service, Print Spooler
  (rule 5.2, Level 2, Low; a print server needs it). Domain controllers stay
  with `spooler_on_dc`.
- `tools\New-ReportGif.ps1`: turns a report into the README GIF (Windows
  PowerShell 5.1 and Edge or Chrome, headless), one captioned slide per section,
  with one check opened; each slide is a window-sized screenshot, since a single
  screenshot of a long report comes out partly blank.

### Changed
- README: the "When to use something else" list under the comparison table is gone.
- `examples/demo_report.gif` rebuilt from the 1.2 demo report: version, "Attacks
  it enables", an opened check with its fix script and found/required values,
  the installed software and all findings (no AI section), starting with the
  dashboard.

## [1.2] - 2026-10-15
### Added
- "Attacks it enables" for every check: what an attacker can do with the
  finding (NTLM relay, credential dumping, privilege escalation, evasion...),
  written for each of the 132 checks (one text per DISA STIG product, whose
  rule IDs name the attack). Shown under each check of the report, in a new
  `Attacks` CSV column and a new `attacks` JSON Lines field (added, nothing
  renamed). The regression fails on a check without it.
- SQL Server through endoflife.date: the collector reads each Database Engine
  instance (new `sqlServer` section: the version of `sqlservr.exe`, and the
  registry `Setup` PatchLevel, Version, SP and Edition, read only). With
  `-EolOnline` / `-EolFile` each instance is placed on its service pack line
  (2016 SP2, SP3, SP3 Azure Connect Pack, 2008 R2 SP3...) by its build:
  `software_eol` when that line has ended (Low while ESU runs), and
  `software_outdated` when it is behind the latest cumulative update, or the
  latest GDR build for an instance on the security-only branch. Once every
  instance is placed, the Programs and Features rows of SQL Server are left to
  it; the copy kept next to the report also keeps the label and latest GDR
  build of each line. Without the data SQL Server stays on the lifecycle table.
- Launcher banner framed, with the repository address; the version reads v1.2.
- `.gitattributes` pins the line endings (LF in the repository, CRLF on disk), so
  a tool that rewrites a file with other line endings no longer makes a
  whole-file diff; the regression checks the rule is there.
- `CONTRIBUTING.md` (reporting bugs without real host data, proposing changes,
  the tests to pass); `SECURITY.md` names the security contact and links GitHub
  private vulnerability reporting; OpenSSF Baseline badge in the README;
  `.gitignore` also keeps out the downloaded catalog copies and `.pfx` files.
- AI step: when Gemini still answers 503 (model overloaded) or 429 after the
  retries, HostBadger suggests a smaller model (`-Model gemini-3.5-flash-lite`,
  for example) and points at the Gemini models page; the README says the same.
- `software_cve`: known vulnerabilities of the installed version of Python,
  Node.js, .NET, Notepad++, PowerShell 7, VirtualBox, Wireshark, 7-Zip, VLC,
  Git, GIMP, WinSCP, PuTTY, FileZilla, KeePass, Audacity, Mullvad VPN and
  AnyDesk. `-CveOnline` asks the NVD CVE API 2.0 (services.nvd.nist.gov) for the
  CVEs of each product by CPE, never by version and for the whole list whatever
  the hosts have, and judges the version ranges locally; then one GET of the
  FIRST EPSS daily file (epss.empiricalsecurity.com, gzip, about 3 MB), of which
  only the scores of those CVEs are kept. Only CVEs published before collection
  count, KEV from the date CISA added the CVE. One finding per program with the
  count, highest CVSS, the CVEs in KEV, the highest EPSS score and the release
  that fixes them all; High with a KEV CVE, CVSS 9.0 or EPSS 0.1, Medium for CVSS
  7.0 or EPSS 0.01. `NVD_API_KEY` is sent as a header and never written; without
  it requests are 6.5 s apart (about 2.5 minutes). Copy kept as
  `<report>_cve.json`, `-CveFile` reads it; guided menu question; AI re-run
  reuses it; both addresses allowed in `Test-HostBadgerSafety.ps1`.
- Program versions from the Chocolatey community repository: `-ChocoOnline`
  (GETs to community.chocolatey.org/api/v2/, page by page, nothing is sent; the
  copy is kept as `<report>_choco.json`) or `-ChocoFile`. `software_outdated`
  now also covers 7-Zip, VLC, Git for Windows, GIMP, WinSCP, PuTTY, FileZilla,
  KeePass, Audacity, Mullvad VPN, OBS Studio and AnyDesk, which endoflife.date
  lacks: every version has its publication date, so a host is late only for
  releases that existed at collection, and the grace period counts from the
  first one it missed. The same package list is asked for whatever the hosts
  have. The feed is often busy (503/504): each page is tried three times, and a
  package whose history did not come back whole is not judged. Guided menu
  question, AI re-run reuses the copy, community.chocolatey.org allowed in
  `Test-HostBadgerSafety.ps1`.
- README: "How it compares" (HardeningKitty, Policy Analyzer, DISA SCC,
  CIS-CAT Pro, Tenable/Qualys, Defender Vulnerability Management), with when to
  use something else.
- Eclipse Temurin JDK/JRE in the endoflife.date product map.
### Changed
- `software_outdated`: a program several releases behind a recent one (Notepad++
  8.9.1 when 8.9.8.1 came out within the grace period) is now flagged, Low;
  endoflife.date gives only the newest release's date, so the grace period
  alone hid hosts that had missed months of updates. One release behind inside
  the grace period is still not flagged. Build metadata ("+1") is ignored when
  versions are compared.
- `software_eol`: installed software past its vendor's end of support (Flash,
  Shockwave, Silverlight, Java 6/7, Adobe Reader/Acrobat XI, 2015 and 2017,
  Office/Visio/Project 2007 to LTSC 2021, Exchange 2010 to 2019, SQL Server 2008
  to 2016, Python 2 and 3.5 to 3.9, Node.js by major version, .NET Core / .NET 1.0
  to 7, Visual C++ 2005 to 2013 runtimes). The lifecycle table lives in
  `lib\Checks.ps1` next to the Windows one and is judged at collection time;
  severity per product (High for browser plugins, old readers and Exchange, Low
  for the Visual C++ runtimes). No collector change: it reads the existing
  `software` section. The installed name is tokenized for the AI prompt like
  the KEV finding. Paid extended support still running (Exchange 2016/2019,
  Oracle Java 8) lowers the finding to Low and says until when.
- Software lifecycle data from [endoflife.date](https://endoflife.date) (MIT):
  `-EolOnline` (one HTTPS GET of about 3 MB to endoflife.date/api/v1/products/full,
  nothing is sent; the reduced copy is kept next to the report as
  `<report>_eol.json`) or `-EolFile`. With it `software_eol` uses current dates
  and also covers Oracle Java, PowerShell 7, VirtualBox and Wireshark, and the
  new check `software_outdated` flags a program behind the latest release of its
  line (Python, Node.js, .NET runtimes, Java, PowerShell, VirtualBox, Wireshark),
  or a Firefox, Chrome or Notepad++ whose release line has already been replaced.
  A release counts only if it came out before collection and more than
  `-SoftwareGraceDays` (default 30) earlier; Medium when it is over 180 days old.
  The guided menu asks for it; the AI re-run reuses the kept copy. Allowed in
  `Test-HostBadgerSafety.ps1` as the only new address. The three catalog
  downloads now share one function (`Get-CatalogText`).
### Fixed
- AI pseudonymizer: a four-part program version ("version 32.0.0.465") is no
  longer taken for an IP address.
- AI pseudonymizer: check titles are no longer tokenized. On a host with an
  account called "support", "Windows version out of support" reached the model
  as "out of USER-1"; titles are now set aside like the CIS references, and the
  leak test ignores them (the same word elsewhere is still caught).
- `tests\New-ReportGif.ps1` turns a report into the slide GIF of the README
  (headless Edge or Chrome, Windows PowerShell 5.1). `examples\demo_report.gif`
  is regenerated from the current synthetic fleet and now includes the AI
  summary and the exploitability triage (Gemini, on the synthetic snapshots).
  `examples\demo_ai_prompt.txt` is regenerated too (`-AiDryRun`, current fleet).
- Two host-hardening checks for NTLM coercion / capture vectors: `webclient_webdav_enabled`
  (the WebClient / WebDAV Redirector service not disabled, which lets coercion such
  as PetitPotam force HTTP authentication for NTLM relay; High on a domain controller)
  and `wpad_not_disabled` (Web Proxy Auto-Discovery left on, so clients resolve
  "wpad" and an attacker who answers captures NTLM). New read-only collector field
  `hardening.wpadDisabled`; WebClient is read from the existing service list.
- DISA STIG coverage for Windows Server 2016 (V2R10) and Windows Server 2025
  (V1R1), domain-controller and member-server variants, as the check types
  `stig_server2016` and `stig_server2025` (the Server 2016 rules on a host its
  own CIS benchmark already recognises; Server 2025, which shares build 26100
  with Windows 11 24H2, is told apart by its server product type). The STIG
  layer now covers twelve products and 1,427 registry rules. No new collector
  command: the extra registry values were added to the read-only list the
  collector already reads.
- Five more CIS Windows Server checks for settings the Windows 11 benchmark does
  not have: `explorer_motw_bypass` (Mark of the Web not applied to files from
  insecure sources, CIS 18.10.29.2), `app_installer_policy_gaps` (App Installer
  / winget local-archive scan override, Store certificate-pinning bypass and
  command-line interfaces, CIS 18.10.18.4/.6/.7), `server_network_policy_gaps`
  (default IPv6 DNS servers and Internet Explorer feed Basic authentication, CIS
  18.6.4.3 / 18.10.58.2), `ldap_client_encryption_weak` (LDAP client encryption
  below Negotiate sealing, CIS 2.3.11.8) and, on domain controllers,
  `dc_security_policy_gaps` (ROCA-vulnerable Windows Hello for Business key
  validation and NTLM-in-domain auditing, CIS 18.9.39.1 / 2.3.11.13). New
  read-only collector field `hardening.serverPolicy`. 125 checks.
- CIS Windows Server coverage completed for settings that the Windows 11
  benchmark does not have (ansible-lockdown Windows-2022/2019/2016-CIS, MIT):
  three new server/domain-controller checks — `smb_server_hardening_gaps`
  (minimum SMB dialect 3.1.1 and SMB client Require Encryption, CIS 18.6.7.1 /
  18.6.8.2), `defender_server_baseline_gaps` (exclusions hidden from local
  users and scanned during a quick scan, CIS 18.10.43.17 / 18.10.43.13.1; it
  follows the Defender passive-mode rule) and `terminal_services_server_gaps`
  (per-session temporary folders and a single Remote Desktop session per user,
  CIS 18.10.57.3.11.2 / 18.10.57.3.2.1). Two more user rights are judged on
  servers — Create symbolic links (CIS 2.2.14, server 2.2.18/2.2.19) and
  Synchronize directory service data (server 2.2.48, domain-controller only) —
  and four more advanced-audit subcategories on domain controllers: Computer
  Account Management, Distribution Group Management, Other Account Management
  Events and Directory Service Access (CIS 17.2.2 to 17.4.1; GUIDs verified
  live against `auditpol`). New collector fields `hardening.serverSmb`,
  `hardening.defenderPolicy` and `hardening.terminalServicesPolicy`.
  `data\cis-map.json` now also lists, in a new `extra` section, the rule number
  and level of every server/Windows-10-only rule in each benchmark, so these
  findings quote the host's own number (`Add-Finding -ServerCis` with a Server
  2022 key resolves it through `Resolve-ExtraCis`). 120 checks.
- Three checks from a review of Harden-Windows-Security (MIT; ideas and public
  setting names only) against what HostBadger already reads:
  `bitlocker_weak_encryption` (a BitLocker volume on the drive's own hardware
  encryption, CVE-2018-12037, Medium; on a 128-bit key or CBC instead of
  XTS-AES 256, Low; from data already collected), `mdns_enabled` (multicast DNS
  on, like LLMNR and NetBIOS open to Responder; CIS Server 18.6.4.1; Low, with a
  fix script) and `authenticode_padding_check_off` (`EnableCertPaddingCheck`
  not 1, the opt-in fix for CVE-2013-3900, in CISA KEV; Low; no fix script
  because Microsoft warns that some installers then look unsigned). New
  collector fields `network.mdnsPolicyEnable` / `mdnsServiceEnable` and
  `hardening.certPaddingCheck` / `certPaddingCheckWow` / `is64BitOs`. Lynis
  (GPL-3.0) was reviewed for ideas only; its checks are for Unix systems.
- Encrypted snapshots: the collector's `-EncryptPassword` (AES-256-CBC with an
  HMAC-SHA256, encrypt-then-MAC, keys from PBKDF2-SHA256 at 600,000 rounds, or
  PBKDF2-SHA1 at 1,300,000 on a .NET Framework older than 4.7.2) or
  `-EncryptCertificate` (CMS EnvelopedData, AES-256, to a .cer file or a
  thumbprint in the certificate store) writes `hostsnapshot_<host>_<time>.hbx`
  instead of the zip; the zip is built in memory and nothing is written in
  clear. A missing certificate stops the collector before it collects. The
  analyzer reads `.hbx` files like zips, with `-SnapshotPassword` (asked for
  when missing) or the private key from the certificate store or
  `-SnapshotPfx` (loaded as an ephemeral key, never written to the profile); a
  wrong password or a changed file is reported and that snapshot is skipped.
  `meta.options.encryption` records the mode, never the secret. The guided
  menu asks when it collects (a password by default), and asks for the
  password once when it analyzes encrypted snapshots.
- Vulnerable and malicious drivers: new collector section `drivers` (every
  kernel driver service: name, state, start mode, file and its SHA-256, read
  with `Get-FileHash`; plus `VulnerableDriverBlocklistEnable`) and two checks.
  `vulnerable_driver_present` matches the hashes against the LOLDrivers catalog
  (www.loldrivers.io, Apache License 2.0): Critical for a known malicious
  driver, High for a loaded vulnerable one, Medium when installed but not
  running, one level lower for a sample LOLDrivers has not verified.
  `driver_blocklist_off` flags the Microsoft vulnerable driver blocklist
  explicitly turned off (Medium, with a fix script). The catalog ships as
  `data\vulnerable-drivers.json` (2,198 driver files), rebuilt by the new
  developer tool `tools\Convert-LolDrivers.ps1`; `-DriversOnline` downloads a
  fresh one (one GET of about 30 MB to www.loldrivers.io, from `lib\AI.ps1`)
  and keeps the converted copy next to the report. The guided menu asks, and
  names the address. Driver paths are tokenized for the AI step.
- Found versus required: every CIS and DISA STIG finding now carries the value
  on the host and the value the framework requires, as `Found` / `Expected`
  (new CSV columns, new JSON Lines fields `found` / `expected`) and as two
  "Found" / "Required" columns in the report table of each check (only for
  checks that have them). STIG findings take them from the catalog ("not
  configured" / "1"); CIS findings from their detail ("Name = value (CIS x
  expects y)") or from the check itself where the detail did not say what is
  required. The two aggregate checks (audit subcategories, ASR rules) keep
  listing every item in the detail and leave both empty. The fields do not
  reach the AI prompt.
- DISA STIG for Windows Server: two new checks, `stig_server2022` (Windows
  Server 2022 STIG V2R8) and `stig_server2019` (Windows Server 2019 STIG
  V3R8), 401 more registry rules (1039 in all). A server gets the domain
  controller rules (99 on 2022, 98 on 2019) or the member server rules (102),
  by role; Objects read `WN22-DC V-...`, `WN19-MS V-...`. Other server
  versions get no Windows STIG. The data comes from the PowerSTIG processed
  files (MIT), rebuilt with `tools\Convert-PowerStigData.ps1`; the collector's
  `STIG-REGISTRY` list now reads 514 values. The synthetic domain controller
  runs Windows Server 2019 (a Server 2016 domain controller is still tested).
- CIS on Windows 10 and Windows Server 2016: findings on those hosts now quote
  the *CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0* and the *CIS
  Microsoft Windows Server 2016 Benchmark v3.0.0* (for example SSDP Discovery is
  5.31 on Windows 10, 5.30 on Windows 11), from the MIT-licensed
  ansible-lockdown Windows-10-CIS and Windows-2016-CIS roles added to
  `data\cis-map.json` (each pairing cross-checked on its title). Server-only
  rules keep their number on Server 2016, except the Windows LAPS rule its
  benchmark lacks (it covers legacy LAPS), which quotes Server 2022. Expected
  values are unchanged. `tools\Convert-CisMapping.ps1` now also reads the
  `win_security_policy` registry form (`LegalNoticeText`), skips the duplicate
  `gpo_creation` tasks and records the BitLocker and next-generation profile
  levels.
- Report: a pie chart of the local accounts across the hosts, enabled
  administrators (members of the local Administrators group, matched by SID)
  versus enabled standard users and disabled accounts. Domain controllers (no
  local accounts) and hosts whose Administrators group could not be read are
  left out, never counted as standard users. No new collector field.
- Server-only CIS rules (CIS Windows Server 2022/2019 v4.0.0), two new checks.
  `dc_netlogon_policy_weak` (domain controllers): an exception list for
  vulnerable Netlogon secure channel connections, the Zerologon enforcement
  exceptions (2.3.5.2, High; only its presence is collected, never the
  accounts), machine account password changes refused (2.3.5.5) and Server
  Operators allowed to schedule tasks (2.3.5.1), Medium. `server_baseline_gaps`
  (servers, Low): shutdown from the logon screen (2.3.13.1), a member server
  that unlocks without asking a domain controller (2.3.7.8), and Windows LAPS
  backing up to Active Directory without password expiration protection
  (18.9.25.2). Fix scripts for the password change refusal, Server Operators
  tasks and shutdown without logon; not for the Zerologon list, the unlock
  rule or LAPS, which need a decision. New collector fields
  `hardening.netlogon.refusePasswordChange`,
  `hardening.netlogon.vulnerableChannelAllowListPresent`,
  `hardening.serverLogon` and `laps.windowsLapsPolicyRoot` /
  `laps.windowsLapsPasswordExpirationProtection`. Catalog field `CisServer`
  for checks whose rules only the server benchmarks have;
  `ldap_server_signing_off` now quotes 2.3.5.3 / 2.3.5.4 and
  `lsa_not_protected` CIS 18.9.26.2 (NG profile on servers).
  `tools\Convert-CisMapping.ps1` falls back on the title when the two roles
  write a setting under different keys, and records the NG profile level.
- User rights on servers: `user_rights_excessive` and `deny_logon_rights_missing`
  now run on member servers and domain controllers too, with the member server
  and domain controller lists of the CIS Windows Server 2022/2019 benchmarks
  (for example network logon: Administrators and Authenticated Users, plus
  ENTERPRISE DOMAIN CONTROLLERS on a DC; Remote Desktop: Administrators only on
  a DC; deny network logon: "Local account and member of Administrators" on a
  member server, Guests only on a DC). New on domain controllers: "Add
  workstations to domain" (`SeMachineAccountPrivilege`, CIS Server 2.2.5)
  held by anyone but Administrators; Windows grants it to Authenticated Users
  by default, which with the machine account quota lets any user create
  computer accounts. `Add-Finding -ServerCis` quotes a rule that only the
  server benchmarks have.
- CIS on Windows Server: on Server 2022 and Server 2019 the findings now quote
  the rule of the *CIS Microsoft Windows Server 2022 / 2019 Benchmark v4.0.0*
  (domain controller or member server variant by role, with the server
  profile level) instead of the Windows 11 number, in the Detail, the `Cis`
  field and the report. New JSON Lines field `cis_benchmark` and CSV column
  `CisBenchmark` name the benchmark. A rule with no server counterpart is
  quoted as `Windows 11 x.y.z`. The mapping is `data\cis-map.json`, built by the
  new developer tool `tools\Convert-CisMapping.ps1` from local clones of the
  MIT-licensed ansible-lockdown roles (same registry value, else same title;
  every registry pairing cross-checked on its title). Expected values are
  unchanged: they are the same in the three benchmarks for every setting
  HostBadger reads, except the one under Fixed.
- BitLocker Group Policy, CIS Windows 11 18.10.9.x (the optional BitLocker
  profile, all 47 rules), as two checks. `bitlocker_policy_weak` (Medium, with
  per-value severity) flags values that lower the protection itself: drive
  hardware encryption trusted, BitLocker without a TPM, Secure Boot not used for
  integrity, no additional authentication at startup, a password on the OS
  drive; on workstations (not Home) it also flags `DisableExternalDMAUnderLock`
  and `RDVDenyWriteAccess` when not set, since the Windows default is the
  problem. `bitlocker_policy_gaps` (Low) compares the other 38 values with the
  profile only when they are set (recovery options, AD DS escrow, smart cards,
  TPM startup combinations): organizational choices, reported as a comparison.
  No fix script for either (BitLocker policy is an organizational decision).
  New collector field `hardening.bitlockerPolicy` (47 read-only registry
  values; `RDVDenyWriteAccess` is read under
  `HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE`, where Group Policy
  writes it).
- New check `firewall_notifications_on` (Low, CIS Windows 11 9.1.3 / 9.2.3 /
  9.3.3, L1): the firewall policy of the Domain, Private or Public profile
  explicitly sets `DisableNotifications` to something other than 1. Judged only
  when the value is set. Fixable (one HKLM policy value per profile). New
  collector field `hardening.firewallPolicy` (three read-only registry values).
- `winrm_insecure_auth` now also judges two more CIS Windows 11 rules on the
  WinRM service: `AllowAutoConfig` (18.10.88.2.2, Level 2 - remote
  reconfiguration of WinRM over WinRM itself; deliberately left without a fix
  script, since disabling it can break EDR/RMM tooling that configures WinRM
  remotely) and `DisableRunAs` (18.10.88.2.4 - storing RunAs credentials for a
  listener; fixable, and judged on the Windows default too since "not
  configured" behaves as insecure). Two new collector fields in the existing
  `hardening.winrm` section (`serviceAllowAutoConfig`, `serviceDisableRunAs`),
  same registry key already opened for the other WinRM values. `Cis` widened
  to '18.10.88.1.1 - 18.10.88.2.4 (L1/L2)'.
- `audit_policy_gaps` now judges all 27 rules of CIS Windows 11 section 17
  (Advanced Audit Policy Configuration), not just 13 of them: added the other
  14 subcategories to `$script:RequiredAudit` (Application Group Management,
  Plug and Play Events, Group Membership, Logoff, Other Logon/Logoff Events,
  Detailed File Share, File Share, Removable Storage, Authorization Policy
  Change, MPSSVC Rule-Level Policy Change, Other Policy Change Events, IPsec
  Driver, Other System Events, Security State Change), each with the
  Success/Failure requirement the benchmark sets. Every GUID (new and
  pre-existing) was verified live against `auditpol /list /subcategory:* /v`
  on a real Windows 11 host, not taken from memory or secondary sources; this
  caught and corrected one wrong GUID candidate for "Other Policy Change
  Events" before it shipped. No new collector field: `auditpol /backup`
  already returns every subcategory. `Cis` annotated on the catalog entry for
  the first time ('17.1.1, 17.2.1 - 17.2.3, 17.3.1 - 17.3.2, 17.5.1 - 17.5.6,
  17.6.1 - 17.6.4, 17.7.1 - 17.7.5, 17.8.1, 17.9.1 - 17.9.5 (L1)').

### Fixed
- Regression suite: a launcher test whose typed answers slipped could send
  the synthetic fleet (pseudonymized) to the real Gemini with the developer's
  `GEMINI_API_KEY`. The suite now runs with a fake key and the AI endpoint on a
  dead local port, and fails if a run leaves a file in the project folder.
- Guided menu: adding the AI summary after a report downloaded the CISA KEV
  and LOLDrivers catalogs a second time. The AI run now reuses the copies kept
  next to the report (`<report>_kev.json` with `-KevFile`, `<report>_drivers.json`
  with the new `-DriversFile`), so nothing is downloaded again and the summary
  works on the same data as the report. `-DriversFile` also takes the original
  drivers.json from www.loldrivers.io.
- A list of rules in a finding ("CIS 2.3.7.5, 2.3.7.6") had only its first
  number translated to the host's benchmark; every number is now.
- Windows LAPS configured through Group Policy was not seen: the collector read
  `HKLM\SOFTWARE\Policies\Microsoft Windows\LAPS`, which Windows LAPS does not
  use, so such hosts got a false "LAPS not configured" (High). It now reads the
  Windows LAPS policy roots in the order Windows does (CSP
  `HKLM\Software\Microsoft\Policies\LAPS`, Group Policy
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`, local
  configuration) and uses the first one that holds a value.
- AI step: a CIS rule number preceded by the benchmark name ("CIS Server 2022
  2.3.5.2") was pseudonymized as an IP address in the prompt.
- `null_session_access` no longer flags the LSARPC, NETLOGON and SAMR pipes on
  a domain controller, where CIS (2.3.10.6, DC only) expects them. New
  collector field `hardening.nullSessionPipesNonDcCount` (still a count, never
  the names); older snapshots keep the previous behaviour.

### Changed
- `service_binary_writable` (folder writable, program not): the finding now
  says a planted DLL *can* be loaded if the program looks for one in its
  folder, and that this is not checked, instead of saying it *is* loaded.
  Severity unchanged (Medium, High when non-admins can start the service).
- README "Known limitations": the user rights check is described as it now
  works (judged on every role, against the CIS benchmark of that role), the
  GPO point is renamed "Effective settings only, no GPO comparison", and the
  STIG layer is said to judge registry rules only.
- The analyzer writes its output to a `.\output` folder by default instead of
  the current directory. A new `-OutDir` sets the folder; a `-OutHtml` / `-OutCsv`
  / `-OutJsonl` / `-OutRemediation` given as a bare file name lands there, while a
  name with a folder or an absolute path is used exactly as given (the folder is
  created if missing). The guided menu defaults its report path to `.\output` to
  match. The collector is unchanged: it still defaults to a temporary folder
  (its output describes the machine and must not land in the working tree) and
  already takes `-OutDir`.
- The HTML report has a new look (the "keycap" theme): a warm paper
  background, ink-black 3px borders and hard offset shadows on every panel,
  a red accent and mono uppercase labels. Self-contained as before (system
  fonts, no web fonts or external resources), the layout and every section are
  unchanged, and it prints without the shadows. The chart palette was retuned
  to match.
- `COVERAGE.md` no longer names the external projects its rule data is derived
  from; that attribution lives in `README.md` and `LICENSE`.
- AI step: the default Gemini model is now `gemini-3.8-flash` (stable;
  `gemini-3.7-flash` is no longer listed by Google). `-Model` still picks
  another one.
- CIS Windows 11 Enterprise Benchmark v3.0.0 coverage audit (Phase 1 of a
  broader baseline-expansion effort): five existing checks already judged a
  CIS rule without saying so in the catalog's `Cis` field, so they were missing
  from `COVERAGE.md`'s CIS column and from any gap analysis against the
  benchmark. Annotated `print_point_and_print_weak` (18.7.8, 18.7.10, 18.7.11),
  `defender_protection_features_off` (18.10.42.5.2, 18.10.42.10.1,
  18.10.42.10.4), `cmdline_audit_off` (18.9.3.1), `llmnr_enabled` (18.6.4.3),
  and confirmed `winrm_insecure_auth` already covers all five WinRM rules
  (18.10.88.1.1-.1.3, .2.1, .2.3), not just the two its `Cis` range notation's
  endpoints suggested. No behavior change.
- `service_should_be_disabled` now also recognizes `BTAGService` (CIS 5.1,
  Bluetooth Audio Gateway) and `bthserv` (CIS 5.2, Bluetooth Support) - both
  Level 2, the two services below the already-covered 5.3-5.44 Level 1 range.
  Reuses the existing service-disable check; no new collector field.

## [1.1] - 2026-10-08
### Added
- **DISA STIG layer**: eight checks (`stig_windows10`, `stig_windows11`, `stig_defender`,
  `stig_firewall`, `stig_edge`, `stig_chrome`, `stig_firefox`, `stig_office`)
  that judge 638 registry rules (Windows 10 V3R6, Windows 11 V2R7, Defender V2R8, Firewall V2R2,
  Edge V2R5, Chrome V2R11, Firefox V6R7, Office 365 ProPlus V3R5), one finding
  per rule that differs. A value that is not configured counts. The data is
  `data\stig-catalog.json`, built by `tools\Convert-PowerStigData.ps1` from
  Microsoft PowerSTIG (MIT); the collector has a new `stig` section that reads
  exactly those values (HKLM, and the HKU hives of signed-in users for the
  per-user Office rules). Each Windows version is judged against its own STIG:
  a Windows 10 host against the Windows 10 STIG, a Windows 11 host against the
  Windows 11 one, a server against neither. Browser and Office rules apply only when the product
  is installed. `-SkipStig` leaves them out; the launcher asks.
- Seven more checks: `asr_other_rules_not_blocking` (13 more Microsoft ASR
  rules), `defender_protection_features_off` (behavior monitoring, downloaded
  files, script scanning, cloud protection, block at first sight),
  `hvci_off`, `powershell_module_logging_off`, `schannel_legacy_crypto_enabled`
  (SSL/TLS 1.0/1.1 and RC4/DES/3DES/NULL explicitly enabled),
  `ldap_server_signing_off` (domain controllers) and
  `print_point_and_print_weak` (PrintNightmare condition). New collector
  fields: Defender MAPS / block at first sight / script scanning, SCHANNEL,
  NTDS LDAP signing, Point and Print.
- `tools\New-CoverageDoc.ps1` writes `COVERAGE.md` from the catalog.
- New category "DISA STIG" in the report.
- Compliance pie charts at the top of the report: DISA STIG rules judged versus
  failed, and CIS-based checks applicable versus fired.
- `-HideCis` and `-HideStig` keep those findings out of the HTML listing (the
  charts still count them; CSV and JSON Lines keep them). The launcher asks.
- `-AiIncludeStig`: the STIG findings stay out of the Gemini prompt unless you
  ask for them, because hundreds of findings per host can make the request time
  out. The launcher asks, with that warning.
- Progress cursor (`|/-\`) in the collector and the analyzer for the steps
  that take time (collecting sections, reading snapshots, analyzing hosts,
  writing reports, preparing the AI prompt). It moves at each step, drawn only
  on an interactive console, so an EDR session or a log gets no extra output.
- The compliance charts sit right under the score cards.
- README: new summary and features sections; MooseAlto references removed.
- **Pending Windows updates** (Collect-HostSnapshot.ps1 -CheckUpdates, opt-in): the Windows Update Agent searches for missing software updates (it contacts the WSUS server set by policy or Microsoft Update) and the check updates_pending reports each one, rated by Microsoft severity. The launcher asks and names the address.
- **Installed software** (new collector section software, always collected) listed in the report, with pie charts by publisher.
- **CISA KEV** (-KevFile or -KevOnline): installed software is matched to the Known Exploited Vulnerabilities catalog by vendor and product name (kev_software_match, new category Software). The catalog has no version ranges, so a finding is a lead to verify. -KevOnline makes one GET to www.cisa.gov and keeps a copy next to the report; the launcher asks and names the address. The program name in the finding is tokenized for the AI step.
- Charts: missing updates by severity, software and the KEV catalog.
- `service_binary_writable` is clearer and sharper: a folder-only finding now says the program itself is not writable but a DLL can be planted next to it, and the collector reads who may start the service (the SERVICE_START right in its security descriptor, administrators and SYSTEM only: otherwise it is unknown). A writable service folder that non-admin users can start is High instead of Medium.
- **service_path_ancestor_control**: a service program under a folder that a non-administrator owns or has full control of (the folder itself or any folder above it up to the drive root, outside the Windows directory). High when everyone has that control on a LocalSystem service, Medium otherwise; members of the local Administrators group are not reported. The collector reads the owner and the permission-changing rights of each parent folder (read-only, cached).
- Fix: the text of a service finding under ProgramData contained a drive path, which made the AI leak check refuse to send the prompt. The text no longer has one, and a test covers it.
- Fix: `service_path_ancestor_control` fired on almost every service, with blank text ("...has  on..."). Two bugs: a leading comma on an already-built array in the collector (`return , $res`) wrapped it as a single element instead of returning it as-is, so the analyzer read .kind/.sid/.rights off the wrong object; and an empty array deep inside the snapshot could serialize as a bare `null` instead of `[]`. Both are fixed (the collector now normalizes `writableBy`/`ancestorControl` to `[]` when empty, and `Import-HostSnapshot` does the same for snapshots collected before this fix); members of the local Administrators group are correctly excluded, verified against a real run.
- Fix: a writable-file/folder finding could show an unreadable raw number (e.g. `-536805376`) instead of a permission name, whenever an ACE used the raw GENERIC_READ/WRITE/EXECUTE/ALL bits rather than the specific rights .NET's `FileSystemRights` enum names (seen on a real inherit-only `Authenticated Users` ACE an installer had written). The collector now decomposes those bits into readable names (`GenericRead, GenericWrite, GenericExecute, Delete`); detection and severity were already correct, only the detail text was wrong.

### Changed
- `-PerHost` writes one HTML report per host next to the fleet report
  (`<report>_<HOST>.html`). The guided menu asks for it (default yes) only when
  the snapshot folder holds more than one host.
- Several snapshots of one host now print a single line ("N snapshots, using
  the newest ...") instead of one "using the newer snapshot" line per file.

## [1.0] - 2026-10-07
First release.

### Collecting
- `Collect-HostSnapshot.ps1`, one self-contained, read-only collector for
  Windows PowerShell 5.1 and 7. It is made to be uploaded as an EDR cloud
  script and run through Real Time Response as SYSTEM, and it leaves a zip.
  It reads the host and OS, updates, Microsoft Defender, BitLocker, Secure
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
- `-AiDryRun` shows the exact prompt and sends nothing. The prompt and the
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
