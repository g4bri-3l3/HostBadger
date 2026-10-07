# Changelog

All notable changes to HostBadger are written down here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are numbered major.minor: a new minor for new features and fixes, a
new major if the snapshot or the JSON Lines format ever breaks.

## [1.5] - 2026-10-07
### Changed
- Fix scripts now live in the report. Under each check in "Findings by check"
  there is a **Fix script** block, in plain PowerShell with a Copy button, for
  every check that has a safe fix. Hosts that need exactly the same changes
  share one block, and a note says how many of the check's findings it
  covers. The script prints "old -> new" for each setting, changes nothing
  until you set `$Apply = $true`, and ends with an Undo line.
- Nothing is written to a folder by default any more. `-OutRemediation` (one
  file per host, with a rollback file) is still there if you want it, and the
  launcher no longer asks about it.
- Inside, the fixes are now plain data (`Get-RemediationActions`) and are
  drawn two ways: as the snippets in the report and as the lines of the
  per-host file.
### Added
- The launcher scans for snapshots by itself. When you analyze, it looks in a
  `snapshots` folder next to where you are, then in the current folder, then
  in the `snapshots` folder next to the scripts. It lists what it finds (host,
  collection time in UTC, size, and a note on an older snapshot of a host that
  a folder run ignores) and you press Enter for the whole folder, type a
  number for one snapshot, or type a path. If it finds nothing, it asks for a
  path as before.
- A short animated tour of the demo report (`examples/demo_report.gif`),
  shown at the top of the README.
- Regression tests for the fix blocks. There is one block under every check
  that has a fix and none under the others, every block parses and previews by
  default, and the registry blocks really run in a private `HKCU` branch: the
  preview creates nothing, and `$Apply = $true` sets every value the script
  promised.

## [1.4] - 2026-10-07
### Added
- Remediation scripts (`lib/Remediation.ps1`, `-OutRemediation <folder>`): one
  `remediate_<host>.ps1` per host for the findings that have a safe, standard
  fix. That is 51 check types, and the "Fix script" column in `COVERAGE.md`
  says which. A fix only qualifies if it is one setting, set to the value the
  benchmark expects, easy to undo, and needs no decision from the organization.
- The script previews unless you pass `-Apply`. Before each change it writes
  the old value to a rollback file (rewritten after every change, and
  `-Restore <file> -Apply` undoes it). It stops on the wrong computer name,
  needs administrator rights for `-Apply`, can be run twice safely, and is
  never run by HostBadger.
- The report got a "Remediation scripts" section and a line under each check.
  JSON Lines gained `fix_available`, and the launcher asks about scripts.
- Regression tests: the generated scripts parse, contain no download, hidden
  code or deletion, touch only HKLM paths and preview by default. Every
  promised fix produces a line. The registry engine runs for real in a private
  `HKCU` branch: preview changes nothing, apply sets the values, a second
  apply does nothing, restore brings back the old values and removes the ones
  that were created, and another computer is refused.
### Changed
- The launcher offers the AI summary right after the report is written
  ("Report ready", then N / D / S / C) for options 2 and 3. Before, it was a
  y/N question hidden among the analysis questions, and it was easy to miss.
  Choosing D, S or C runs the analysis again with the AI step on, so the
  report on disk gets the AI section. Option 4 still asks first.
- Whatever a sub-script prints can no longer be mistaken for a value the menu
  needs (`Out-Host`). The regression now drives the launcher with typed
  answers.
- `Test-HostBadgerSafety.ps1` reviews what HostBadger really runs: the
  scripts in the folder and in `lib\`. A script in another subfolder, such as a
  copy of a different tool, is listed as "not reviewed" and no longer fails the
  verdict. With a copy of IDWolf inside, it used to fail with 139 problems.
  The regression covers both cases.
### Left out on purpose
- Anything that needs a decision or carries a risk: banner text, allowed
  administrators, password and lockout policy, services, NetBIOS, ASR, audit
  policy, Defender exclusions, BitLocker, Credential Guard, LSA protection,
  LAPS, user rights, tasks and autoruns. For these the written remediation
  stays.

## [1.3] - 2026-10-07
### Added
- The local security policy, read through `secedit /export` (collector 1.2,
  section `securityPolicy`). Four new checks follow CIS rules 1.1.x, 1.2.x and
  2.2.x of the Windows 11 Enterprise benchmark v3.0.0, which brings the total
  to 84:
  - `password_policy_weak`,
  - `account_lockout_weak`,
  - `user_rights_excessive` (Level 1 rights, workstations only; debug, act as
    part of the OS, create a token, enable delegation, load drivers, take
    ownership and credential manager access count as High),
  - `deny_logon_rights_missing`.
- The export goes to a temporary INF file and a log, both deleted right away.
  Without administrator or SYSTEM rights the section fails and the four checks
  are listed as not evaluated.
- `Test-HostBadgerSafety.ps1` accepts `secedit.exe` with `/export` only.
  `/configure`, `/import`, `/analyze`, `/generaterollback` and `/validate` fail
  the review, and the regression proves it with a tampered collector.
- Regression tests: the INF parser, cut out of the collector and run on a
  UTF-16 sample; a compliant policy on the hardened server and the laptop;
  domain controllers skipped.
### Changed
- The BitLocker checks understand Windows Home. The OS volume is still High,
  but the finding points to Device encryption or an upgrade. "TPM without PIN"
  is not raised, because a PIN can't be set on Home. The data volume finding
  says that BitLocker isn't available there.
### Fixed
- `updates_stale` could not see an unpatched Windows on any host with
  Defender. The "last update installed" date came from the Windows Update
  history, and that history also lists the daily Defender definitions, the
  antimalware platform, the monthly malware-removal tool, and .NET,
  PowerShell and store updates. A Windows 11 23H2 Home with no cumulative
  update since 20 November 2025 showed an update from the day before.
- The check now uses the Windows hotfix list, which records the updates of the
  operating system itself in any language. It falls back to the update history
  only when no hotfix has a date, and the finding says which source it used.
- The collector also drops the Defender, platform and malware-removal entries
  from the history date. It recognises them by KB number, because their titles
  are localized.
- Snapshots taken with an older collector keep the old history date. The
  check ignores it whenever the hotfix list has dates.
- In the AI prompt, CIS rule numbers (and lists of them, like
  `CIS 2.3.7.5, 2.3.7.6`) were mistaken for IP addresses and turned into
  `IP-n` tokens. They are left alone now, and the leak check ignores them too.
- The author of a scheduled task is no longer treated as an account name. On a
  host with a task authored by `Microsoft`, that had turned `Microsoft Windows`
  into `USER-1 Windows`. The regression checks both fixes, and also that a real
  address is still caught.

## [1.2] - 2026-10-07
### Added
- 30 baseline checks, 80 in all, that follow rules of the CIS Microsoft Windows
  11 Enterprise Benchmark v3.0.0. The rule numbers and expected values come
  from the MIT-licensed ansible-lockdown/Windows-11-CIS role. There is a new
  category, System Hardening, and the rest land in the existing categories.
- Every finding quotes its rule. The report, the findings CSV (a `Cis` column)
  and the JSON Lines (a `cis` field) carry it, 18 existing checks now name
  their rule too, and `COVERAGE.md` has a CIS column.
- Collector 1.1 reads a new `hardening` section, using registry values only.
  It keeps the number of anonymous shares and pipes but never their names. It
  records only whether an AutoLogon password is stored, never the password. It
  also reads the Application and System log sizes and Defender Network
  Protection. A snapshot without the section lists the new checks as not
  evaluated.
- The new checks cover: insecure SMB guest logons, LDAP client signing, NTLM
  session security, anonymous share enumeration, Everyone includes anonymous,
  blank passwords, ForceGuest, anonymous pipes and shares, the domain secure
  channel, clear-text SMB passwords, WinRM Basic, Digest and unencrypted
  traffic, the SMBv1 client driver, IP source routing and ICMP redirects, RDP
  policy gaps, AutoPlay, automatic logon, the inactivity lock, the logon
  message, last user shown, other UAC settings, Automatic Updates disabled,
  SmartScreen, Application and System log size, PowerShell transcription,
  the services the Level 1 baseline disables (workstations), Defender Network
  Protection and PUA, SEHOP, safe DLL search, and PKU2U and NULL session
  fallback.
### Changed
- The AI step keeps stock service names from the CIS list readable instead of
  replacing them with tokens.

## [1.1] - 2026-10-07
### Added
- An optional AI step (`lib/AI.ps1`), adapted from IDWolf. With `-SendToAI`,
  HostBadger asks Gemini for an executive summary, a remediation plan in work
  packages, quick wins, monitoring ideas (with event IDs), the hosts to work on
  first, PowerShell snippets for routine fixes and a triage across the fleet.
  The answer is added to the report in a section marked as AI-written.
- The related options: `-AiConfirm` shows the prompt and asks y/N,
  `-AiDryRun <file>` writes the exact prompt and sends nothing, and there are
  `-ApiKey` (or `GEMINI_API_KEY`), `-Model` and `-AiMaxAttempts`. It is off
  unless you ask. Without a flag nothing is built or sent, and HostBadger
  never prompts.
- Everything that identifies something is replaced by a token before sending:
  hosts, FQDNs, domains, accounts, groups, SIDs, paths, the names of services,
  tasks, autoruns and adapters, listener processes and addresses. Names that
  could be ordinary words are matched with their exact case. The collector's
  error messages never leave the machine. A leak check refuses to send if a
  real name, SID, UNC path or drive path is left.
- The prompt and the reply are kept next to the report
  (`_ai_prompt.txt` and `_ai_response.json`), still with tokens. Anything in
  the reply about a check that didn't fire, or about an unknown host token, is
  dropped.
- `Start-HostBadger.ps1`, a guided menu: collect this machine, analyze a file,
  a zip or a folder, collect and analyze, add an AI summary, run the safety
  review.
- Regression tests: no real name in the prompt or the request body, the leak
  check, no send without a flag or a key, an end-to-end run against a local
  mock endpoint, and a safety review that fails on network code in the
  collector.
### Changed
- `Test-HostBadgerSafety.ps1` allows network code and the Gemini address only
  in `lib/AI.ps1`. `Start-Sleep` is allowed only there, and `Read-Host` only in
  the two entry points. The collector stays offline, and anything else fails.

## [1.0] - 2026-10-06
### Added
- `Collect-HostSnapshot.ps1`, one self-contained, read-only collector for
  Windows PowerShell 5.1 and 7. It is ready to be uploaded as an EDR cloud
  script and run through Real Time Response as SYSTEM. It reads the host and
  OS, updates (hotfixes and the Windows Update history), Microsoft Defender
  (status, exclusions, ASR rules), BitLocker, Secure Boot, LSA and credential
  protection, SMB, LLMNR, NetBIOS, firewall profiles, listening ports with
  their process, RDP, local accounts and the local Administrators group (ADSI,
  by SID), LAPS, UAC, PowerShell logging and the 2.0 engine, the audit policy
  (`auditpol /backup`, numeric values in any language), services, scheduled
  tasks and machine-wide autoruns, with the ACL of the programs they start.
- Each section is collected on its own, and a failure is recorded instead of
  stopping the run. Arguments that look like passwords are masked. The output
  is a zip ready for `get`.
- `HostBadger.ps1`, the offline analyzer, for one snapshot, a zip or a folder
  of them (the newest snapshot per host counts). It has 50 checks in nine
  categories and knows the role of the host (workstation, server or domain
  controller). A check whose data is missing, whose Defender is in passive mode
  or whose ACLs were skipped is listed as "not evaluated".
- Its outputs are an HTML report (hosts table, coverage gaps, findings by check
  with remediation and MITRE links, a filterable table), a findings CSV, and
  JSON Lines for a SIEM with a stable `finding_id` and one summary per host. It
  also has `-CompareTo`, `-ExceptionsFile`, `-AllowedAdmins` and thresholds.
  The score and grade work as in IDWolf.
- A Windows lifecycle table (Windows 10, Windows 11, Windows Server 2012 to
  2025, by build and edition) behind `os_unsupported` and `os_support_ending`.
- `Test-HostBadgerSafety.ps1` reads the scripts without running them. It fails
  on any command outside the reviewed list, any system change, auditpol with
  anything other than /get or /backup, ADSI or COM used for more than reading,
  hidden code and network access.
- A synthetic fleet (`tests/New-SyntheticHostSnapshot.ps1`, five scenarios),
  `tests/Run-Regression.ps1` (exact counts, every check fires, the "not
  evaluated" rule, roles, determinism, zip input, exceptions, comparison, JSON
  Lines, the documentation and the safety review) and `examples/` with the demo
  report.
