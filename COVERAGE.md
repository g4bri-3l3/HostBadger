# HostBadger coverage

Every check in `lib\Checks.ps1`, generated from the catalog (87 checks). Severity is the default; a few findings raise or lower it (the check's description in the report says when). Roles: W workstation, S server, DC domain controller.

The CIS column gives the rule number in the *CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0* and its profile level (L1 corporate, L2 high security). Rule numbers and expected values were taken from the MIT-licensed [ansible-lockdown/Windows-11-CIS](https://github.com/ansible-lockdown/Windows-11-CIS) role; the descriptions are HostBadger's own. A check is a read-only comparison of the host's setting with the rule; it is not a certification of conformity, and the benchmark covers many more settings (most of the administrative templates, for instance) than HostBadger reads.

The last column says whether HostBadger can write a remediation script for the check (`-OutRemediation`): one setting, the expected value, reversible, previewed by default and with a rollback file. `no` means the fix needs a decision, carries a risk, or is an upgrade: follow the remediation text in the report.

## Credential Protection

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `lsa_not_protected` | Medium | T1003.001 |  | W, S, DC | no | LSASS not running as a protected process |
| `credential_guard_off` | Medium | T1003.001 |  | W, S | no | Credential Guard not running |
| `wdigest_cleartext` | High | T1003.001 | 18.4.8 (L1) | W, S, DC | yes | WDigest stores cleartext passwords |
| `cached_logons_high` | Low | T1003.005 | 2.3.7.7 (L2) | W, S | yes | Many domain logons cached |
| `lm_hash_stored` | High | T1003 | 2.3.11.5 (L1) | W, S, DC | yes | LM hashes stored |
| `ntlm_weak_lmcompat` | Medium | T1557.001 | 2.3.11.7 (L1) | W, S, DC | yes | LM / NTLMv1 not refused |
| `anonymous_sam_enum` | Medium | T1087.001 | 2.3.10.2 (L1) | W, S, DC | yes | Anonymous enumeration of accounts allowed |
| `ntlm_min_session_security_weak` | Low | T1557.001 | 2.3.11.9, 2.3.11.10 (L1) | W, S, DC | yes | NTLM session security below NTLMv2 with 128-bit encryption |
| `anonymous_shares_enum` | Low | T1135 | 2.3.10.3 (L1) | W, S, DC | yes | Anonymous enumeration of accounts and shares allowed |
| `everyone_includes_anonymous` | Medium | T1087 | 2.3.10.5 (L1) | W, S, DC | yes | Everyone permissions apply to anonymous users |
| `autologon_enabled` | Medium | T1552.002 | 18.5.1 (L1) | W, S, DC | no | Automatic logon configured |
| `lsa_weak_auth_options` | Medium | T1557 | 2.3.11.2, 2.3.11.3 (L1) | W, S, DC | yes | LocalSystem NULL session fallback or PKU2U online identities allowed |

## Antivirus

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `defender_realtime_off` | High | T1562.001 | 18.10.42.10.2 (L1) | W, S, DC | yes | Defender real-time protection off |
| `defender_tamper_off` | Medium | T1562.001 |  | W, S, DC | no | Defender tamper protection off |
| `defender_signatures_stale` | Medium | T1562.001 |  | W, S, DC | no | Defender signatures out of date |
| `defender_exclusion` | Low | T1562.001 |  | W, S, DC | no | Defender exclusion |
| `asr_standard_rules_missing` | Medium | T1003.001 | 18.10.42.6.1.1 (L1) | W, S, DC | no | Standard ASR rules not in block mode |
| `smartscreen_off` | Medium | T1204 | 18.10.75.2.1 (L1) | W, S, DC | yes | Microsoft Defender SmartScreen turned off by policy |
| `defender_network_protection_off` | Medium | T1189 | 18.10.42.6.3.1 (L1) | W, S, DC | yes | Defender Network Protection not enabled |
| `defender_pua_off` | Low | T1204.002 | 18.10.42.16 (L1) | W, S, DC | yes | Defender blocking of potentially unwanted apps off |
| `edr_agent_stopped` | High | T1562.001 |  | W, S, DC | no | EDR agent installed but not running |
| `edr_expected_missing` | High | T1562.001 |  | W, S, DC | no | Expected EDR agent not found |
| `edr_not_found` | Low | T1562.001 |  | W, S, DC | no | No EDR or endpoint protection agent found |

## Disk and Boot

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `bitlocker_os_volume_off` | High | T1005 |  | W, S, DC | no | Operating system volume not encrypted |
| `bitlocker_tpm_only` | Low | T1005 |  | W | no | BitLocker without pre-boot PIN |
| `bitlocker_data_volume_off` | Low | T1005 |  | W, S, DC | no | Fixed data volume not encrypted |
| `secure_boot_off` | Medium | T1542.003 |  | W, S, DC | no | Secure Boot off |

## Network Exposure

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `smb1_server_enabled` | High | T1210 | 18.4.4 (L1) | W, S, DC | yes | SMBv1 server enabled |
| `smb_server_signing_not_required` | Medium | T1557.001 | 2.3.9.2 (L1) | W, S, DC | yes | SMB server signing not required |
| `smb_client_signing_not_required` | Low | T1557.001 | 2.3.8.1 (L1) | W, S, DC | yes | SMB client signing not required |
| `llmnr_enabled` | Medium | T1557.001 |  | W, S, DC | yes | LLMNR not disabled |
| `netbios_enabled` | Low | T1557.001 |  | W, S, DC | no | NetBIOS over TCP/IP enabled |
| `firewall_profile_disabled` | High | T1562.004 |  | W, S, DC | yes | Windows Firewall profile disabled |
| `firewall_default_inbound_allow` | High | T1562.004 |  | W, S, DC | yes | Firewall allows inbound by default |
| `firewall_drop_logging_off` | Low | T1562.004 |  | W, S, DC | yes | Dropped packets not logged |
| `risky_listener` | Medium | T1021 |  | W, S, DC | no | Risky service listening on the network |
| `smb_insecure_guest_auth` | Medium | T1021.002 | 18.6.8.1 (L1) | W, S, DC | yes | Insecure SMB guest logons allowed |
| `ldap_client_signing_off` | Medium | T1557 | 2.3.11.8 (L1) | W, S, DC | yes | LDAP client signing disabled |
| `null_session_access` | Medium | T1135 | 2.3.10.6, 2.3.10.9, 2.3.10.11 (L1) | W, S, DC | yes | Shares or pipes reachable without authentication |
| `secure_channel_unprotected` | Medium | T1557 | 2.3.6.1 - 2.3.6.6 (L1) | W, S, DC | yes | Domain secure channel not protected |
| `smb_plaintext_password` | High | T1557 | 2.3.8.3 (L1) | W, S, DC | yes | Unencrypted passwords sent to third-party SMB servers |
| `winrm_insecure_auth` | Medium | T1021.006 | 18.10.88.1.1 - 18.10.88.2.3 (L1) | W, S, DC | yes | WinRM allows Basic, Digest or unencrypted traffic |
| `smb1_client_driver_enabled` | Low | T1210 | 18.4.3 (L1) | W, S, DC | yes | SMBv1 client driver enabled |
| `ip_stack_hardening_gaps` | Low | T1557 | 18.5.2, 18.5.3, 18.5.5 (L1) | W, S, DC | yes | IP stack accepts source routing or ICMP redirects |

## Remote Access

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `rdp_nla_disabled` | High | T1021.001 | 18.10.56.3.9.4 (L1) | W, S, DC | yes | RDP without Network Level Authentication |
| `rdp_enabled_workstation` | Low | T1021.001 | 18.10.56.3.2.1 (L2) | W | no | RDP enabled on a workstation |
| `rdp_policy_gaps` | Low | T1021.001 | 18.10.56.3.9.1 - 18.10.56.3.9.5, 18.10.56.3.3.3 (L1) | W, S, DC | yes | Remote Desktop policy weaker than the baseline |

## Local Accounts

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `builtin_admin_enabled` | Medium | T1078.003 |  | W, S | no | Built-in Administrator enabled |
| `guest_enabled` | High | T1078.001 | 2.3.1.2 (L1) | W, S, DC | yes | Guest account enabled |
| `local_admin_member` | Medium | T1078.003 |  | W, S | no | Extra member of local Administrators |
| `local_account_password_not_required` | High | T1078.003 |  | W, S | no | Enabled local account allowed an empty password |
| `local_account_password_never_expires` | Low | T1078.003 |  | W, S | no | Local account password never expires |
| `laps_not_configured` | High | T1078.003 |  | W, S | no | LAPS not configured |
| `uac_disabled` | High | T1548.002 | 2.3.17.6 (L1) | W, S, DC | yes | UAC disabled |
| `uac_admin_no_prompt` | Medium | T1548.002 | 2.3.17.2 (L1) | W, S, DC | yes | UAC elevates administrators without asking |
| `remote_uac_token_filter_off` | Medium | T1550.002 | 18.4.1 (L1) | W, S | yes | Remote UAC filtering disabled for local accounts |
| `blank_password_network_logon` | Medium | T1078.003 | 2.3.1.3 (L1) | W, S, DC | yes | Blank passwords allowed outside the console |
| `force_guest_sharing_model` | High | T1078.001 | 2.3.10.12 (L1) | W, S, DC | yes | Network logons are forced to the Guest account |
| `uac_hardening_gaps` | Low | T1548.002 | 2.3.17.1, 2.3.17.4, 2.3.17.5, 2.3.17.7, 2.3.17.8 (L1) | W, S, DC | yes | UAC settings weaker than the baseline |
| `password_policy_weak` | Medium | T1110 | 1.1.1 - 1.1.5, 1.1.7 (L1) | W, S | no | Local password policy weaker than the baseline |
| `account_lockout_weak` | Medium | T1110 | 1.2.1, 1.2.2, 1.2.4 (L1) | W, S | no | Account lockout missing or too lenient |
| `deny_logon_rights_missing` | Low | T1078.001 | 2.2.16 - 2.2.20 (L1) | W | no | Guests or local accounts not denied network or remote logon |

## Privilege Escalation

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `always_install_elevated` | High | T1548 |  | W, S, DC | yes | AlwaysInstallElevated enabled |
| `service_unquoted_path` | Medium | T1574.009 |  | W, S, DC | no | Service path with spaces and no quotes |
| `service_binary_writable` | High | T1574.010 |  | W, S, DC | no | Service program writable by users |
| `task_binary_writable` | High | T1053.005 |  | W, S, DC | no | Privileged scheduled task runs a user-writable program |
| `autorun_writable` | High | T1547.001 |  | W, S, DC | no | Machine-wide autorun points to a user-writable program |
| `spooler_on_dc` | Medium | T1187 |  | DC | yes | Print Spooler running on a domain controller |
| `user_rights_excessive` | Medium | T1134 | 2.2.1 - 2.2.39, Level 1 rights (L1) | W | no | User right granted to more principals than the baseline |

## Logging

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `audit_policy_gaps` | Medium | T1562.002 |  | W, S, DC | no | Audit policy gaps |
| `cmdline_audit_off` | Medium | T1562.002 |  | W, S, DC | yes | Command lines missing from process events |
| `powershell_scriptblock_logging_off` | Medium | T1562.002 | 18.10.86.1 (L2) | W, S, DC | yes | PowerShell script block logging off |
| `powershell_v2_enabled` | Medium | T1562.010 |  | W, S, DC | yes | PowerShell 2.0 engine installed |
| `security_log_small` | Low | T1070.001 | 18.10.25.2.2 (L1) | W, S, DC | yes | Security event log too small |
| `event_logs_small` | Low | T1070.001 | 18.10.25.1.2, 18.10.25.4.2 (L1) | W, S, DC | yes | Application or System event log too small |
| `powershell_transcription_off` | Low | T1562.002 | 18.10.86.2 (L2) | W, S, DC | yes | PowerShell transcription off |

## Patching

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `os_unsupported` | High | T1190 |  | W, S, DC | no | Windows version out of support |
| `os_support_ending` | Low | T1190 |  | W, S, DC | no | Windows support ends soon |
| `updates_stale` | High | T1190 |  | W, S, DC | no | No update installed recently |
| `wu_auto_updates_disabled` | Medium | T1190 | 18.10.92.2.1 (L1) | W, S, DC | yes | Automatic Windows Update turned off by policy |

## System Hardening

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `autoplay_enabled` | Low | T1091 | 18.10.7.1 - 18.10.7.3 (L1) | W, S, DC | yes | AutoPlay / AutoRun not fully turned off |
| `inactivity_lock_missing` | Low |  | 2.3.7.4 (L1) | W, S, DC | yes | No machine inactivity lock within 15 minutes |
| `logon_banner_missing` | Low |  | 2.3.7.5, 2.3.7.6 (L1) | W, S, DC | no | No logon warning message |
| `interactive_logon_gaps` | Low | T1087 | 2.3.7.1, 2.3.7.2 (L1) | W, S, DC | yes | Logon screen shows the last user or skips CTRL+ALT+DEL |
| `service_should_be_disabled` | Low | T1021 | 5.3 - 5.44, Level 1 services (L1) | W | no | Service the baseline says to disable is running or automatic |
| `sehop_disabled` | Medium | T1203 | 18.4.6 (L1) | W, S, DC | yes | SEHOP exploit mitigation disabled |
| `safe_dll_search_off` | Medium | T1574.001 | 18.5.9 (L1) | W, S, DC | yes | Safe DLL search mode disabled |
