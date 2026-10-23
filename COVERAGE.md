# HostBadger coverage

Every check in `lib\Checks.ps1`, generated from the catalog (167 checks, of which 13 cover the 1475 registry rules of the DISA STIGs listed at the end). Severity is the default; a few findings raise or lower it (the check's description in the report says when). Roles: W workstation, S server, DC domain controller.

The CIS column gives the rule number in the *CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0* and its profile level (L1 corporate, L2 high security); the descriptions are HostBadger's own. A check is a read-only comparison of the host's setting with the rule; it is not a certification of conformity, and the benchmark covers many more settings (most of the administrative templates, for instance) than HostBadger reads. On Windows 10 and on Windows Server 2022, 2019 and 2016 the findings quote the same setting in that version's CIS benchmark instead (Windows 10 Enterprise v3.0.0, Server 2022 and 2019 v4.0.0, Server 2016 v3.0.0). Checks marked *Server* follow a rule that only the server benchmarks have.

The last column says whether HostBadger can write a remediation script for the check (`-OutRemediation`): one setting, the expected value, reversible, previewed by default and with a rollback file. `no` means the fix needs a decision, carries a risk, or is an upgrade: follow the remediation text in the report.

## Credential Protection

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `lsa_not_protected` | Medium | T1003.001 | 18.9.26.2 (L1) | W, S, DC | no | LSASS not running as a protected process |
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
| `hvci_off` | Low | T1068 |  | W, S | no | Memory integrity (HVCI) not running |
| `dc_security_policy_gaps` | Medium | T1556 | Server 18.9.39.1, 2.3.11.13 (L1) | DC | no | Domain controller is missing a CIS Windows Server security setting |
| `remote_credential_guard_off` | Low | T1550.002 |  | W, S, DC | no | Remote Credential Guard is not in use |
| `unattend_credentials` | High | T1552.001 |  | W, S, DC | no | Password left in a Windows setup answer file |
| `gpp_cpassword_cached` | High | T1552.006 |  | W, S, DC | no | Group Policy Preferences password (cpassword) on the host |
| `powershell_history_secrets` | Medium | T1552.001 |  | W, S, DC | no | PowerShell history holds what looks like a password |
| `service_domain_account` | Medium | T1003.004 |  | W, S, DC | no | Service or task runs as a domain account with a stored password |
| `kerberos_rc4_allowed` | Medium | T1558.003 | 2.3.11.4 (L1) | W, S, DC | no | Kerberos allows RC4 or DES |
| `local_admin_password_shared` | High | T1550.002 |  | W, S | no | Local account password probably shared with other hosts |

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
| `asr_other_rules_not_blocking` | Low | T1204.002 |  | W, S, DC | no | Other attack surface reduction rules not in block mode |
| `defender_protection_features_off` | Medium | T1562.001 | 18.10.42.5.2, 18.10.42.10.1, 18.10.42.10.4 (L1/L2) | W, S, DC | no | Defender protection feature turned off |
| `defender_server_baseline_gaps` | Low | T1562.001 | Server 18.10.43.13.1, 18.10.43.17 (L1) | S, DC | no | Server Defender policy differs from the CIS Windows Server baseline |

## Disk and Boot

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `bitlocker_os_volume_off` | High | T1005 |  | W, S, DC | no | Operating system volume not encrypted |
| `bitlocker_tpm_only` | Low | T1005 |  | W | no | BitLocker without pre-boot PIN |
| `bitlocker_data_volume_off` | Low | T1005 |  | W, S, DC | no | Fixed data volume not encrypted |
| `bitlocker_weak_encryption` | Low | T1005 |  | W, S, DC | no | BitLocker volume uses a weak encryption method |
| `bitlocker_policy_weak` | Medium | T1005 | 18.10.9.x (BitLocker profile) | W, S, DC | no | BitLocker policy weakens the protection of the disks |
| `bitlocker_policy_gaps` | Low | T1005 | 18.10.9.1.1 - 18.10.9.3.15 (BitLocker profile) | W, S, DC | no | BitLocker policy differs from the CIS BitLocker profile |
| `secure_boot_off` | Medium | T1542.003 |  | W, S, DC | no | Secure Boot off |

## Network Exposure

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `smb1_server_enabled` | High | T1210 | 18.4.4 (L1) | W, S, DC | yes | SMBv1 server enabled |
| `smb_server_signing_not_required` | Medium | T1557.001 | 2.3.9.2 (L1) | W, S, DC | yes | SMB server signing not required |
| `smb_client_signing_not_required` | Low | T1557.001 | 2.3.8.1 (L1) | W, S, DC | yes | SMB client signing not required |
| `llmnr_enabled` | Medium | T1557.001 | 18.6.4.3 (L1) | W, S, DC | yes | LLMNR not disabled |
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
| `winrm_insecure_auth` | Medium | T1021.006 | 18.10.88.1.1 - 18.10.88.2.4 (L1/L2) | W, S, DC | yes | WinRM allows Basic, Digest, unencrypted traffic, or an unsafe service configuration |
| `mdns_enabled` | Low | T1557.001 | Server 18.6.4.1 (L1) | W, S, DC | yes | Multicast DNS (mDNS) enabled |
| `firewall_notifications_on` | Low | T1562.004 | 9.1.3, 9.2.3, 9.3.3 (L1) | W, S, DC | yes | Windows Firewall shows notifications when it blocks a program |
| `smb1_client_driver_enabled` | Low | T1210 | 18.4.3 (L1) | W, S, DC | yes | SMBv1 client driver enabled |
| `ip_stack_hardening_gaps` | Low | T1557 | 18.5.2, 18.5.3, 18.5.5 (L1) | W, S, DC | yes | IP stack accepts source routing or ICMP redirects |
| `schannel_legacy_crypto_enabled` | Medium | T1557 |  | W, S, DC | no | Legacy TLS/SSL protocol or weak cipher explicitly enabled |
| `ldap_server_signing_off` | Medium | T1557 | Server 2.3.5.3, 2.3.5.4 (L1) | DC | no | Domain controller does not require LDAP signing or channel binding |
| `dc_netlogon_policy_weak` | High | T1210 | Server 2.3.5.1, 2.3.5.2, 2.3.5.5 (L1) | DC | yes | Domain controller weakens Netlogon or lets Server Operators schedule tasks |
| `smb_server_hardening_gaps` | Medium | T1557 | Server 18.6.7.1, 18.6.8.2 (L1) | S, DC | no | Server does not mandate a minimum SMB dialect or SMB client encryption |
| `server_network_policy_gaps` | Low | T1557 | Server 18.6.4.3 (L2), 18.10.58.2 (L1) | S, DC | no | Server network setting differs from the CIS Windows Server baseline |
| `ldap_client_encryption_weak` | Medium | T1557 | Server 2.3.11.8 (L1) | S, DC | no | LDAP client does not require encryption |
| `webclient_webdav_enabled` | Low | T1187 |  | W, S, DC | no | WebClient (WebDAV) service is enabled |
| `wpad_not_disabled` | Low | T1557.001 |  | W, S, DC | no | WPAD auto-discovery is not disabled |
| `lolbin_outbound_not_blocked` | Low | T1105 |  | W, S, DC | no | System tools used to download payloads can reach the network |
| `root_ca_added` | Medium | T1553.004 |  | W, S, DC | no | Root certificate added outside the Microsoft trusted root program |
| `wifi_profile_insecure` | Medium | T1557 |  | W, S, DC | no | Saved Wi-Fi network without encryption or with WEP |

## Remote Access

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `rdp_nla_disabled` | High | T1021.001 | 18.10.56.3.9.4 (L1) | W, S, DC | yes | RDP without Network Level Authentication |
| `rdp_enabled_workstation` | Low | T1021.001 | 18.10.56.3.2.1 (L2) | W | no | RDP enabled on a workstation |
| `rdp_policy_gaps` | Low | T1021.001 | 18.10.56.3.9.1 - 18.10.56.3.9.5, 18.10.56.3.3.3 (L1) | W, S, DC | yes | Remote Desktop policy weaker than the baseline |
| `remote_access_tool` | Medium | T1219 |  | W, S, DC | no | Remote access tool installed |

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
| `deny_logon_rights_missing` | Low | T1078.001 | 2.2.16 - 2.2.20 (L1) | W, S, DC | no | Guests or local accounts not denied network or remote logon |

## Privilege Escalation

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `always_install_elevated` | High | T1548 |  | W, S, DC | yes | AlwaysInstallElevated enabled |
| `service_unquoted_path` | Medium | T1574.009 |  | W, S, DC | no | Service path with spaces and no quotes |
| `service_binary_writable` | High | T1574.010 |  | W, S, DC | no | Service program writable by users |
| `task_binary_writable` | High | T1053.005 |  | W, S, DC | no | Privileged scheduled task runs a user-writable program |
| `autorun_writable` | High | T1547.001 |  | W, S, DC | no | Machine-wide autorun points to a user-writable program |
| `system_path_writable` | High | T1574.007 |  | W, S, DC | no | Folder of the machine PATH writable by users |
| `program_dir_writable` | Medium | T1574.001 |  | W, S, DC | no | Program installed in a folder users can write |
| `vulnerable_driver_present` | High | T1068 |  | W, S, DC | no | Known vulnerable or malicious driver on the host |
| `driver_blocklist_off` | Medium | T1068 |  | W, S, DC | yes | Microsoft vulnerable driver blocklist turned off |
| `spooler_on_dc` | Medium | T1187 |  | DC | yes | Print Spooler running on a domain controller |
| `user_rights_excessive` | Medium | T1134 | 2.2.1 - 2.2.39, Level 1 rights (L1) | W, S, DC | no | User right granted to more principals than the baseline |
| `service_path_ancestor_control` | Medium | T1574.010 |  | W, S, DC | no | Service program under a folder that a non-administrator controls |
| `service_permissions_weak` | High | T1543.003 |  | W, S, DC | no | Service permissions let non-administrators change or delete it |
| `print_point_and_print_weak` | Medium | T1068 | 18.7.8, 18.7.10, 18.7.11 (L1) | W, S, DC | no | Point and Print allows driver installation without elevation |

## Persistence

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `persistence_wmi_subscription` | High | T1546.003 |  | W, S, DC | no | WMI event subscription runs a command or a script |
| `persistence_registry_hijack` | High | T1546.012 |  | W, S, DC | no | Code planted in a Windows load point |

## Logging

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `audit_policy_gaps` | Medium | T1562.002 | 17.1.1, 17.2.1 - 17.2.3, 17.3.1 - 17.3.2, 17.5.1 - 17.5.6, 17.6.1 - 17.6.4, 17.7.1 - 17.7.5, 17.8.1, 17.9.1 - 17.9.5 (L1) | W, S, DC | no | Audit policy gaps |
| `cmdline_audit_off` | Medium | T1562.002 | 18.9.3.1 (L1) | W, S, DC | yes | Command lines missing from process events |
| `powershell_scriptblock_logging_off` | Medium | T1562.002 | 18.10.86.1 (L2) | W, S, DC | yes | PowerShell script block logging off |
| `powershell_v2_enabled` | Medium | T1562.010 |  | W, S, DC | yes | PowerShell 2.0 engine installed |
| `security_log_small` | Low | T1070.001 | 18.10.25.2.2 (L1) | W, S, DC | yes | Security event log too small |
| `event_logs_small` | Low | T1070.001 | 18.10.25.1.2, 18.10.25.4.2 (L1) | W, S, DC | yes | Application or System event log too small |
| `powershell_transcription_off` | Low | T1562.002 | 18.10.86.2 (L2) | W, S, DC | yes | PowerShell transcription off |
| `powershell_module_logging_off` | Low | T1059.001 |  | W, S, DC | no | PowerShell module logging off |
| `log_forwarding_missing` | Low | T1070.001 |  | W, S, DC | no | Event logs are not sent anywhere |
| `sysmon_missing` | Low | T1562.002 |  | W, S, DC | no | No process telemetry: neither Sysmon nor an EDR |

## Patching

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `os_unsupported` | High | T1190 |  | W, S, DC | no | Windows version out of support |
| `os_support_ending` | Low | T1190 |  | W, S, DC | no | Windows support ends soon |
| `updates_stale` | High | T1190 |  | W, S, DC | no | No update installed recently |
| `wu_auto_updates_disabled` | Medium | T1190 | 18.10.92.2.1 (L1) | W, S, DC | yes | Automatic Windows Update turned off by policy |
| `updates_pending` | Medium | T1190 |  | W, S, DC | no | Windows update available but not installed |
| `reboot_overdue` | Low | T1068 |  | W, S, DC | no | Restart overdue: installed updates are not active |

## System Hardening

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `authenticode_padding_check_off` | Low | T1553.002 |  | W, S, DC | no | Stricter Authenticode signature check not enabled (CVE-2013-3900) |
| `autoplay_enabled` | Low | T1091 | 18.10.7.1 - 18.10.7.3 (L1) | W, S, DC | yes | AutoPlay / AutoRun not fully turned off |
| `inactivity_lock_missing` | Low |  | 2.3.7.4 (L1) | W, S, DC | yes | No machine inactivity lock within 15 minutes |
| `logon_banner_missing` | Low |  | 2.3.7.5, 2.3.7.6 (L1) | W, S, DC | no | No logon warning message |
| `interactive_logon_gaps` | Low | T1087 | 2.3.7.1, 2.3.7.2 (L1) | W, S, DC | yes | Logon screen shows the last user or skips CTRL+ALT+DEL |
| `service_should_be_disabled` | Low | T1021 | 5.1 - 5.44, Level 1 services (L1) | W, S | no | Service the baseline says to disable is running or automatic |
| `sehop_disabled` | Medium | T1203 | 18.4.6 (L1) | W, S, DC | yes | SEHOP exploit mitigation disabled |
| `safe_dll_search_off` | Medium | T1574.001 | 18.5.9 (L1) | W, S, DC | yes | Safe DLL search mode disabled |
| `server_baseline_gaps` | Low | T1078 | Server 2.3.7.8, 2.3.13.1, 18.9.25.2 (L1) | S, DC | yes | Server setting differs from the CIS Windows Server baseline |
| `terminal_services_server_gaps` | Low | T1563.002 | Server 18.10.57.3.2.1 (L2), 18.10.57.3.11.2 (L1) | S, DC | no | Remote Desktop session settings differ from the CIS Windows Server baseline |
| `explorer_motw_bypass` | Medium | T1553.005 | Server 18.10.29.2 (L1) | S, DC | no | Mark of the Web is not applied to files copied from insecure sources |
| `app_installer_policy_gaps` | Low | T1059 | Server 18.10.18.4, 18.10.18.6 (L1), 18.10.18.7 (L2) | S, DC | no | App Installer (winget) is not restricted per the CIS Windows Server baseline |
| `brave_policy_gaps` | Medium | T1189 |  | W, S, DC | no | Brave policy weaker than the Chrome STIG |
| `script_files_execute_on_open` | Medium | T1204.002 |  | W, S, DC | yes | Script files run when they are double-clicked |
| `removable_media_execute_allowed` | Low | T1091 |  | W | no | Programs can run from removable disks |
| `app_control_not_enforced` | Medium | T1204.002 |  | W, S, DC | no | No application control enforced |
| `powershell_clm_off` | Low | T1059.001 |  | W, S, DC | no | PowerShell is not held to Constrained Language Mode |
| `netfx3_enabled` | Low | T1562.010 |  | W, S, DC | no | .NET Framework 3.5 (2.0 and 3.0) is enabled |
| `ie11_enabled` | Medium | T1189 |  | W, S, DC | no | Internet Explorer 11 is enabled |
| `office_macro_settings_weak` | Medium | T1566.001 |  | W, S, DC | no | Office macro settings not enforced by policy |
| `machine_sid_duplicate` | Medium | T1078.003 |  | W, S | no | Machine SID shared with other hosts |
| `config_drift` | Low | T1112 |  | W, S, DC | no | Settings differ from the rest of the fleet |

## Software

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `kev_software_match` | Low | T1190 |  | W, S, DC | no | Installed software with vulnerabilities known to be exploited (CISA KEV) |
| `software_eol` | Medium | T1203 |  | W, S, DC | no | Installed software no longer supported by its vendor |
| `software_cve` | Medium | T1203 |  | W, S, DC | no | Installed software version with known vulnerabilities |
| `software_outdated` | Low | T1203 |  | W, S, DC | no | Installed software behind the latest release of its line |
| `bloatware_installed` | Low | T1176 |  | W, S | no | Preinstalled games, consumer apps or antivirus trials |
| `browser_extension_malicious` | High | T1176 |  | W, S, DC | no | Browser extension removed from the store or known to be malicious |
| `browser_extension_sideloaded` | Medium | T1176 |  | W, S, DC | no | Browser extension installed outside the store |
| `browser_extension_not_allowed` | Medium | T1176 |  | W, S, DC | no | Browser extension not on the approved list |
| `browser_extension_broad_access` | Low | T1176 |  | W, S, DC | no | Browser extension can read and change every website |

## DISA STIG

| ID | Severity | MITRE | CIS | Roles | Fix script | Title |
|---|---|---|---|---|---|---|
| `stig_windows10` | Medium | T1112 |  | W | no | Windows 10 setting differs from the DISA STIG |
| `stig_windows11` | Medium | T1112 |  | W | no | Windows 11 setting differs from the DISA STIG |
| `stig_server2016` | Medium | T1112 |  | S, DC | no | Windows Server 2016 setting differs from the DISA STIG |
| `stig_server2019` | Medium | T1112 |  | S, DC | no | Windows Server 2019 setting differs from the DISA STIG |
| `stig_server2022` | Medium | T1112 |  | S, DC | no | Windows Server 2022 setting differs from the DISA STIG |
| `stig_server2025` | Medium | T1112 |  | S, DC | no | Windows Server 2025 setting differs from the DISA STIG |
| `stig_defender` | Medium | T1562.001 |  | W, S, DC | no | Microsoft Defender Antivirus setting differs from the DISA STIG |
| `stig_firewall` | Medium | T1562.004 |  | W, S, DC | no | Windows Firewall setting differs from the DISA STIG |
| `stig_edge` | Medium | T1189 |  | W, S, DC | no | Microsoft Edge policy differs from the DISA STIG |
| `stig_chrome` | Medium | T1189 |  | W, S, DC | no | Google Chrome policy differs from the DISA STIG |
| `stig_firefox` | Medium | T1189 |  | W, S, DC | no | Mozilla Firefox policy differs from the DISA STIG |
| `stig_office` | Medium | T1204.002 |  | W, S, DC | no | Microsoft 365 Apps policy differs from the DISA STIG |
| `stig_adobe` | Medium | T1204.002 |  | W, S, DC | no | Adobe Acrobat policy differs from the DISA STIG |

## DISA STIG rules read by the stig_* checks

The registry rules of the DISA STIGs (STIG content published by DISA). Each rule is one finding when the host differs; the collector reads exactly those values and nothing else. Rules that need an organization decision (a banner text, an approved URL list) are left out. Browser and Office rules are judged only when the product is installed; Office rules are per-user policies and are judged on the user profiles that were loaded when the snapshot was taken.

| Product | STIG release | Rules | CAT I | CAT II | CAT III |
|---|---|---|---|---|---|
| `stig_adobe` | Adobe Acrobat Reader DC Continuous V2R1 | 26 | 0 | 16 | 10 |
| `stig_adobe` | Adobe Acrobat Pro DC Continuous V2R1 | 22 | 0 | 11 | 11 |
| `stig_windows10` | Windows 10 V3R6 | 137 | 17 | 105 | 15 |
| `stig_windows11` | Windows 11 V2R7 | 133 | 16 | 103 | 14 |
| `stig_defender` | Microsoft Defender Antivirus V2R8 | 67 | 4 | 63 | 0 |
| `stig_firewall` | Windows Defender Firewall V2R2 | 38 | 6 | 14 | 18 |
| `stig_edge` | Microsoft Edge V2R5 | 53 | 0 | 48 | 5 |
| `stig_chrome` | Google Chrome V2R11 | 40 | 0 | 39 | 1 |
| `stig_firefox` | Mozilla Firefox V6R7 | 43 | 1 | 40 | 2 |
| `stig_office` | Microsoft Office 365 ProPlus V3R5 | 127 | 1 | 126 | 0 |
| `stig_server2016` | Windows Server 2016 V2R10 (DC + member) | 200 | 25 | 161 | 14 |
| `stig_server2019` | Windows Server 2019 V3R8 (DC + member) | 200 | 25 | 159 | 16 |
| `stig_server2022` | Windows Server 2022 V2R8 (DC + member) | 201 | 25 | 160 | 16 |
| `stig_server2025` | Windows Server 2025 V1R1 (DC + member) | 188 | 21 | 151 | 16 |

## ACSC Essential Eight requirements judged from a host

The requirements of the ASD Essential Eight Maturity Model (November 2023) that a host shows, in the ASD wording, with the checks that judge them. The dashboard gives each strategy the highest maturity level whose requirements here, and those of the levels below, are all met. The other requirements (vulnerability scanning cadence, central logging, multi-factor authentication, backups, processes) need evidence a host does not hold, so the level is an upper bound. Multi-factor authentication and regular backups have no requirement a host shows.

| Strategy | ML | Requirement | Checks | Notes |
|---|---|---|---|---|
| Patch applications | 1 | Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release. | `software_outdated` | judged on the applications HostBadger can place on a release line (needs the release data) |
| Patch applications | 1 | Office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed. | `software_eol` |  |
| Patch applications | 2 | Patches, updates or other vendor mitigations for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within one month of release. | `software_outdated` | judged on the applications HostBadger can place on a release line (needs the release data) |
| Patch applications | 3 | Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist. | `software_cve` | finding matching `in the CISA KEV catalog`; the installed version has a vulnerability in the CISA KEV catalog (working exploits), judged by version (needs the CVE data) |
| Patch applications | 3 | Applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed. | `software_eol` |  |
| Patch operating systems | 1 | Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release. | `updates_stale`, `updates_pending` | the date of the last Windows update, and the pending updates when the snapshot searched for them |
| Patch operating systems | 1 | Operating systems that are no longer supported by vendors are replaced. | `os_unsupported` |  |
| Restrict administrative privileges | 1 | Privileged users are assigned a dedicated privileged user account to be used solely for duties requiring privileged access. | `local_admin_member` | an account other than the built-in Administrator in the local Administrators group is usually an everyday account with admin rights |
| Restrict administrative privileges | 2 | Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed. | `laps_not_configured` | the local administrator account (LAPS), on domain members |
| Restrict administrative privileges | 3 | Memory integrity functionality is enabled. | `hvci_off` |  |
| Restrict administrative privileges | 3 | Local Security Authority protection functionality is enabled. | `lsa_not_protected` |  |
| Restrict administrative privileges | 3 | Credential Guard functionality is enabled. | `credential_guard_off` |  |
| Restrict administrative privileges | 3 | Remote Credential Guard functionality is enabled. | `remote_credential_guard_off` | domain members |
| Application control | 1 | Application control is implemented on workstations. | `app_control_not_enforced` | roles: W |
| Application control | 3 | Application control is implemented on non-internet-facing servers. | `app_control_not_enforced` | roles: S, DC; Maturity Level Two already asks for it on internet-facing servers |
| Application control | 3 | Microsoft's vulnerable driver blocklist is implemented. | `driver_blocklist_off` |  |
| Restrict Microsoft Office macros | 1 | Microsoft Office macros in files originating from the internet are blocked. | `office_macro_settings_weak` | with Microsoft Office; finding matching `Office macros from the internet` |
| Restrict Microsoft Office macros | 1 | Microsoft Office macro antivirus scanning is enabled. | `office_macro_settings_weak` | with Microsoft Office; finding matching `Office macro antivirus scanning` |
| Restrict Microsoft Office macros | 1 | Microsoft Office macro security settings cannot be changed by users. | `office_macro_settings_weak` | with Microsoft Office; finding matching `Office macro security settings`; the macro security level set by policy in Word, Excel and PowerPoint |
| Restrict Microsoft Office macros | 2 | Microsoft Office macros are blocked from making Win32 API calls. | `asr_other_rules_not_blocking` | with Microsoft Office; finding matching `Block Win32 API calls from Office macros`; the attack surface reduction rule |
| Restrict Microsoft Office macros | 3 | Only Microsoft Office macros running from within a sandboxed environment, a Trusted Location or that are digitally signed by a trusted publisher are allowed to execute. | `office_macro_settings_weak` | with Microsoft Office; finding matching `signed or trusted only` |
| User application hardening | 1 | Internet Explorer 11 is disabled or removed. | `ie11_enabled` |  |
| User application hardening | 1 | Web browsers do not process Java from the internet. | `ie11_enabled` | current browsers cannot run Java applets; IE11 was the last one that did |
| User application hardening | 2 | Web browsers are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur. | `stig_edge`, `stig_chrome`, `stig_firefox` | judged against the DISA STIG of each installed browser, not the ASD guide |
| User application hardening | 2 | Microsoft Office is blocked from creating child processes. | `asr_other_rules_not_blocking` | with Microsoft Office; finding matching `Block all Office applications from creating child processes`; the attack surface reduction rule |
| User application hardening | 2 | Microsoft Office is blocked from creating executable content. | `asr_other_rules_not_blocking` | with Microsoft Office; finding matching `Block Office applications from creating executable content`; the attack surface reduction rule |
| User application hardening | 2 | Microsoft Office is blocked from injecting code into other processes. | `asr_other_rules_not_blocking` | with Microsoft Office; finding matching `Block Office applications from injecting code into other processes`; the attack surface reduction rule |
| User application hardening | 2 | Microsoft Office is configured to prevent activation of Object Linking and Embedding packages. | `office_macro_settings_weak` | with Microsoft Office; finding matching `Office OLE packages` |
| User application hardening | 2 | Office productivity suites are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur. | `stig_office` | with Microsoft Office; judged against the DISA Microsoft 365 Apps STIG, not the ASD guide |
| User application hardening | 2 | PDF software is blocked from creating child processes. | `asr_other_rules_not_blocking` | finding matching `Block Adobe Reader from creating child processes`; the attack surface reduction rule (Adobe Reader) |
| User application hardening | 2 | PDF software is hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur. | `stig_adobe` | Adobe Acrobat, judged against its DISA STIG |
| User application hardening | 2 | PowerShell module logging, script block logging and transcription events are centrally logged. | `powershell_scriptblock_logging_off`, `powershell_module_logging_off` | only the local side: the logging is turned on (central collection is not visible from a host) |
| User application hardening | 2 | Command line process creation events are centrally logged. | `cmdline_audit_off` | only the local side: the command line is recorded (central collection is not visible from a host) |
| User application hardening | 3 | .NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed. | `netfx3_enabled` |  |
| User application hardening | 3 | Windows PowerShell 2.0 is disabled or removed. | `powershell_v2_enabled` |  |
| User application hardening | 3 | PowerShell is configured to use Constrained Language Mode. | `powershell_clm_off` |  |

## NIS2: ACN basic measures judged from a host

The requirements of the basic security measures of the Italian National Cybersecurity Agency (ACN Determinazione 379907/2025, D.Lgs. 138/2024: Allegato 1 for soggetti importanti, Allegato 2 for soggetti essenziali) that a host shows, in ACN's wording (`data\acn-nis2-measures.json`), with the checks that give evidence about them. The dashboard lists those with a finding against them. The other requirements (governance, risk and vulnerability plans, inventories, backups, multi-factor authentication, training, incident handling, documented procedures) need evidence a host does not hold: no contrary evidence on a host is not compliance.

| Measure | Point | Requirement (ACN) | Checks | Notes |
|---|---|---|---|---|
| ID.AM-02 | 1 | È mantenuto un inventario aggiornato dei servizi, dei sistemi e delle applicazioni software che compongono i sistemi informativi e di rete, ivi incluse le applicazioni commerciali, open-source e custom, anche accessibili tramite API, approvati da attori interni al soggetto NIS. | `remote_access_tool` | judged only with -AllowedRemoteTools; finding matching `not in -AllowedRemoteTools`; remote access tools outside -AllowedRemoteTools |
| ID.AM-02 | 1 | È mantenuto un inventario aggiornato dei servizi, dei sistemi e delle applicazioni software che compongono i sistemi informativi e di rete, ivi incluse le applicazioni commerciali, open-source e custom, anche accessibili tramite API, approvati da attori interni al soggetto NIS. | `browser_extension_not_allowed` | judged only with -AllowedExtensions; browser extensions outside -AllowedExtensions |
| ID.RA-08 | 2 | Le vulnerabilità, ivi comprese quelle identificate ai sensi della misura ID.RA-01, sono prontamente risolte attraverso aggiornamenti di sicurezza o misure di mitigazione, ove disponibili, ovvero accettando e documentando il rischio in accordo al piano di trattamento dei rischi di cui alla misura ID.RA-06. | `kev_software_match`, `software_cve`, `vulnerable_driver_present` | installed software with known exploited or published vulnerabilities, vulnerable drivers (needs the KEV or CVE data) |
| PR.AA-01 | 1 | Tutte le utenze, ivi incluse quelle con privilegi amministrativi e quelle utilizzate per l’accesso remoto, sono censite, approvate da attori interni al soggetto NIS e, fatte salve motivate e documentate ragioni tecniche, in accordo agli esiti della valutazione del rischio di cui alla misura ID.RA-05, sono individuali per gli utenti. | `guest_enabled`, `builtin_admin_enabled` | shared built-in accounts enabled |
| PR.AA-01 | 2 | Le credenziali (ad esempio nome utente e password) relative alle utenze sono robuste e aggiornate in accordo agli esiti della valutazione del rischio di cui alla misura ID.RA-05. | `password_policy_weak`, `account_lockout_weak`, `local_account_password_never_expires`, `local_account_password_not_required`, `blank_password_network_logon`, `laps_not_configured`, `local_admin_password_shared`, `lm_hash_stored`, `autologon_enabled`, `unattend_credentials`, `gpp_cpassword_cached` | the local password policy and local accounts, passwords left on disk |
| PR.AA-03 | 1 | Le modalità di autenticazione delle utenze per accedere ai sistemi informativi e di rete sono commisurate al rischio. A tal fine sono valutati almeno i rischi connessi: a) ai privilegi delle utenze; b) alla criticità dei sistemi informativi e di rete; c) alla tipologia di operazioni che le utenze possono effettuare sui sistemi informativi e di rete. | `rdp_nla_disabled`, `winrm_insecure_auth`, `ntlm_weak_lmcompat`, `kerberos_rc4_allowed`, `smb_insecure_guest_auth` | the authentication methods the host accepts |
| PR.AA-05 | 1 | I permessi sono assegnati alle utenze in accordo ai principi del minimo privilegio e della separazione delle funzioni, tenuto anche conto della necessità di conoscere (need to know). | `user_rights_excessive`, `uac_disabled`, `uac_admin_no_prompt`, `remote_uac_token_filter_off`, `always_install_elevated`, `service_binary_writable`, `task_binary_writable`, `autorun_writable`, `system_path_writable`, `program_dir_writable`, `service_permissions_weak`, `service_unquoted_path`, `service_path_ancestor_control` | user rights, UAC, and the ways a standard user gains administrator rights on the host |
| PR.AA-05 | 2 | È assicurata la completa distinzione tra utenze con e senza privilegi amministrativi degli amministratori di sistema alle quali debbono corrispondere credenziali diverse. | `local_admin_member` | an account other than the built-in Administrator in the local Administrators group is usually an everyday account with admin rights |
| PR.DS-01 | 1 | Per almeno i sistemi informativi e di rete rilevanti, in accordo agli esiti della valutazione del rischio di cui alla misura ID.RA-05, fatte salve motivate e documentate ragioni normative o tecniche, i dati memorizzati sui dispositivi portatili, ivi inclusi laptop, smartphone e tablet, e sui supporti removibili, sono cifrati con protocolli e algoritmi allo stato dell’arte e considerati sicuri. | `bitlocker_os_volume_off`, `bitlocker_data_volume_off`, `bitlocker_tpm_only`, `bitlocker_weak_encryption` | roles: W; BitLocker on every workstation (HostBadger does not tell a laptop from a desktop); removable media are not seen |
| PR.DS-01 | 2 | Fatte salve motivate e documentate ragioni normative o tecniche, è disabilitata l'auto esecuzione dei supporti rimovibili ed è effettuata la loro scansione al fine di rilevare codici malevoli prima che siano utilizzati nei sistemi informativi e di rete. | `autoplay_enabled`, `removable_media_execute_allowed` | autorun and execution from removable media; the scan is part of DE.CM-09 |
| PR.DS-02 | 1 | Per almeno i sistemi informativi e di rete rilevanti, ivi inclusi quelli di comunicazione vocale, video e testuale, in accordo agli esiti della valutazione del rischio di cui alla misura ID.RA-05, fatte salve motivate e documentate ragioni normative o tecniche, sono utilizzati, per la trasmissione dei dati da e verso l’esterno del soggetto NIS, protocolli e algoritmi di cifratura allo stato dell’arte e considerati sicuri. | `schannel_legacy_crypto_enabled`, `smb_plaintext_password`, `ldap_client_encryption_weak`, `wifi_profile_insecure` | the protocols and ciphers the host offers; the traffic itself is not seen |
| PR.PS-01 | 1 | Per almeno i sistemi informativi e di rete rilevanti, sono definite, e documentate in un elenco aggiornato, le loro configurazioni di riferimento sicure (hardened). | `config_drift` | Allegato 2 only (soggetti essenziali); hosts of the same role that differ in their settings (needs several hosts); a documented reference configuration is not seen |
| PR.PS-02 | 1 | Fatte salve motivate e documentate ragioni normative o tecniche, in accordo agli esiti della valutazione del rischio di cui alla misura ID.RA-05, è installato esclusivamente software, ivi compresi i sistemi operativi, per il quale è garantita la disponibilità di aggiornamenti di sicurezza. | `os_unsupported`, `software_eol` | Windows and the software HostBadger can place on a support calendar |
| PR.PS-02 | 2 | Fatte salve motivate e documentate ragioni normative o tecniche, sono installati, senza ingiustificato ritardo, gli ultimi aggiornamenti di sicurezza rilasciati dal produttore in coerenza con il piano di gestione delle vulnerabilità di cui alla misura ID.RA-08. | `updates_stale`, `updates_pending`, `wu_auto_updates_disabled`, `reboot_overdue`, `software_outdated` | Windows updates, and the applications HostBadger can place on a release line (needs the release data) |
| PR.PS-04 | 1 | Tutti gli accessi eseguiti da remoto e quelli effettuati con utenze con privilegi amministrativi sono registrati. | `audit_policy_gaps` | the local audit policy: logon, privilege use and account management events |
| PR.PS-04 | 2 | Per almeno i sistemi informativi e di rete rilevanti, sono acquisiti e, in modo sicuro e possibilmente centralizzato, conservati almeno i log necessari ai fini del monitoraggio degli eventi di sicurezza, ivi compresi quelli relativi agli accessi di cui al punto 1. | `log_forwarding_missing`, `security_log_small`, `event_logs_small`, `cmdline_audit_off`, `powershell_scriptblock_logging_off`, `powershell_module_logging_off` | only the local side: what the host records, how much it keeps, whether it forwards |
| PR.IR-01 | 1 | Per almeno i sistemi informativi e di rete rilevanti, sono definite e documentate le eventuali attività consentite da remoto e implementate adeguate misure di sicurezza per l’accesso. | `rdp_nla_disabled`, `rdp_policy_gaps`, `rdp_enabled_workstation`, `winrm_insecure_auth`, `remote_access_tool` | Remote Desktop, WinRM and remote access tools on the host |
| PR.IR-01 | 3 | Sono presenti, aggiornati, mantenuti e configurati in modo adeguato sistemi perimetrali, quali firewall. | `firewall_profile_disabled`, `firewall_default_inbound_allow` | the Windows firewall of the host; perimeter firewalls are not seen |
| DE.CM-01 | 1 | Per almeno i sistemi informativi e di rete rilevanti, sono presenti, aggiornati, mantenuti e configurati in modo adeguato strumenti tecnici per rilevare tempestivamente gli incidenti significativi. | `edr_not_found`, `edr_agent_stopped`, `edr_expected_missing` | an EDR agent on the host, running |
| DE.CM-01 | 5 | Per almeno i sistemi informativi e di rete rilevanti, ai fini di cui al punto 1, sono monitorati gli accessi da remoto, le attività dei sistemi perimetrali (ad esempio router e firewall), gli eventi amministrativi di rilievo, nonché gli accessi eseguiti o falliti alle risorse di rete, ai punti terminali (endpoint) e agli applicativi al fine di rilevare gli eventi di sicurezza informatica. | `audit_policy_gaps`, `log_forwarding_missing` | Allegato 2 only (soggetti essenziali); only the local side: the events the host records and forwards |
| DE.CM-09 | 1 | Fatte salve motivate e documentate ragioni normative o tecniche, sono presenti, aggiornati, mantenuti e configurati in modo adeguato, sistemi di protezione dei punti terminali (endpoint) per il rilevamento del codice malevolo. | `defender_realtime_off`, `defender_signatures_stale`, `defender_tamper_off`, `defender_protection_features_off`, `defender_exclusion`, `edr_not_found`, `edr_agent_stopped` | Microsoft Defender (or the EDR that replaces it): on, up to date, without broad exclusions |

