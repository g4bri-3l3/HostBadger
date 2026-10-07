# HostBadger checks: the catalog, the "not evaluated" rule, the checks for each host, exceptions and
# the score.
#
# Each catalog entry has a Category, a Severity (the default one; a finding can raise or lower it),
# a Mitre technique, Needs (the snapshot sections it reads; see Get-NotEvaluatedChecks), Roles
# (where it applies: workstation, server, dc), a Title, a Description and a Remediation. A check
# that doesn't apply to a role is skipped silently. A check whose data is missing is listed as "not
# evaluated", never as clean.

$script:AllRoles = @('workstation', 'server', 'dc')

$script:CheckCatalog = [ordered]@{
    # ---------------- Credential protection ----------------
    lsa_not_protected = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1003.001'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'LSASS not running as a protected process'
        Description = 'RunAsPPL is not set, so any process with debug rights can open LSASS and read the credentials cached in it (Mimikatz-style dumping).'
        Remediation = 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa RunAsPPL = 1 (or 2 for UEFI lock) through Group Policy or Intune, after checking that no LSA plug-in or driver is incompatible.' }
    credential_guard_off = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1003.001'; Needs = @('credentialProtection'); Roles = @('workstation', 'server')
        Title = 'Credential Guard not running'
        Description = 'Credential Guard keeps NTLM hashes and Kerberos tickets in an isolated process that even SYSTEM cannot read. Without it, a single local admin compromise yields reusable domain credentials.'
        Remediation = 'Enable Virtualization-based Security with Credential Guard (Group Policy: Device Guard > Turn On Virtualization Based Security) on hardware that supports it. Not supported on domain controllers.' }
    wdigest_cleartext = @{ Category = 'Credential Protection'; Severity = 'High'; Mitre = 'T1003.001'; Cis = '18.4.8 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'WDigest stores cleartext passwords'
        Description = 'UseLogonCredential = 1 makes LSASS keep the cleartext password of every interactive logon, so one memory dump gives the password itself. Attackers set it on purpose to harvest passwords later.'
        Remediation = 'Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest UseLogonCredential = 0 and find out who changed it.' }
    cached_logons_high = @{ Category = 'Credential Protection'; Severity = 'Low'; Mitre = 'T1003.005'; Cis = '2.3.7.7 (L2)'; Needs = @('credentialProtection'); Roles = @('workstation', 'server')
        Title = 'Many domain logons cached'
        Description = 'Cached domain credentials (MSCache v2 hashes) can be extracted and cracked offline from a stolen or compromised machine. Servers rarely need them at all.'
        Remediation = 'Set "Interactive logon: Number of previous logons to cache" to 4 or fewer on workstations and 0-1 on servers.' }
    lm_hash_stored = @{ Category = 'Credential Protection'; Severity = 'High'; Mitre = 'T1003'; Cis = '2.3.11.5 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'LM hashes stored'
        Description = 'NoLMHash is 0, so the trivially crackable LM hash is stored for local passwords set from now on.'
        Remediation = 'Set "Network security: Do not store LAN Manager hash value on next password change" to Enabled, then change the local passwords.' }
    ntlm_weak_lmcompat = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1557.001'; Cis = '2.3.11.7 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'LM / NTLMv1 not refused'
        Description = 'LmCompatibilityLevel is below 5 (unset means 3), so the host still accepts LM and NTLMv1 responses, which can be cracked or relayed.'
        Remediation = 'Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (5) after auditing NTLMv1 use.' }
    anonymous_sam_enum = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1087.001'; Cis = '2.3.10.2 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'Anonymous enumeration of accounts allowed'
        Description = 'RestrictAnonymousSAM is 0, so anyone on the network can list the local accounts without logging on, feeding password spraying.'
        Remediation = 'Set "Network access: Do not allow anonymous enumeration of SAM accounts" to Enabled.' }

    # ---------------- Antivirus (Microsoft Defender) ----------------
    defender_realtime_off = @{ Category = 'Antivirus'; Severity = 'High'; Mitre = 'T1562.001'; Cis = '18.10.42.10.2 (L1)'; Needs = @('defender'); Roles = $script:AllRoles
        Title = 'Defender real-time protection off'
        Description = 'Microsoft Defender is the active antivirus but real-time protection (or the antivirus engine) is off: files are not scanned when written or run.'
        Remediation = 'Turn real-time protection back on, find out why it was disabled, and enable tamper protection so it cannot be turned off locally.' }
    defender_tamper_off = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1562.001'; Needs = @('defender'); Roles = $script:AllRoles
        Title = 'Defender tamper protection off'
        Description = 'Without tamper protection, a local administrator (or malware running as one) can disable Defender, add exclusions or stop real-time protection.'
        Remediation = 'Enable tamper protection from Microsoft Defender for Endpoint / Intune, or Windows Security on unmanaged devices.' }
    defender_signatures_stale = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1562.001'; Needs = @('defender'); Roles = $script:AllRoles
        Title = 'Defender signatures out of date'
        Description = 'The antivirus signatures were last updated more days ago than the threshold, so recent malware is not recognized.'
        Remediation = 'Check that the host reaches its update source (WSUS, Microsoft Update or a file share) and that the signature update task runs.' }
    defender_exclusion = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1562.001'; Needs = @('defender', 'defender.exclusions'); Roles = $script:AllRoles
        Title = 'Defender exclusion'
        Description = 'Files matching an exclusion are never scanned. A broad or user-writable exclusion (a drive, a profile, Temp, Downloads, a script extension, a scripting host) is where malware is dropped on purpose; it is High. Narrow exclusions for known software are Low, worth an occasional review.'
        Remediation = 'Remove broad exclusions; scope the rest to the exact file or folder of the product that needs it, ideally under Program Files where users cannot write.' }
    asr_standard_rules_missing = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1003.001'; Cis = '18.10.42.6.1.1 (L1)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Standard ASR rules not in block mode'
        Description = 'Microsoft recommends three attack surface reduction rules for every device (block credential stealing from LSASS, abuse of vulnerable signed drivers, persistence through WMI event subscriptions). They are not all set to block.'
        Remediation = 'Set the listed rules to Block (1) through Intune, Group Policy or Set-MpPreference, after a period in audit mode if needed.' }

    # ---------------- Disk and boot ----------------
    bitlocker_os_volume_off = @{ Category = 'Disk and Boot'; Severity = 'High'; Mitre = 'T1005'; Needs = @('bitlocker'); Roles = $script:AllRoles
        Title = 'Operating system volume not encrypted'
        Description = 'The Windows volume is not protected by BitLocker: anyone with the disk (a stolen laptop, a copied VM disk) reads every file, cached credential and the SAM offline. High on workstations, Medium on servers.'
        Remediation = 'Enable BitLocker on the OS volume with a TPM protector (plus a PIN on laptops) and escrow the recovery key to Entra ID or Active Directory.' }
    bitlocker_tpm_only = @{ Category = 'Disk and Boot'; Severity = 'Low'; Mitre = 'T1005'; Needs = @('bitlocker'); Roles = @('workstation')
        Title = 'BitLocker without pre-boot PIN'
        Description = 'The OS volume unlocks with the TPM alone. On a stolen laptop, TPM-sniffing and DMA attacks can recover the key; a PIN closes them.'
        Remediation = 'Add a TPM+PIN protector on laptops that leave the office (Require additional authentication at startup).' }
    bitlocker_data_volume_off = @{ Category = 'Disk and Boot'; Severity = 'Low'; Mitre = 'T1005'; Needs = @('bitlocker'); Roles = $script:AllRoles
        Title = 'Fixed data volume not encrypted'
        Description = 'A fixed data disk is not protected by BitLocker; its content is readable offline.'
        Remediation = 'Encrypt fixed data volumes too (auto-unlock with the OS volume).' }
    secure_boot_off = @{ Category = 'Disk and Boot'; Severity = 'Medium'; Mitre = 'T1542.003'; Needs = @('boot'); Roles = $script:AllRoles
        Title = 'Secure Boot off'
        Description = 'Secure Boot is disabled or the host boots in legacy BIOS mode, so bootkits can load before Windows and its defenses.'
        Remediation = 'Switch the firmware to UEFI and enable Secure Boot (convert the disk with mbr2gpt first if needed).' }

    # ---------------- Network exposure ----------------
    smb1_server_enabled = @{ Category = 'Network Exposure'; Severity = 'High'; Mitre = 'T1210'; Cis = '18.4.4 (L1)'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'SMBv1 server enabled'
        Description = 'SMBv1 is obsolete and exploitable (EternalBlue / WannaCry); no supported Windows needs it.'
        Remediation = 'Disable it: Set-SmbServerConfiguration -EnableSMB1Protocol $false, or remove the SMB 1.0/CIFS feature.' }
    smb_server_signing_not_required = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557.001'; Cis = '2.3.9.2 (L1)'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'SMB server signing not required'
        Description = 'Without required signing, NTLM authentication to this host can be relayed from a coerced machine (PetitPotam, PrinterBug, Responder). High on domain controllers.'
        Remediation = 'Enable "Microsoft network server: Digitally sign communications (always)".' }
    smb_client_signing_not_required = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557.001'; Cis = '2.3.8.1 (L1)'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'SMB client signing not required'
        Description = 'The SMB client accepts unsigned sessions, so its traffic can be tampered with or relayed.'
        Remediation = 'Enable "Microsoft network client: Digitally sign communications (always)".' }
    llmnr_enabled = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557.001'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'LLMNR not disabled'
        Description = 'Multicast name resolution lets anyone on the same subnet answer a mistyped name and capture or relay the NTLM authentication that follows (Responder).'
        Remediation = 'Group Policy: DNS Client > Turn off multicast name resolution = Enabled.' }
    netbios_enabled = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557.001'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'NetBIOS over TCP/IP enabled'
        Description = 'NBT-NS poisoning works like LLMNR poisoning. "Default" means enabled unless DHCP turns it off.'
        Remediation = 'Disable NetBIOS over TCP/IP on every adapter (DHCP option 001 or the adapter settings), after checking nothing depends on it.' }
    firewall_profile_disabled = @{ Category = 'Network Exposure'; Severity = 'High'; Mitre = 'T1562.004'; Needs = @('network', 'network.firewall'); Roles = $script:AllRoles
        Title = 'Windows Firewall profile disabled'
        Description = 'A firewall profile is off: every listening service is reachable from the networks that profile covers.'
        Remediation = 'Turn the profile on (Group Policy: Windows Defender Firewall with Advanced Security) and allow only what the host needs.' }
    firewall_default_inbound_allow = @{ Category = 'Network Exposure'; Severity = 'High'; Mitre = 'T1562.004'; Needs = @('network', 'network.firewall'); Roles = $script:AllRoles
        Title = 'Firewall allows inbound by default'
        Description = 'The default inbound action is Allow: anything not explicitly blocked is reachable.'
        Remediation = 'Set the default inbound action to Block and add allow rules for the services the host offers.' }
    firewall_drop_logging_off = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1562.004'; Needs = @('network', 'network.firewall'); Roles = $script:AllRoles
        Title = 'Dropped packets not logged'
        Description = 'The firewall does not log the connections it blocks, so scans and lateral movement attempts against the host leave no trace.'
        Remediation = 'Enable "Log dropped packets" on every profile and collect the log (or the 5152/5157 events) centrally.' }
    risky_listener = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1021'; Needs = @('network', 'network.listening'); Roles = $script:AllRoles
        Title = 'Risky service listening on the network'
        Description = 'A service often abused or unencrypted (Telnet, FTP, TFTP, SNMP, VNC, databases, caches, WinRM over HTTP on a workstation) listens on a non-loopback address.'
        Remediation = 'Stop or uninstall the service if not needed; otherwise bind it to localhost or restrict it with firewall rules to the hosts that use it.' }

    # ---------------- Remote access ----------------
    rdp_nla_disabled = @{ Category = 'Remote Access'; Severity = 'High'; Mitre = 'T1021.001'; Cis = '18.10.56.3.9.4 (L1)'; Needs = @('remoteAccess'); Roles = $script:AllRoles
        Title = 'RDP without Network Level Authentication'
        Description = 'Remote Desktop is on and accepts sessions before the user authenticates, exposing the logon screen and pre-auth RDP bugs (BlueKeep class) to anyone who can reach port 3389.'
        Remediation = 'Require Network Level Authentication (UserAuthentication = 1) for RDP.' }
    rdp_enabled_workstation = @{ Category = 'Remote Access'; Severity = 'Low'; Mitre = 'T1021.001'; Cis = '18.10.56.3.2.1 (L2)'; Needs = @('remoteAccess'); Roles = @('workstation')
        Title = 'RDP enabled on a workstation'
        Description = 'Remote Desktop is open on a workstation, a common lateral movement path between user machines.'
        Remediation = 'Disable RDP on workstations that do not need it, or allow 3389 only from admin jump hosts.' }

    # ---------------- Local accounts ----------------
    builtin_admin_enabled = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1078.003'; Needs = @('localAccounts'); Roles = @('workstation', 'server')
        Title = 'Built-in Administrator enabled'
        Description = 'The RID 500 account is enabled. It cannot be locked out, and without LAPS it often shares one password across many machines (pass-the-hash everywhere). Low when LAPS manages the password.'
        Remediation = 'Disable it, or let Windows LAPS manage its password.' }
    guest_enabled = @{ Category = 'Local Accounts'; Severity = 'High'; Mitre = 'T1078.001'; Cis = '2.3.1.2 (L1)'; Needs = @('localAccounts'); Roles = $script:AllRoles
        Title = 'Guest account enabled'
        Description = 'The built-in Guest account (RID 501) is enabled.'
        Remediation = 'Disable the Guest account.' }
    local_admin_member = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1078.003'; Needs = @('localAccounts', 'localAccounts.administrators'); Roles = @('workstation', 'server')
        Title = 'Extra member of local Administrators'
        Description = 'An account or group other than the built-in Administrator and Domain Admins is a local administrator. Local accounts and individual users there are Medium (standing admin rights on the box, often the same password elsewhere); groups are Low (check who is inside). Pass -AllowedAdmins for the groups that belong there.'
        Remediation = 'Remove the member, or grant admin rights through a dedicated, small group managed centrally (and LAPS for emergency access).' }
    local_account_password_not_required = @{ Category = 'Local Accounts'; Severity = 'High'; Mitre = 'T1078.003'; Needs = @('localAccounts'); Roles = @('workstation', 'server')
        Title = 'Enabled local account allowed an empty password'
        Description = 'The account has the "password not required" flag, so it can have a blank password regardless of the password policy.'
        Remediation = 'Clear the flag (net user <name> /passwordreq:yes), set a strong password, or disable the account.' }
    local_account_password_never_expires = @{ Category = 'Local Accounts'; Severity = 'Low'; Mitre = 'T1078.003'; Needs = @('localAccounts'); Roles = @('workstation', 'server')
        Title = 'Local account password never expires'
        Description = 'An enabled local account keeps the same password forever, unmanaged.'
        Remediation = 'Disable local accounts that are not needed; manage the rest with LAPS or a vault.' }
    laps_not_configured = @{ Category = 'Local Accounts'; Severity = 'High'; Mitre = 'T1078.003'; Needs = @('laps'); Roles = @('workstation', 'server')
        Title = 'LAPS not configured'
        Description = 'Neither Windows LAPS nor legacy Microsoft LAPS manages the local administrator password on this domain or Entra joined host, so it is likely the same on many machines.'
        Remediation = 'Deploy Windows LAPS (BackupDirectory = Active Directory or Entra ID) through Group Policy or Intune.' }
    uac_disabled = @{ Category = 'Local Accounts'; Severity = 'High'; Mitre = 'T1548.002'; Cis = '2.3.17.6 (L1)'; Needs = @('uac'); Roles = $script:AllRoles
        Title = 'UAC disabled'
        Description = 'EnableLUA = 0: every administrator runs everything with a full admin token, and Defender SmartScreen and modern apps lose their protections.'
        Remediation = 'Set EnableLUA = 1 ("User Account Control: Run all administrators in Admin Approval Mode").' }
    uac_admin_no_prompt = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1548.002'; Cis = '2.3.17.2 (L1)'; Needs = @('uac'); Roles = $script:AllRoles
        Title = 'UAC elevates administrators without asking'
        Description = 'ConsentPromptBehaviorAdmin = 0: any program an administrator starts can elevate silently.'
        Remediation = 'Set "Behavior of the elevation prompt for administrators" to prompt for consent on the secure desktop (2) or for credentials.' }
    remote_uac_token_filter_off = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1550.002'; Cis = '18.4.1 (L1)'; Needs = @('uac'); Roles = @('workstation', 'server')
        Title = 'Remote UAC filtering disabled for local accounts'
        Description = 'LocalAccountTokenFilterPolicy = 1 gives local administrator accounts a full admin token over the network, the condition pass-the-hash with a shared local password needs.'
        Remediation = 'Remove LocalAccountTokenFilterPolicy (or set 0) and use domain accounts for remote administration.' }
    always_install_elevated = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1548'; Needs = @('uac'); Roles = $script:AllRoles
        Title = 'AlwaysInstallElevated enabled'
        Description = 'Windows Installer packages install with SYSTEM rights for every user (when the per-user policy is set too, which a user can do): any user becomes SYSTEM with a crafted .msi.'
        Remediation = 'Set "Always install with elevated privileges" to Disabled in both computer and user policy.' }

    # ---------------- Privilege escalation ----------------
    service_unquoted_path = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1574.009'; Needs = @('services'); Roles = $script:AllRoles
        Title = 'Service path with spaces and no quotes'
        Description = 'An unquoted service path with spaces makes Windows try "C:\Program.exe", "C:\Program Files\Some.exe" and so on first: whoever can write one of those places runs code as the service account.'
        Remediation = 'Quote the ImagePath of the service (HKLM\SYSTEM\CurrentControlSet\Services\<name>), or reinstall it with a fixed installer.' }
    service_binary_writable = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1574.010'; Needs = @('services', 'acl'); Roles = $script:AllRoles
        Title = 'Service program writable by users'
        Description = 'Everyone, Users, Authenticated Users or Domain Users can change the service program (High) or drop files into its folder (Medium, DLL planting): any user gets the service account, usually SYSTEM.'
        Remediation = 'Fix the ACL: only Administrators, SYSTEM and TrustedInstaller should be able to write the file and its folder. Move the program under Program Files if it lives elsewhere.' }
    task_binary_writable = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1053.005'; Needs = @('scheduledTasks', 'acl'); Roles = $script:AllRoles
        Title = 'Privileged scheduled task runs a user-writable program'
        Description = 'A task running as SYSTEM, a service account or with highest privileges starts a program that low privileged users can change (High) or whose folder they can write (Medium).'
        Remediation = 'Fix the ACL of the program and its folder, or point the task at a protected copy.' }
    autorun_writable = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1547.001'; Needs = @('autoruns', 'acl'); Roles = $script:AllRoles
        Title = 'Machine-wide autorun points to a user-writable program'
        Description = 'An HKLM Run key or the common Startup folder starts, for every user who logs on (administrators included), a program that low privileged users can change (High) or whose folder they can write (Medium).'
        Remediation = 'Fix the ACL of the program and its folder, or remove the autorun.' }
    spooler_on_dc = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1187'; Needs = @('services'); Roles = @('dc')
        Title = 'Print Spooler running on a domain controller'
        Description = 'The spooler lets any domain user coerce the DC into authenticating to them (PrinterBug), feeding NTLM relay and unconstrained delegation attacks.'
        Remediation = 'Stop and disable the Print Spooler service on domain controllers.' }

    # ---------------- Logging ----------------
    audit_policy_gaps = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.002'; Needs = @('audit'); Roles = $script:AllRoles
        Title = 'Audit policy gaps'
        Description = 'Subcategories the CIS benchmark expects (logon, credential validation, process creation, account and group changes, policy changes, privilege use; Kerberos and directory changes on DCs) are not audited, so attacks leave no event to detect.'
        Remediation = 'Configure the Advanced Audit Policy for the listed subcategories (Group Policy: Advanced Audit Policy Configuration) and forward the Security log.' }
    cmdline_audit_off = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.002'; Needs = @('audit'); Roles = $script:AllRoles
        Title = 'Command lines missing from process events'
        Description = 'Event 4688 does not record the command line, which is what tells a normal PowerShell or cmd.exe start from a malicious one.'
        Remediation = 'Enable "Include command line in process creation events" with Audit Process Creation (Success).' }
    powershell_scriptblock_logging_off = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.002'; Cis = '18.10.86.1 (L2)'; Needs = @('powershell'); Roles = $script:AllRoles
        Title = 'PowerShell script block logging off'
        Description = 'PowerShell is the most used attacker tool on Windows; without script block logging (event 4104) the code it ran is not recorded, even when obfuscated.'
        Remediation = 'Enable "Turn on PowerShell Script Block Logging" and forward Microsoft-Windows-PowerShell/Operational.' }
    powershell_v2_enabled = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.010'; Needs = @('powershell'); Roles = $script:AllRoles
        Title = 'PowerShell 2.0 engine installed'
        Description = 'powershell -Version 2 starts an engine without script block logging, AMSI or Constrained Language Mode: the classic downgrade to escape logging.'
        Remediation = 'Remove the optional feature: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (Remove-WindowsFeature PowerShell-V2 on servers).' }
    security_log_small = @{ Category = 'Logging'; Severity = 'Low'; Mitre = 'T1070.001'; Cis = '18.10.25.2.2 (L1)'; Needs = @('audit'); Roles = $script:AllRoles
        Title = 'Security event log too small'
        Description = 'The Security log rolls over quickly at this size; events from the start of an intrusion are gone before anyone looks, unless they are forwarded.'
        Remediation = 'Set the Security log maximum size to at least 196,608 KB (CIS), more on servers and DCs, and forward events to the SIEM.' }

    # ---------------- Patching and lifecycle ----------------
    os_unsupported = @{ Category = 'Patching'; Severity = 'High'; Mitre = 'T1190'; Needs = @('host'); Roles = $script:AllRoles
        Title = 'Windows version out of support'
        Description = 'This Windows build and edition no longer receives security updates (unless the host is enrolled in Extended Security Updates).'
        Remediation = 'Upgrade to a supported release, or enroll in ESU while the upgrade is planned.' }
    os_support_ending = @{ Category = 'Patching'; Severity = 'Low'; Mitre = 'T1190'; Needs = @('host'); Roles = $script:AllRoles
        Title = 'Windows support ends soon'
        Description = 'Security updates for this Windows build and edition end within the warning window.'
        Remediation = 'Plan the feature update or the OS upgrade before the end date.' }
    updates_stale = @{ Category = 'Patching'; Severity = 'High'; Mitre = 'T1190'; Needs = @('patches'); Roles = $script:AllRoles
        Title = 'No update installed recently'
        Description = 'No update of Windows itself has been installed for longer than the threshold, so the monthly security fixes are missing. The date comes from the Windows hotfix list; the Windows Update screen can show a later date because it also lists .NET, PowerShell, Defender and app updates, which say nothing about whether Windows is patched. A host whose Windows version is out of support stops receiving these updates altogether.'
        Remediation = 'Check Windows Update / WSUS / Intune for this host: failed installs, a paused ring, or a host that never reboots.' }
    # ---------------- Baseline settings (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0) ----------------
    # Cis names the benchmark rules that the check follows, with the profile level. Only values that
    # are set get judged, unless the Windows default is itself the problem.
    smb_insecure_guest_auth = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1021.002'; Cis = '18.6.8.1 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Insecure SMB guest logons allowed'
        Description = 'AllowInsecureGuestAuth = 1 lets this host connect to SMB servers as a guest without signing or encryption, so a rogue file server or a man in the middle can feed it files and capture traffic.'
        Remediation = 'Set "Lanman Workstation: Enable insecure guest logons" to Disabled and move legacy NAS devices to authenticated SMB.' }
    ldap_client_signing_off = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; Cis = '2.3.11.8 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'LDAP client signing disabled'
        Description = 'LDAPClientIntegrity = 0 means LDAP binds from this host are not signed, so they can be relayed or modified in transit.'
        Remediation = 'Set "Network security: LDAP client signing requirements" to Negotiate signing (or Require signing once every directory supports it).' }
    ntlm_min_session_security_weak = @{ Category = 'Credential Protection'; Severity = 'Low'; Mitre = 'T1557.001'; Cis = '2.3.11.9, 2.3.11.10 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'NTLM session security below NTLMv2 with 128-bit encryption'
        Description = 'The minimum session security for NTLM clients or servers is explicitly set below "Require NTLMv2 session security + 128-bit encryption" (0x20080000), which allows weaker, easier to attack sessions.'
        Remediation = 'Set "Network security: Minimum session security for NTLM SSP based clients / servers" to Require NTLMv2 session security and Require 128-bit encryption.' }
    anonymous_shares_enum = @{ Category = 'Credential Protection'; Severity = 'Low'; Mitre = 'T1135'; Cis = '2.3.10.3 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
        Title = 'Anonymous enumeration of accounts and shares allowed'
        Description = 'RestrictAnonymous is not 1, so an unauthenticated user can list share names and other information about this host.'
        Remediation = 'Set "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to Enabled.' }
    everyone_includes_anonymous = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1087'; Cis = '2.3.10.5 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Everyone permissions apply to anonymous users'
        Description = 'EveryoneIncludesAnonymous = 1 makes the Everyone group include anonymous (not logged on) users, so any share or file open to Everyone is open to anyone on the network.'
        Remediation = 'Set "Network access: Let Everyone permissions apply to anonymous users" to Disabled.' }
    blank_password_network_logon = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1078.003'; Cis = '2.3.1.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Blank passwords allowed outside the console'
        Description = 'LimitBlankPasswordUse = 0 lets local accounts with an empty password log on over the network (SMB, RDP, remote tools), not just at the keyboard.'
        Remediation = 'Set "Accounts: Limit local account use of blank passwords to console logon only" to Enabled and give every local account a password.' }
    force_guest_sharing_model = @{ Category = 'Local Accounts'; Severity = 'High'; Mitre = 'T1078.001'; Cis = '2.3.10.12 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Network logons are forced to the Guest account'
        Description = 'ForceGuest = 1 ("Guest only") makes every network logon to a local account run as Guest, which hides who did what and defeats per-user access control on shares.'
        Remediation = 'Set "Network access: Sharing and security model for local accounts" to Classic - local users authenticate as themselves.' }
    null_session_access = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1135'; Cis = '2.3.10.6, 2.3.10.9, 2.3.10.11 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Shares or pipes reachable without authentication'
        Description = 'Named pipes or shares are listed as accessible anonymously, or the restriction on anonymous access to pipes and shares is off (RestrictNullSessAccess = 0).'
        Remediation = 'Empty "Network access: Named Pipes / Shares that can be accessed anonymously" and enable "Restrict anonymous access to Named Pipes and Shares".' }
    secure_channel_unprotected = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; Cis = '2.3.6.1 - 2.3.6.6 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Domain secure channel not protected'
        Description = 'The channel between this domain member and its domain controller is not required to be signed, sealed or to use a strong session key, or the machine account password is not rotated (disabled, or older than 30 days).'
        Remediation = 'Set the "Domain member: Digitally encrypt or sign secure channel data" and "Require strong session key" policies to Enabled, leave machine account password changes on, and set the maximum age to 30 days.' }
    smb_plaintext_password = @{ Category = 'Network Exposure'; Severity = 'High'; Mitre = 'T1557'; Cis = '2.3.8.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Unencrypted passwords sent to third-party SMB servers'
        Description = 'EnablePlainTextPassword = 1 lets the SMB client send the password in clear text to servers that ask for it, so anyone on the path reads it.'
        Remediation = 'Set "Microsoft network client: Send unencrypted password to third-party SMB servers" to Disabled.' }
    winrm_insecure_auth = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1021.006'; Cis = '18.10.88.1.1 - 18.10.88.2.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'WinRM allows Basic, Digest or unencrypted traffic'
        Description = 'The WinRM client or service policy explicitly allows Basic authentication, Digest authentication or unencrypted traffic, which exposes credentials and commands to anyone who can observe or relay the connection.'
        Remediation = 'Set the WinRM client and service policies to disallow Basic, Digest and unencrypted traffic (use Kerberos, or HTTPS listeners).' }
    smb1_client_driver_enabled = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1210'; Cis = '18.4.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'SMBv1 client driver enabled'
        Description = 'The mrxsmb10 driver is not disabled (Start is not 4), so this host can still talk SMBv1 to old servers, with all its known weaknesses.'
        Remediation = 'Disable SMBv1 client: remove the optional feature or set "Configure SMB v1 client driver" to Disable driver.' }
    ip_stack_hardening_gaps = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557'; Cis = '18.5.2, 18.5.3, 18.5.5 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'IP stack accepts source routing or ICMP redirects'
        Description = 'IP source routing is explicitly set below the highest protection (2), or ICMP redirects are allowed to override routes: both let a nearby attacker steer this host traffic.'
        Remediation = 'Set the MSS policies "IP source routing protection level" to highest protection and "Allow ICMP redirects to override OSPF generated routes" to Disabled.' }
    rdp_policy_gaps = @{ Category = 'Remote Access'; Severity = 'Low'; Mitre = 'T1021.001'; Cis = '18.10.56.3.9.1 - 18.10.56.3.9.5, 18.10.56.3.3.3 (L1)'; Needs = @('remoteAccess', 'hardening'); Roles = $script:AllRoles
        Title = 'Remote Desktop policy weaker than the baseline'
        Description = 'RDP is enabled and its policy explicitly allows a weaker security layer or encryption level, does not require a password prompt or secure RPC, or leaves drive redirection on (data can be copied out of the session).'
        Remediation = 'Set Remote Desktop Session Host policies: security layer SSL, encryption level High, always prompt for a password, require secure RPC, and do not allow drive redirection.' }
    autoplay_enabled = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1091'; Cis = '18.10.7.1 - 18.10.7.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'AutoPlay / AutoRun not fully turned off'
        Description = 'AutoPlay is not disabled for all drives, or AutoRun commands are not blocked, so a USB stick or disc can start or suggest running its content.'
        Remediation = 'Set "Turn off Autoplay" to Enabled for All drives, "Set the default behavior for AutoRun" to Do not execute any autorun commands, and disallow Autoplay for non-volume devices.' }
    autologon_enabled = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1552.002'; Cis = '18.5.1 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Automatic logon configured'
        Description = 'AutoAdminLogon = 1: Windows logs a user on at boot. When the password is stored in the registry (DefaultPassword) anyone who can read that key, and every local user can, has it in clear text; that case is High.'
        Remediation = 'Set AutoAdminLogon to 0, delete the DefaultPassword value, and change the password that was stored there.' }
    inactivity_lock_missing = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = ''; Cis = '2.3.7.4 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'No machine inactivity lock within 15 minutes'
        Description = 'InactivityTimeoutSecs is not set, is 0, or is above 900 seconds: an unattended session stays open and usable.'
        Remediation = 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less (not 0).' }
    logon_banner_missing = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = ''; Cis = '2.3.7.5, 2.3.7.6 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'No logon warning message'
        Description = 'Neither a title nor a text is configured for the message shown before logon. A legal notice supports acceptable-use and monitoring policies.'
        Remediation = 'Set "Interactive logon: Message title / Message text for users attempting to log on" as approved by legal.' }
    interactive_logon_gaps = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1087'; Cis = '2.3.7.1, 2.3.7.2 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Logon screen shows the last user or skips CTRL+ALT+DEL'
        Description = 'The logon screen displays the last signed-in user name (a free account list for anyone at the keyboard), or the secure attention sequence is not required, which makes credential-stealing fake logon screens easier.'
        Remediation = 'Set "Interactive logon: Don''t display last signed-in" to Enabled and "Do not require CTRL+ALT+DEL" to Disabled.' }
    uac_hardening_gaps = @{ Category = 'Local Accounts'; Severity = 'Low'; Mitre = 'T1548.002'; Cis = '2.3.17.1, 2.3.17.4, 2.3.17.5, 2.3.17.7, 2.3.17.8 (L1)'; Needs = @('uac', 'hardening'); Roles = $script:AllRoles
        Title = 'UAC settings weaker than the baseline'
        Description = 'The built-in Administrator is not in Admin Approval Mode, or installer detection, secure UIAccess paths, the secure desktop for prompts (Medium) or file and registry virtualization is explicitly turned off.'
        Remediation = 'Set the User Account Control policies back to the baseline: Admin Approval Mode for the built-in Administrator on, detect installs, secure UIAccess paths, secure desktop prompts, virtualize write failures.' }
    wu_auto_updates_disabled = @{ Category = 'Patching'; Severity = 'Medium'; Mitre = 'T1190'; Cis = '18.10.92.2.1 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Automatic Windows Update turned off by policy'
        Description = 'NoAutoUpdate = 1: the Automatic Updates policy is set to Disabled, so security updates are not installed unless someone does it by hand.'
        Remediation = 'Set "Configure Automatic Updates" to Enabled (or Not configured on managed rings) and check that WSUS / Intune delivers the updates.' }
    smartscreen_off = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1204'; Cis = '18.10.75.2.1 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Microsoft Defender SmartScreen turned off by policy'
        Description = 'EnableSmartScreen = 0: Windows no longer warns about or blocks downloaded programs with a bad reputation.'
        Remediation = 'Set "Configure Windows Defender SmartScreen" to Enabled (Warn and prevent bypass) or remove the policy.' }
    event_logs_small = @{ Category = 'Logging'; Severity = 'Low'; Mitre = 'T1070.001'; Cis = '18.10.25.1.2, 18.10.25.4.2 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Application or System event log too small'
        Description = 'The log is smaller than 32,768 KB, so on a busy host it wraps within hours and the evidence of an incident is overwritten.'
        Remediation = 'Set the Application and System log maximum size to at least 32,768 KB and forward events to the SIEM.' }
    powershell_transcription_off = @{ Category = 'Logging'; Severity = 'Low'; Mitre = 'T1562.002'; Cis = '18.10.86.2 (L2)'; Needs = @('powershell'); Roles = $script:AllRoles
        Title = 'PowerShell transcription off'
        Description = 'EnableTranscripting is not 1, so there is no text record of what was typed and shown in PowerShell sessions (a CIS Level 2 control).'
        Remediation = 'Turn on PowerShell transcription to a protected, central folder, and keep script block logging on as well.' }
    service_should_be_disabled = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1021'; Cis = '5.3 - 5.44, Level 1 services (L1)'; Needs = @('services'); Roles = @('workstation')
        Title = 'Service the baseline says to disable is running or automatic'
        Description = 'A service the CIS Level 1 workstation baseline wants disabled (Computer Browser, IIS, FTP, SSH server, RPC Locator, Routing and Remote Access, SNMP-like Simple TCP/IP, SSDP, UPnP, Xbox services, WSL and others) is running or starts automatically. Network-facing ones are Medium. Services that are stopped and set to Manual are not listed.'
        Remediation = 'Disable the service (and uninstall the feature if it is not needed). On a server that legitimately runs the role, record an exception.' }
    defender_network_protection_off = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1189'; Cis = '18.10.42.6.3.1 (L1)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Defender Network Protection not enabled'
        Description = 'Network Protection is off or only auditing, so connections to known malicious sites and servers are not blocked at the network layer.'
        Remediation = 'Set Network Protection to Block mode (Intune, Group Policy or Set-MpPreference -EnableNetworkProtection Enabled) after a period in audit mode.' }
    defender_pua_off = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1204.002'; Cis = '18.10.42.16 (L1)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Defender blocking of potentially unwanted apps off'
        Description = 'PUA protection is not in block mode, so adware, bundlers and unwanted tools are not stopped.'
        Remediation = 'Enable PUA protection (Intune, Group Policy or Set-MpPreference -PUAProtection Enabled).' }
    sehop_disabled = @{ Category = 'System Hardening'; Severity = 'Medium'; Mitre = 'T1203'; Cis = '18.4.6 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'SEHOP exploit mitigation disabled'
        Description = 'DisableExceptionChainValidation = 1 turns off Structured Exception Handling Overwrite Protection, a mitigation that blocks a common class of memory-corruption exploits.'
        Remediation = 'Set "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to Enabled.' }
    safe_dll_search_off = @{ Category = 'System Hardening'; Severity = 'Medium'; Mitre = 'T1574.001'; Cis = '18.5.9 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Safe DLL search mode disabled'
        Description = 'SafeDllSearchMode = 0 makes programs look for DLLs in the current folder before the system folders, which makes DLL planting easy.'
        Remediation = 'Set "MSS: Enable Safe DLL search mode" to Enabled.' }
    # ---------------- Local security policy (read from the policy export) ----------------
    password_policy_weak = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1110'; Cis = '1.1.1 - 1.1.5, 1.1.7 (L1)'; Needs = @('securityPolicy'); Roles = @('workstation', 'server')
        Title = 'Local password policy weaker than the baseline'
        Description = 'The local account password policy (the one that applies to local accounts; domain accounts follow the domain policy) allows short or simple passwords, never forces a change or a minimum age, remembers too few old passwords, or stores them with reversible encryption. A password that never expires is flagged here and by the per-account check.'
        Remediation = 'Set history to 24, maximum age 365 days or less, minimum age 1 day or more, minimum length 14, complexity on, reversible encryption off (or manage local admin passwords with LAPS and rely on the domain policy for domain accounts).' }
    account_lockout_weak = @{ Category = 'Local Accounts'; Severity = 'Medium'; Mitre = 'T1110'; Cis = '1.2.1, 1.2.2, 1.2.4 (L1)'; Needs = @('securityPolicy'); Roles = @('workstation', 'server')
        Title = 'Account lockout missing or too lenient'
        Description = 'Local accounts are never locked after failed logons (threshold 0) or after more than 5 attempts, or the lockout lasts or resets in less than 15 minutes, which leaves password guessing against local accounts practical.'
        Remediation = 'Set the account lockout threshold to 5 or fewer attempts (not 0), the lockout duration to 15 minutes or more, and reset the counter after 15 minutes or more.' }
    user_rights_excessive = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1134'; Cis = '2.2.1 - 2.2.39, Level 1 rights (L1)'; Needs = @('securityPolicy'); Roles = @('workstation')
        Title = 'User right granted to more principals than the baseline'
        Description = 'A privilege or logon right is held by principals the CIS Level 1 workstation baseline does not list. Rights such as debug programs, act as part of the operating system, create a token or load drivers are a direct path to SYSTEM, so those are High; the rest are Medium. Default Windows grants some rights more widely than CIS (for example Backup Operators), so review before tightening.'
        Remediation = 'Remove the extra principals from the right (Local Security Policy > User Rights Assignment, or the matching Group Policy), after checking that no service or backup job depends on them.' }
    deny_logon_rights_missing = @{ Category = 'Local Accounts'; Severity = 'Low'; Mitre = 'T1078.001'; Cis = '2.2.16 - 2.2.20 (L1)'; Needs = @('securityPolicy'); Roles = @('workstation')
        Title = 'Guests or local accounts not denied network or remote logon'
        Description = 'The deny rights for network, batch, service, local and Remote Desktop logon do not list Guests (and, for network and Remote Desktop, "Local account"), so the Guest account or a local account can log on remotely if it is ever enabled or reused.'
        Remediation = 'Add Guests to the five deny logon rights and Local account to "Deny access to this computer from the network" and "Deny log on through Remote Desktop Services".' }
    lsa_weak_auth_options = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1557'; Cis = '2.3.11.2, 2.3.11.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'LocalSystem NULL session fallback or PKU2U online identities allowed'
        Description = 'AllowNullSessionFallback or PKU2U AllowOnlineID is explicitly 1: services running as LocalSystem may fall back to anonymous NTLM sessions, or the host accepts authentication with online identities.'
        Remediation = 'Set "Allow LocalSystem NULL session fallback" and "Allow PKU2U authentication requests to use online identities" to Disabled.' }
}

# Microsoft's "standard protection" ASR rules, recommended for every device.
$script:StandardAsrRules = [ordered]@{
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
}

# Audit subcategories (by GUID, the same in every language) and what CIS
# expects: 1 success, 2 failure, 3 both. 'dc' entries only on DCs.
$script:RequiredAudit = @(
    @{ Guid = '0cce923f-69ae-11d9-bed3-505054503030'; Name = 'Credential Validation'; Need = 3 }
    @{ Guid = '0cce9242-69ae-11d9-bed3-505054503030'; Name = 'Kerberos Authentication Service'; Need = 3; Dc = $true }
    @{ Guid = '0cce9240-69ae-11d9-bed3-505054503030'; Name = 'Kerberos Service Ticket Operations'; Need = 3; Dc = $true }
    @{ Guid = '0cce9237-69ae-11d9-bed3-505054503030'; Name = 'Security Group Management'; Need = 1 }
    @{ Guid = '0cce9235-69ae-11d9-bed3-505054503030'; Name = 'User Account Management'; Need = 3 }
    @{ Guid = '0cce923c-69ae-11d9-bed3-505054503030'; Name = 'Directory Service Changes'; Need = 1; Dc = $true }
    @{ Guid = '0cce922b-69ae-11d9-bed3-505054503030'; Name = 'Process Creation'; Need = 1 }
    @{ Guid = '0cce9215-69ae-11d9-bed3-505054503030'; Name = 'Logon'; Need = 3 }
    @{ Guid = '0cce9217-69ae-11d9-bed3-505054503030'; Name = 'Account Lockout'; Need = 2 }
    @{ Guid = '0cce921b-69ae-11d9-bed3-505054503030'; Name = 'Special Logon'; Need = 1 }
    @{ Guid = '0cce9227-69ae-11d9-bed3-505054503030'; Name = 'Other Object Access Events'; Need = 3 }
    @{ Guid = '0cce922f-69ae-11d9-bed3-505054503030'; Name = 'Audit Policy Change'; Need = 1 }
    @{ Guid = '0cce9230-69ae-11d9-bed3-505054503030'; Name = 'Authentication Policy Change'; Need = 1 }
    @{ Guid = '0cce9228-69ae-11d9-bed3-505054503030'; Name = 'Sensitive Privilege Use'; Need = 3 }
    @{ Guid = '0cce9211-69ae-11d9-bed3-505054503030'; Name = 'Security System Extension'; Need = 1 }
    @{ Guid = '0cce9212-69ae-11d9-bed3-505054503030'; Name = 'System Integrity'; Need = 3 }
)

# Ports worth flagging when they listen beyond localhost. Workstation-only
# entries are normal on servers.
$script:RiskyListenPorts = @{
    'tcp/21' = 'FTP'; 'tcp/23' = 'Telnet'; 'udp/69' = 'TFTP'; 'udp/161' = 'SNMP'; 'tcp/1433' = 'SQL Server'; 'tcp/1521' = 'Oracle'
    'tcp/3306' = 'MySQL'; 'tcp/5432' = 'PostgreSQL'; 'tcp/5900' = 'VNC'; 'tcp/5901' = 'VNC'; 'tcp/6379' = 'Redis'
    'tcp/9200' = 'Elasticsearch'; 'tcp/11211' = 'Memcached'; 'udp/11211' = 'Memcached'; 'tcp/27017' = 'MongoDB'
}
$script:WorkstationOnlyListenPorts = @{ 'tcp/5985' = 'WinRM over HTTP' }

# Exclusions that open a hole rather than skip one product.
$script:RiskyExclusionPathPatterns = @(
    '^[a-z]:\\?$', '^[a-z]:\\users\\?$', '\\users\\[^\\]+\\?$', '\\appdata(\\|$)', '\\temp(\\|$)', '\\downloads(\\|$)', '\\desktop(\\|$)',
    '^[a-z]:\\programdata\\?$', '^[a-z]:\\windows\\?$', '^[a-z]:\\windows\\system32\\?$', '^%', '\*', '\\public(\\|$)'
)
$script:RiskyExclusionExtensions = @('exe', 'dll', 'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'hta', 'scr', 'msi', 'lnk', 'wsf', 'com', 'pif', 'zip', 'iso')
$script:RiskyExclusionProcesses = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
    'msiexec.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe', 'explorer.exe', 'svchost.exe', 'python.exe', 'java.exe', 'javaw.exe', 'node.exe')

$script:WellKnownSids = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-4' = 'INTERACTIVE'
    'S-1-5-2' = 'NETWORK'; 'S-1-5-7' = 'ANONYMOUS LOGON'
}
function Get-SidLabel {
    param([string]$Sid)
    if ($script:WellKnownSids.ContainsKey($Sid)) { return $script:WellKnownSids[$Sid] }
    if ($Sid -match '-513$') { return 'Domain Users' }
    if ($Sid -match '-515$') { return 'Domain Computers' }
    return $Sid
}

# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------
function Add-Finding {
    # Type + Host + Object must be unique in a run, because comparisons and the SIEM finding_id are
    # built from them.
    param([string]$Type, [string]$Object, [string]$Detail, [string]$Severity = '')
    $meta = $script:CheckCatalog[$Type]
    if (-not $meta) { throw "Unknown check type: $Type" }
    # A check that follows several rules names the one that applies in the detail ("CIS 5.30 ...").
    # The profile level is the one in the catalog.
    $cis = "$($meta.Cis)"
    if ($cis) {
        $rule = [regex]::Match("$Detail", 'CIS (\d+(?:\.\d+)+)')
        $level = [regex]::Match($cis, '\((L\d)\)\s*$')
        if ($rule.Success -and $level.Success) { $cis = "$($rule.Groups[1].Value) ($($level.Groups[1].Value))" }
    }
    if (-not $Severity) { $Severity = $meta.Severity }
    $script:Findings.Add([PSCustomObject]@{
            Severity = $Severity
            Type     = $Type
            Title    = $meta.Title
            Category = $meta.Category
            Host     = $script:CurrentHost
            Object   = $Object
            Detail   = $Detail
            Mitre    = $meta.Mitre
            Cis      = $cis
        })
}

function Get-NotEvaluatedChecks {
    # For each check, why it can't be judged on this host. A failed section covers its sub-sections
    # (if "defender" fails, so does "defender.exclusions"), but not the other way round. Reasons
    # that the checks work out themselves come in $Extra (type -> reason).
    param($Snapshot, [hashtable]$Extra = @{})
    $role = Get-SnapshotRole $Snapshot
    $failed = @{}
    foreach ($e in @($Snapshot.meta.collectionErrors | Where-Object { $_ })) { $failed["$($e.section)"] = "$($e.message)" }
    $collected = @($Snapshot.meta.sectionsCollected | ForEach-Object { "$_" })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($type in $script:CheckCatalog.Keys) {
        $meta = $script:CheckCatalog[$type]
        if ($role -ne 'unknown' -and $meta.Roles -notcontains $role) { continue }
        $reasons = @()
        foreach ($need in $meta.Needs) {
            if ($need -eq 'acl') {
                if ($Snapshot.meta.options.skipAcl) { $reasons += 'file ACLs not read (collected with -SkipAcl)' }
                continue
            }
            $hit = $false
            foreach ($f in $failed.Keys) {
                if ($need -eq $f -or $need.StartsWith("$f.")) { $reasons += "collection of '$f' failed: $($failed[$f])"; $hit = $true }
            }
            $top = $need.Split('.')[0]
            if (-not $hit -and $collected -notcontains $top) { $reasons += "section '$top' not in the snapshot" }
        }
        if ($Extra.ContainsKey($type)) { $reasons += $Extra[$type] }
        if ($reasons.Count -gt 0) {
            $out.Add([PSCustomObject]@{ Host = (Get-SnapshotHostName $Snapshot); Type = $type; Title = $meta.Title; Reason = (($reasons | Select-Object -Unique) -join '; ') })
        }
    }
    return $out
}

# --------------------------------------------------------------------------
# One host
# --------------------------------------------------------------------------
function Test-CommandInUserWritablePlace {
    param([string]$Path)
    return ("$Path" -match '(?i)^[a-z]:\\users\\|\\appdata\\|\\temp\\|^[a-z]:\\programdata\\|\\downloads\\|^[a-z]:\\[^\\]+\.exe$')
}

function Get-WriterText {
    param($Writers)
    return ((@($Writers | Where-Object { $_ }) | ForEach-Object { "$(Get-SidLabel $_.sid) on the $($_.scope) ($($_.rights))" } | Select-Object -Unique) -join '; ')
}

function Invoke-HostChecks {
    # Returns @{ Findings; NotEvaluated } for one snapshot.
    param($Snapshot, [hashtable]$Config)
    $script:Findings = New-Object System.Collections.Generic.List[object]
    $script:CurrentHost = Get-SnapshotHostName $Snapshot
    $script:RefDate = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc
    if (-not $script:RefDate) { throw "$($Snapshot._path): meta.collectedAtUtc missing" }
    $role = Get-SnapshotRole $Snapshot
    $extra = @{}

    # Defender in passive mode (another antivirus is primary): its switches are off by design, so
    # its checks say nothing about this host.
    $d = $Snapshot.defender
    if ($d -and $d.amRunningMode -and "$($d.amRunningMode)" -notmatch '(?i)^normal$') {
        foreach ($t in @('defender_realtime_off', 'defender_tamper_off', 'defender_signatures_stale', 'defender_exclusion', 'asr_standard_rules_missing', 'defender_network_protection_off', 'defender_pua_off')) {
            $extra[$t] = "Microsoft Defender Antivirus runs in '$($d.amRunningMode)': another antivirus is primary, check that product"
        }
    }
    if ($Snapshot.credentialProtection -and $null -eq $Snapshot.credentialProtection.credentialGuardRunning) {
        $extra['credential_guard_off'] = 'Device Guard status (Win32_DeviceGuard) not readable'
    }

    $ne = @(Get-NotEvaluatedChecks -Snapshot $Snapshot -Extra $extra)
    $skip = @{}; foreach ($n in $ne) { $skip[$n.Type] = $true }
    $can = { param($t) (-not $skip.ContainsKey($t)) -and ($role -eq 'unknown' -or $script:CheckCatalog[$t].Roles -contains $role) }

    $groups = [ordered]@{
        'credential' = { Invoke-CredentialChecks $Snapshot $Config $can }
        'antivirus'  = { Invoke-AntivirusChecks $Snapshot $Config $can }
        'disk'       = { Invoke-DiskChecks $Snapshot $Config $can $role }
        'network'    = { Invoke-NetworkChecks $Snapshot $Config $can $role }
        'accounts'   = { Invoke-AccountChecks $Snapshot $Config $can }
        'privesc'    = { Invoke-PrivescChecks $Snapshot $Config $can }
        'logging'    = { Invoke-LoggingChecks $Snapshot $Config $can $role }
        'baseline'   = { Invoke-BaselineChecks $Snapshot $Config $can $role }
        'policy'     = { Invoke-PolicyChecks $Snapshot $Config $can $role }
        'patching'   = { Invoke-PatchChecks $Snapshot $Config $can }
    }
    foreach ($g in $groups.Keys) {
        # One broken group becomes a warning, not a lost report.
        try { & $groups[$g] }
        catch { Write-Warning "${script:CurrentHost}: $g checks failed: $($_.Exception.Message)" }
    }
    return [PSCustomObject]@{ Findings = $script:Findings.ToArray(); NotEvaluated = $ne }
}

function Invoke-CredentialChecks {
    param($S, $Config, $can)
    $c = $S.credentialProtection
    if (& $can 'lsa_not_protected') {
        if (@(1, 2) -notcontains [int]$c.runAsPPL -or $null -eq $c.runAsPPL) {
            Add-Finding -Type 'lsa_not_protected' -Object 'LSA' -Detail "RunAsPPL = $(if ($null -eq $c.runAsPPL) { 'not set' } else { $c.runAsPPL })."
        }
    }
    if ((& $can 'credential_guard_off') -and $c.credentialGuardRunning -eq $false) {
        Add-Finding -Type 'credential_guard_off' -Object 'Credential Guard' -Detail "Not running (VBS status $($c.vbsStatus): 0 off, 1 configured, 2 running)."
    }
    if ((& $can 'wdigest_cleartext') -and "$($c.wdigestUseLogonCredential)" -eq '1') {
        Add-Finding -Type 'wdigest_cleartext' -Object 'WDigest' -Detail 'UseLogonCredential = 1.'
    }
    if (& $can 'cached_logons_high') {
        $limit = if ((Get-SnapshotRole $S) -eq 'server') { $Config.MaxCachedLogonsServer } else { $Config.MaxCachedLogonsWorkstation }
        # Unset means the Windows default of 10.
        $n = if ("$($c.cachedLogonsCount)" -match '^\d+$') { [int]"$($c.cachedLogonsCount)" } else { 10 }
        if ($n -gt $limit) { Add-Finding -Type 'cached_logons_high' -Object 'CachedLogonsCount' -Detail "$n cached logons (limit $limit)." }
    }
    if ((& $can 'lm_hash_stored') -and "$($c.noLmHash)" -eq '0') {
        Add-Finding -Type 'lm_hash_stored' -Object 'NoLMHash' -Detail 'NoLMHash = 0.'
    }
    if (& $can 'ntlm_weak_lmcompat') {
        $lvl = if ("$($c.lmCompatibilityLevel)" -match '^\d+$') { [int]"$($c.lmCompatibilityLevel)" } else { $null }
        $eff = if ($null -eq $lvl) { 3 } else { $lvl }
        if ($eff -lt 5) { Add-Finding -Type 'ntlm_weak_lmcompat' -Object 'LmCompatibilityLevel' -Detail "Level $eff$(if ($null -eq $lvl) { ' (not set, Windows default)' })." }
    }
    if ((& $can 'anonymous_sam_enum') -and "$($c.restrictAnonymousSam)" -eq '0') {
        Add-Finding -Type 'anonymous_sam_enum' -Object 'RestrictAnonymousSAM' -Detail 'RestrictAnonymousSAM = 0.'
    }
}

function Invoke-AntivirusChecks {
    param($S, $Config, $can)
    $d = $S.defender
    if (-not $d) { return }
    if ((& $can 'defender_realtime_off') -and (-not $d.realTimeProtectionEnabled -or -not $d.antivirusEnabled)) {
        Add-Finding -Type 'defender_realtime_off' -Object 'Microsoft Defender' -Detail "Antivirus enabled: $($d.antivirusEnabled); real-time protection: $($d.realTimeProtectionEnabled)."
    }
    if ((& $can 'defender_tamper_off') -and $d.isTamperProtected -eq $false) {
        Add-Finding -Type 'defender_tamper_off' -Object 'Microsoft Defender' -Detail 'Tamper protection is off.'
    }
    if (& $can 'defender_signatures_stale') {
        $age = Get-AgeDays $d.signatureUpdatedUtc
        if ($null -ne $age -and $age -gt $Config.MaxSignatureAgeDays) {
            Add-Finding -Type 'defender_signatures_stale' -Object 'Microsoft Defender' -Detail "Signatures $age days old (limit $($Config.MaxSignatureAgeDays))."
        }
    }
    if (& $can 'defender_exclusion') {
        foreach ($p in @($d.exclusionPaths | Where-Object { $_ })) {
            $pl = "$p".ToLower()
            $risky = @($script:RiskyExclusionPathPatterns | Where-Object { $pl -match $_ }).Count -gt 0
            Add-Finding -Type 'defender_exclusion' -Object "path: $p" -Severity $(if ($risky) { 'High' } else { 'Low' }) -Detail $(if ($risky) { 'Broad or user-writable folder excluded from scanning.' } else { 'Folder or file excluded from scanning.' })
        }
        foreach ($e in @($d.exclusionExtensions | Where-Object { $_ })) {
            $risky = $script:RiskyExclusionExtensions -contains "$e".TrimStart('.', '*').ToLower()
            Add-Finding -Type 'defender_exclusion' -Object "extension: $e" -Severity $(if ($risky) { 'High' } else { 'Low' }) -Detail $(if ($risky) { 'Executable or script type excluded everywhere.' } else { 'File type excluded everywhere.' })
        }
        foreach ($e in @($d.exclusionProcesses | Where-Object { $_ })) {
            $leaf = ("$e" -split '\\')[-1].ToLower()
            $risky = ($script:RiskyExclusionProcesses -contains $leaf) -or "$e" -match '\*'
            Add-Finding -Type 'defender_exclusion' -Object "process: $e" -Severity $(if ($risky) { 'High' } else { 'Low' }) -Detail $(if ($risky) { 'Files opened by a scripting host or system tool are not scanned.' } else { 'Files opened by this process are not scanned.' })
        }
    }
    if (& $can 'asr_standard_rules_missing') {
        $set = @{}
        foreach ($r in @($d.asrRules | Where-Object { $_ })) { $set["$($r.id)".ToLower()] = $r.action }
        $missing = @($script:StandardAsrRules.Keys | Where-Object { "$($set[$_])" -ne '1' })
        if ($missing.Count -gt 0) {
            $txt = ($missing | ForEach-Object { "$($script:StandardAsrRules[$_]) [$(if ($set.ContainsKey($_)) { "action $($set[$_])" } else { 'not set' })]" }) -join '; '
            Add-Finding -Type 'asr_standard_rules_missing' -Object 'ASR' -Detail "$($missing.Count) of 3 not blocking: $txt."
        }
    }
}

# Windows Home (editionId Core, CoreN, CoreSingleLanguage, CoreCountrySpecific) has no BitLocker
# management: no pre-boot PIN and no BitLocker To Go. It only has "Device encryption", on hardware
# that supports it.
function Test-HomeEdition {
    param($S)
    return ($S.host -and $S.host.os -and "$($S.host.os.editionId)" -match '^Core')
}

function Invoke-DiskChecks {
    param($S, $Config, $can, $role)
    $b = $S.bitlocker
    $isHome = Test-HomeEdition $S
    if ($b) {
        $vols = @($b.volumes | Where-Object { $_ })
        $osVol = $vols | Where-Object { "$($_.volumeType)" -match '(?i)operating' } | Select-Object -First 1
        if (& $can 'bitlocker_os_volume_off') {
            $sev = if ($role -eq 'workstation') { 'High' } else { 'Medium' }
            # The risk is the same on Home. Only the way out changes.
            $homeNote = if ($isHome) { ' Windows Home has no BitLocker management: turn on Device encryption (Settings > Privacy & security > Device encryption; needs a TPM and a Microsoft account sign-in) or upgrade to Pro or Enterprise.' } else { '' }
            if (-not $b.featureInstalled) { Add-Finding -Type 'bitlocker_os_volume_off' -Object 'OS volume' -Severity $sev -Detail "BitLocker feature not installed.$homeNote" }
            elseif ($osVol -and "$($osVol.protectionStatus)" -ne 'On') { Add-Finding -Type 'bitlocker_os_volume_off' -Object "OS volume $($osVol.mountPoint)" -Severity $sev -Detail "Protection $($osVol.protectionStatus)$(if ($osVol.volumeStatus) { ", $($osVol.volumeStatus)" }).$homeNote" }
        }
        # Not on Home: a pre-boot PIN can't be set there, so there is nothing to ask for.
        if ((& $can 'bitlocker_tpm_only') -and -not $isHome -and $osVol -and "$($osVol.protectionStatus)" -eq 'On') {
            $kp = @($osVol.keyProtectors | Where-Object { $_ })
            if ($kp.Count -gt 0 -and $kp -contains 'Tpm' -and @($kp | Where-Object { $_ -match '(?i)pin|startupkey' }).Count -eq 0) {
                Add-Finding -Type 'bitlocker_tpm_only' -Object "OS volume $($osVol.mountPoint)" -Detail "Protectors: $($kp -join ', ')."
            }
        }
        if (& $can 'bitlocker_data_volume_off') {
            foreach ($v in @($vols | Where-Object { "$($_.volumeType)" -match '(?i)^data$|fixed' -and "$($_.protectionStatus)" -ne 'On' })) {
                Add-Finding -Type 'bitlocker_data_volume_off' -Object "volume $($v.mountPoint)" -Detail "Protection $($v.protectionStatus).$(if ($isHome) { ' Windows Home cannot encrypt data volumes with BitLocker; use Pro or Enterprise, or a third-party tool.' })"
            }
        }
    }
    $bt = $S.boot
    if ((& $can 'secure_boot_off') -and $bt) {
        if ("$($bt.firmware)" -eq 'BIOS') { Add-Finding -Type 'secure_boot_off' -Object 'Firmware' -Detail 'Legacy BIOS boot: Secure Boot unavailable.' }
        elseif ($bt.secureBootEnabled -eq $false) { Add-Finding -Type 'secure_boot_off' -Object 'Firmware' -Detail 'UEFI with Secure Boot disabled.' }
    }
}

function Invoke-NetworkChecks {
    param($S, $Config, $can, $role)
    $n = $S.network
    if (-not $n) { return }
    if ((& $can 'smb1_server_enabled') -and $n.smb1ServerEnabled -eq $true) {
        Add-Finding -Type 'smb1_server_enabled' -Object 'SMB server' -Detail 'EnableSMB1Protocol = True.'
    }
    if ((& $can 'smb_server_signing_not_required') -and $n.smbServerSigningRequired -eq $false) {
        Add-Finding -Type 'smb_server_signing_not_required' -Object 'SMB server' -Severity $(if ($role -eq 'dc') { 'High' } else { 'Medium' }) -Detail 'RequireSecuritySignature = False.'
    }
    if ((& $can 'smb_client_signing_not_required') -and $n.smbClientSigningRequired -eq $false) {
        Add-Finding -Type 'smb_client_signing_not_required' -Object 'SMB client' -Detail 'RequireSecuritySignature = False.'
    }
    if ((& $can 'llmnr_enabled') -and "$($n.llmnrPolicyEnableMulticast)" -ne '0') {
        Add-Finding -Type 'llmnr_enabled' -Object 'DNS client' -Detail $(if ($null -eq $n.llmnrPolicyEnableMulticast) { 'EnableMulticast policy not set (LLMNR on by default).' } else { "EnableMulticast = $($n.llmnrPolicyEnableMulticast)." })
    }
    if (& $can 'netbios_enabled') {
        foreach ($a in @($n.netbios | Where-Object { $_ -and "$($_.tcpipNetbiosOptions)" -ne '2' })) {
            Add-Finding -Type 'netbios_enabled' -Object "adapter: $($a.adapter)" -Detail $(if ("$($a.tcpipNetbiosOptions)" -eq '1') { 'Enabled.' } else { 'Default (enabled unless DHCP disables it).' })
        }
    }
    $profiles = @($n.firewallProfiles | Where-Object { $_ })
    if (& $can 'firewall_profile_disabled') {
        foreach ($p in @($profiles | Where-Object { -not $_.enabled })) { Add-Finding -Type 'firewall_profile_disabled' -Object "profile: $($p.name)" -Detail 'Profile disabled.' }
    }
    if (& $can 'firewall_default_inbound_allow') {
        foreach ($p in @($profiles | Where-Object { $_.enabled -and "$($_.defaultInboundAction)" -eq 'Allow' })) { Add-Finding -Type 'firewall_default_inbound_allow' -Object "profile: $($p.name)" -Detail 'Default inbound action Allow.' }
    }
    if (& $can 'firewall_drop_logging_off') {
        $nolog = @($profiles | Where-Object { $_.enabled -and "$($_.logBlocked)" -ne 'True' } | ForEach-Object { $_.name })
        if ($nolog.Count -gt 0) { Add-Finding -Type 'firewall_drop_logging_off' -Object 'Windows Firewall' -Detail "Profiles not logging dropped packets: $($nolog -join ', ')." }
    }
    if (& $can 'risky_listener') {
        $seen = @{}
        foreach ($l in @($n.listening | Where-Object { $_ })) {
            $addr = "$($l.address)"
            if ($addr -match '^(127\.|::1$|::ffff:127\.)') { continue }
            $key = "$($l.protocol)/$($l.port)"
            $name = $script:RiskyListenPorts[$key]
            if (-not $name -and $role -eq 'workstation') { $name = $script:WorkstationOnlyListenPorts[$key] }
            if (-not $name -or $seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            Add-Finding -Type 'risky_listener' -Object "$key ($name)" -Detail "Listening on $addr$(if ($l.process) { " by $($l.process)" })."
        }
    }
    $r = $S.remoteAccess
    if ($r) {
        if ((& $can 'rdp_nla_disabled') -and $r.rdpEnabled -eq $true -and $r.rdpNlaRequired -eq $false) {
            Add-Finding -Type 'rdp_nla_disabled' -Object 'RDP' -Detail 'RDP enabled, UserAuthentication = 0.'
        }
        if ((& $can 'rdp_enabled_workstation') -and $r.rdpEnabled -eq $true) {
            Add-Finding -Type 'rdp_enabled_workstation' -Object 'RDP' -Detail 'fDenyTSConnections = 0.'
        }
    }
}

function Test-LapsConfigured {
    param($S)
    $l = $S.laps
    if (-not $l) { return $false }
    if (@(1, 2) -contains [int]"$($l.windowsLapsBackupDirectory)" -and "$($l.windowsLapsBackupDirectory)" -ne '') { return $true }
    return ($l.legacyLapsEnabled -eq $true -and $l.legacyLapsCseInstalled -eq $true)
}

function Invoke-AccountChecks {
    param($S, $Config, $can)
    $a = $S.localAccounts
    $lapsOn = Test-LapsConfigured $S
    if ($a) {
        $users = @($a.users | Where-Object { $_ })
        $machineSid = "$($S.host.machineSid)"
        foreach ($u in $users) {
            $isAdmin500 = "$($u.sid)" -match '-500$'
            $isGuest = "$($u.sid)" -match '-501$'
            if ($isAdmin500 -and $u.enabled -and (& $can 'builtin_admin_enabled')) {
                Add-Finding -Type 'builtin_admin_enabled' -Object "account: $($u.name)" -Severity $(if ($lapsOn) { 'Low' } else { 'Medium' }) -Detail $(if ($lapsOn) { 'Enabled; LAPS manages its password.' } else { 'Enabled, no LAPS.' })
            }
            if ($isGuest -and $u.enabled -and (& $can 'guest_enabled')) {
                Add-Finding -Type 'guest_enabled' -Object "account: $($u.name)" -Detail 'Guest account enabled.'
            }
            if ($u.enabled -and -not $u.passwordRequired -and (& $can 'local_account_password_not_required')) {
                Add-Finding -Type 'local_account_password_not_required' -Object "account: $($u.name)" -Detail 'PASSWD_NOTREQD set on an enabled account.'
            }
            if ($u.enabled -and -not $u.passwordExpires -and -not ($isAdmin500 -and $lapsOn) -and -not $isGuest -and (& $can 'local_account_password_never_expires')) {
                $age = Get-AgeDays $u.passwordLastSetUtc
                Add-Finding -Type 'local_account_password_never_expires' -Object "account: $($u.name)" -Detail "Password never expires$(if ($null -ne $age) { "; last set $age days ago" })."
            }
        }
        if (& $can 'local_admin_member') {
            $allowed = @($Config.AllowedAdmins | ForEach-Object { "$_".ToLower() })
            foreach ($m in @($a.administrators | Where-Object { $_ })) {
                $sid = "$($m.sid)"
                $label = "$($m.path)"
                if ($sid -match '-500$' -and $machineSid -and $sid.StartsWith("$machineSid-")) { continue }
                # Domain Admins of the host's domain: expected.
                if ($sid -match '^S-1-5-21-.*-512$' -and -not ($machineSid -and $sid.StartsWith("$machineSid-"))) { continue }
                # Entra joined devices: the Global Administrator and device
                # administrator roles are added by design.
                if ($sid -match '^S-1-12-1-') { continue }
                if ($allowed -contains $sid.ToLower() -or $allowed -contains $label.ToLower() -or $allowed -contains ($label.Split('/')[-1]).ToLower()) { continue }
                $isLocal = $machineSid -and $sid.StartsWith("$machineSid-")
                $isGroup = "$($m.class)" -match '(?i)group'
                $sev = if ($isGroup -and -not $isLocal) { 'Low' } else { 'Medium' }
                $what = if ($isLocal) { 'local account' } elseif ($isGroup) { 'domain group' } else { 'domain account' }
                Add-Finding -Type 'local_admin_member' -Object "member: $label" -Severity $sev -Detail "$what ($sid) in the local Administrators group."
            }
        }
    }
    # LAPS only applies to hosts in a directory (domain or Entra joined).
    if ((& $can 'laps_not_configured') -and $S.host -and $S.host.partOfDomain -and -not $lapsOn) {
        $legacy = if ($S.laps.legacyLapsEnabled -eq $true) { "enabled, CSE installed: $($S.laps.legacyLapsCseInstalled)" } else { 'not enabled' }
        Add-Finding -Type 'laps_not_configured' -Object 'LAPS' -Detail "Windows LAPS BackupDirectory: $(if ($null -eq $S.laps.windowsLapsBackupDirectory) { 'not set' } else { $S.laps.windowsLapsBackupDirectory }); legacy LAPS: $legacy."
    }
    $u = $S.uac
    if ($u) {
        if ((& $can 'uac_disabled') -and "$($u.enableLua)" -eq '0') { Add-Finding -Type 'uac_disabled' -Object 'UAC' -Detail 'EnableLUA = 0.' }
        if ((& $can 'uac_admin_no_prompt') -and "$($u.consentPromptBehaviorAdmin)" -eq '0') { Add-Finding -Type 'uac_admin_no_prompt' -Object 'UAC' -Detail 'ConsentPromptBehaviorAdmin = 0.' }
        if ((& $can 'remote_uac_token_filter_off') -and "$($u.localAccountTokenFilterPolicy)" -eq '1') { Add-Finding -Type 'remote_uac_token_filter_off' -Object 'UAC' -Detail 'LocalAccountTokenFilterPolicy = 1.' }
        if ((& $can 'always_install_elevated') -and "$($u.alwaysInstallElevated)" -eq '1') { Add-Finding -Type 'always_install_elevated' -Object 'Windows Installer' -Detail 'AlwaysInstallElevated = 1 in the machine policy.' }
    }
}

function Test-PrivilegedTask {
    param($Task)
    $uid = "$($Task.userId)".ToUpper()
    if ($uid -in @('SYSTEM', 'S-1-5-18', 'NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'S-1-5-19', 'NETWORK SERVICE', 'S-1-5-20', 'LOCALSYSTEM')) { return $true }
    if ("$($Task.runLevel)" -eq 'Highest') { return $true }
    return ("$($Task.groupId)" -match '(?i)administrators|S-1-5-32-544')
}

function Invoke-PrivescChecks {
    param($S, $Config, $can)
    $services = @($S.services | Where-Object { $_ })
    if (& $can 'service_unquoted_path') {
        foreach ($svc in $services) {
            $p = "$($svc.pathName)".Trim()
            if (-not $p -or $p.StartsWith('"') -or $p -match '^\\\\\?\\') { continue }
            $exe = "$($svc.executable)"
            if ($exe -notmatch ' ' -or $exe -match '(?i)^[a-z]:\\windows\\') { continue }
            Add-Finding -Type 'service_unquoted_path' -Object "service: $($svc.name)" -Detail "Runs as $($svc.account): $p"
        }
    }
    if (& $can 'service_binary_writable') {
        foreach ($svc in $services) {
            $w = @($svc.writableBy | Where-Object { $_ })
            if ($w.Count -eq 0) { continue }
            $sev = if (@($w | Where-Object { $_.scope -eq 'file' }).Count -gt 0) { 'High' } else { 'Medium' }
            Add-Finding -Type 'service_binary_writable' -Object "service: $($svc.name)" -Severity $sev -Detail "$($svc.executable), runs as $($svc.account) ($($svc.state)): writable by $(Get-WriterText $w)."
        }
    }
    if (& $can 'task_binary_writable') {
        foreach ($t in @($S.scheduledTasks | Where-Object { $_ -and (Test-PrivilegedTask $_) })) {
            foreach ($act in @($t.actions | Where-Object { $_ })) {
                $w = @($act.writableBy | Where-Object { $_ })
                if ($w.Count -eq 0) { continue }
                $sev = if (@($w | Where-Object { $_.scope -eq 'file' }).Count -gt 0) { 'High' } else { 'Medium' }
                Add-Finding -Type 'task_binary_writable' -Object "task: $($t.path)$($t.name) -> $($act.executable)" -Severity $sev -Detail "Runs as $(if ($t.userId) { $t.userId } else { $t.groupId }) (run level $($t.runLevel)): writable by $(Get-WriterText $w)."
            }
        }
    }
    if (& $can 'autorun_writable') {
        foreach ($r in @($S.autoruns | Where-Object { $_ })) {
            $w = @($r.writableBy | Where-Object { $_ })
            if ($w.Count -eq 0) { continue }
            $sev = if (@($w | Where-Object { $_.scope -eq 'file' }).Count -gt 0) { 'High' } else { 'Medium' }
            Add-Finding -Type 'autorun_writable' -Object "autorun: $($r.location) $($r.name)" -Severity $sev -Detail "$($r.executable): writable by $(Get-WriterText $w)."
        }
    }
    if (& $can 'spooler_on_dc') {
        $sp = $services | Where-Object { $_.name -eq 'Spooler' } | Select-Object -First 1
        if ($sp -and "$($sp.state)" -eq 'Running') { Add-Finding -Type 'spooler_on_dc' -Object 'service: Spooler' -Detail "Running, start mode $($sp.startMode)." }
    }
}

function Get-AuditValue {
    # 0-3 from the numeric Setting Value. The English text is used only when the value is missing
    # (an older snapshot), and the result is $null when nothing is readable.
    param($Row)
    if ($null -ne $Row.value -and "$($Row.value)" -match '^\d+$') { return [int]$Row.value }
    switch -Regex ("$($Row.inclusion)".Trim()) {
        '^(?i)success and failure$' { return 3 }
        '^(?i)success$' { return 1 }
        '^(?i)failure$' { return 2 }
        '^(?i)no auditing$' { return 0 }
    }
    return $null
}

function Invoke-LoggingChecks {
    param($S, $Config, $can, $role)
    $a = $S.audit
    if ($a -and (& $can 'audit_policy_gaps')) {
        $byGuid = @{}
        foreach ($row in @($a.subcategories | Where-Object { $_ })) { $byGuid["$($row.guid)".ToLower()] = $row }
        $gaps = @()
        foreach ($req in $script:RequiredAudit) {
            if ($req.Dc -and $role -ne 'dc') { continue }
            $row = $byGuid[$req.Guid]
            $have = if ($row) { Get-AuditValue $row } else { 0 }
            if ($null -eq $have) { continue }
            if (($have -band $req.Need) -ne $req.Need) {
                $want = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }[$req.Need]
                $gaps += "$($req.Name) (needs $want, has $(@{ 0 = 'none'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }[$have]))"
            }
        }
        if ($gaps.Count -gt 0) { Add-Finding -Type 'audit_policy_gaps' -Object 'Advanced audit policy' -Detail "$($gaps.Count) subcategories short: $($gaps -join '; ')." }
    }
    if ($a -and (& $can 'cmdline_audit_off') -and "$($a.processCreationIncludeCmdLine)" -ne '1') {
        Add-Finding -Type 'cmdline_audit_off' -Object 'Process creation events' -Detail 'ProcessCreationIncludeCmdLine_Enabled not set to 1.'
    }
    if ($a -and (& $can 'security_log_small') -and $null -ne $a.securityLogMaxSizeBytes) {
        $kb = [int64]$a.securityLogMaxSizeBytes / 1KB
        if ($kb -lt $Config.MinSecurityLogKB) { Add-Finding -Type 'security_log_small' -Object 'Security log' -Detail "Maximum size $([int64]$kb) KB (minimum $($Config.MinSecurityLogKB) KB)." }
    }
    $p = $S.powershell
    if ($p) {
        if ((& $can 'powershell_scriptblock_logging_off') -and "$($p.scriptBlockLogging)" -ne '1') {
            Add-Finding -Type 'powershell_scriptblock_logging_off' -Object 'PowerShell' -Detail 'EnableScriptBlockLogging not set to 1.'
        }
        if ((& $can 'powershell_v2_enabled') -and "$($p.v2EngineVersion)" -eq '2.0') {
            Add-Finding -Type 'powershell_v2_enabled' -Object 'PowerShell 2.0' -Detail 'The 2.0 engine is registered (optional feature installed).'
        }
    }
}

# Settings from the CIS Windows 11 Enterprise benchmark (v3.0.0). Each finding quotes its rule
# number. A value that isn't set is judged only where the Windows default is itself the problem.
$script:CisDisableServices = @{
    Browser = '5.3'; iisadmin = '5.6'; irmon = '5.7'; LxssManager = '5.9'; FTPSVC = '5.10'; sshd = '5.12'; RpcLocator = '5.23'
    RemoteAccess = '5.25'; simptcp = '5.27'; sacsvr = '5.29'; SSDPSRV = '5.30'; upnphost = '5.31'; WMSvc = '5.32'; WMPNetworkSvc = '5.35'
    icssvc = '5.36'; W3SVC = '5.40'; XboxGipSvc = '5.41'; XblAuthManager = '5.42'; XblGameSave = '5.43'; XboxNetApiSvc = '5.44'
}
# Network-facing ones are Medium.
$script:CisDisableServicesMedium = @('iisadmin', 'FTPSVC', 'sshd', 'RpcLocator', 'RemoteAccess', 'simptcp', 'WMSvc', 'W3SVC', 'SSDPSRV', 'upnphost')

function ConvertTo-Int64OrNull {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try { return [int64]$Value } catch { return $null }
}

function Invoke-BaselineChecks {
    param($S, $Config, $can, $role)
    $h = $S.hardening
    if ($h) {
        $n = { param($v) ConvertTo-Int64OrNull $v }
        $v = & $n $h.smbInsecureGuestAuth
        if ((& $can 'smb_insecure_guest_auth') -and $v -eq 1) { Add-Finding -Type 'smb_insecure_guest_auth' -Object 'SMB client' -Detail 'AllowInsecureGuestAuth = 1 (CIS 18.6.8.1 expects 0).' }
        $v = & $n $h.ldapClientIntegrity
        if ((& $can 'ldap_client_signing_off') -and $v -eq 0) { Add-Finding -Type 'ldap_client_signing_off' -Object 'LDAP client' -Detail 'LDAPClientIntegrity = 0 (CIS 2.3.11.8 expects 1 or 2).' }
        if (& $can 'ntlm_min_session_security_weak') {
            foreach ($pair in @(@('NTLM client', 'ntlmMinClientSec', 'NTLMMinClientSec', '2.3.11.9'), @('NTLM server', 'ntlmMinServerSec', 'NTLMMinServerSec', '2.3.11.10'))) {
                $v = & $n $h.($pair[1])
                if ($null -ne $v -and (($v -band 537395200) -ne 537395200)) {
                    Add-Finding -Type 'ntlm_min_session_security_weak' -Object $pair[0] -Detail ("{0} = 0x{1:X} (CIS {2} expects 0x20080000: NTLMv2 and 128-bit)." -f $pair[2], $v, $pair[3])
                }
            }
        }
        $v = & $n $h.everyoneIncludesAnonymous
        if ((& $can 'everyone_includes_anonymous') -and $v -eq 1) { Add-Finding -Type 'everyone_includes_anonymous' -Object 'EveryoneIncludesAnonymous' -Detail 'EveryoneIncludesAnonymous = 1 (CIS 2.3.10.5 expects 0).' }
        $v = & $n $h.limitBlankPasswordUse
        if ((& $can 'blank_password_network_logon') -and $v -eq 0) { Add-Finding -Type 'blank_password_network_logon' -Object 'LimitBlankPasswordUse' -Detail 'LimitBlankPasswordUse = 0 (CIS 2.3.1.3 expects 1).' }
        $v = & $n $h.forceGuest
        if ((& $can 'force_guest_sharing_model') -and $v -eq 1) { Add-Finding -Type 'force_guest_sharing_model' -Object 'ForceGuest' -Detail 'ForceGuest = 1, "Guest only" (CIS 2.3.10.12 expects 0, Classic).' }
        $v = & $n $h.enablePlainTextPassword
        if ((& $can 'smb_plaintext_password') -and $v -eq 1) { Add-Finding -Type 'smb_plaintext_password' -Object 'SMB client' -Detail 'EnablePlainTextPassword = 1 (CIS 2.3.8.3 expects 0).' }
        if (& $can 'null_session_access') {
            # How many, never which: share and pipe names are not copied into findings.
            $c = & $n $h.nullSessionSharesCount
            if ($c -gt 0) { Add-Finding -Type 'null_session_access' -Object 'NullSessionShares' -Detail "$c share(s) listed as accessible anonymously (CIS 2.3.10.11 expects none)." }
            $c = & $n $h.nullSessionPipesCount
            if ($c -gt 0) { Add-Finding -Type 'null_session_access' -Object 'NullSessionPipes' -Detail "$c named pipe(s) listed as accessible anonymously (CIS 2.3.10.6 expects none)." }
            $v = & $n $h.restrictNullSessAccess
            if ($v -eq 0) { Add-Finding -Type 'null_session_access' -Object 'RestrictNullSessAccess' -Detail 'RestrictNullSessAccess = 0 (CIS 2.3.10.9 expects 1).' }
        }
        if ((& $can 'secure_channel_unprotected') -and $S.host -and $S.host.partOfDomain -and $h.netlogon) {
            $nl = $h.netlogon
            foreach ($pair in @(@('requireSignOrSeal', 'RequireSignOrSeal', '2.3.6.1'), @('sealSecureChannel', 'SealSecureChannel', '2.3.6.2'), @('signSecureChannel', 'SignSecureChannel', '2.3.6.3'), @('requireStrongKey', 'RequireStrongKey', '2.3.6.6'))) {
                $v = & $n $nl.($pair[0])
                if ($v -eq 0) { Add-Finding -Type 'secure_channel_unprotected' -Object "Netlogon: $($pair[1])" -Detail "$($pair[1]) = 0 (CIS $($pair[2]) expects 1)." }
            }
            $v = & $n $nl.disablePasswordChange
            if ($v -eq 1) { Add-Finding -Type 'secure_channel_unprotected' -Object 'Netlogon: DisablePasswordChange' -Detail 'DisablePasswordChange = 1: the machine account password is never rotated (CIS 2.3.6.4 expects 0).' }
            $v = & $n $nl.maximumPasswordAge
            if ($null -ne $v -and ($v -eq 0 -or $v -gt 30)) { Add-Finding -Type 'secure_channel_unprotected' -Object 'Netlogon: MaximumPasswordAge' -Detail "MaximumPasswordAge = $v days (CIS 2.3.6.5 expects 1 to 30)." }
        }
        if ((& $can 'winrm_insecure_auth') -and $h.winrm) {
            $w = $h.winrm
            foreach ($row in @(@('clientAllowBasic', 'WinRM client: Basic authentication', 'AllowBasic', '18.10.88.1.1'), @('clientAllowUnencryptedTraffic', 'WinRM client: unencrypted traffic', 'AllowUnencryptedTraffic', '18.10.88.1.2'),
                    @('clientAllowDigest', 'WinRM client: Digest authentication', 'AllowDigest', '18.10.88.1.3'), @('serviceAllowBasic', 'WinRM service: Basic authentication', 'AllowBasic', '18.10.88.2.1'),
                    @('serviceAllowUnencryptedTraffic', 'WinRM service: unencrypted traffic', 'AllowUnencryptedTraffic', '18.10.88.2.3'))) {
                $v = & $n $w.($row[0])
                if ($v -eq 1) { Add-Finding -Type 'winrm_insecure_auth' -Object $row[1] -Detail "$($row[2]) = 1 (CIS $($row[3]) expects 0)." }
            }
        }
        $v = & $n $h.mrxsmb10Start
        if ((& $can 'smb1_client_driver_enabled') -and $null -ne $v -and $v -ne 4) { Add-Finding -Type 'smb1_client_driver_enabled' -Object 'mrxsmb10 driver' -Detail "Start = $v (CIS 18.4.3 expects 4, disabled)." }
        if ((& $can 'ip_stack_hardening_gaps') -and $h.ipStack) {
            $ip = $h.ipStack
            $v = & $n $ip.disableIpSourceRoutingV4
            if ($null -ne $v -and $v -lt 2) { Add-Finding -Type 'ip_stack_hardening_gaps' -Object 'IPv4 source routing' -Detail "DisableIPSourceRouting = $v (CIS 18.5.3 expects 2)." }
            $v = & $n $ip.disableIpSourceRoutingV6
            if ($null -ne $v -and $v -lt 2) { Add-Finding -Type 'ip_stack_hardening_gaps' -Object 'IPv6 source routing' -Detail "DisableIPSourceRouting = $v (CIS 18.5.2 expects 2)." }
            $v = & $n $ip.enableIcmpRedirect
            if ($v -eq 1) { Add-Finding -Type 'ip_stack_hardening_gaps' -Object 'ICMP redirects' -Detail 'EnableICMPRedirect = 1 (CIS 18.5.5 expects 0).' }
        }
        $r = $S.remoteAccess
        if ((& $can 'rdp_policy_gaps') -and $r -and $r.rdpEnabled -eq $true -and $h.rdpPolicy) {
            $rp = $h.rdpPolicy
            $v = & $n $rp.securityLayer
            if ($null -ne $v -and $v -lt 2) { Add-Finding -Type 'rdp_policy_gaps' -Object 'Security layer' -Detail "SecurityLayer = $v (CIS 18.10.56.3.9.3 expects 2, SSL/TLS)." }
            $v = & $n $rp.minEncryptionLevel
            if ($null -ne $v -and $v -lt 3) { Add-Finding -Type 'rdp_policy_gaps' -Object 'Encryption level' -Detail "MinEncryptionLevel = $v (CIS 18.10.56.3.9.5 expects 3, High)." }
            $v = & $n $rp.promptForPassword
            if ($v -eq 0) { Add-Finding -Type 'rdp_policy_gaps' -Object 'Password prompt' -Detail 'fPromptForPassword = 0 (CIS 18.10.56.3.9.1 expects 1).' }
            $v = & $n $rp.encryptRpcTraffic
            if ($v -eq 0) { Add-Finding -Type 'rdp_policy_gaps' -Object 'Secure RPC' -Detail 'fEncryptRPCTraffic = 0 (CIS 18.10.56.3.9.2 expects 1).' }
            $v = & $n $rp.disableDriveRedirection
            if ($v -ne 1) { Add-Finding -Type 'rdp_policy_gaps' -Object 'Drive redirection' -Detail "fDisableCdm = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 18.10.56.3.3.3 expects 1)." }
        }
        if ((& $can 'autoplay_enabled') -and $h.explorer) {
            $ex = $h.explorer
            $v = & $n $ex.noDriveTypeAutoRun
            if ($v -ne 255) { Add-Finding -Type 'autoplay_enabled' -Object 'NoDriveTypeAutoRun' -Detail "NoDriveTypeAutoRun = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 18.10.7.3 expects 255, all drives)." }
            $v = & $n $ex.noAutorun
            if ($v -ne 1) { Add-Finding -Type 'autoplay_enabled' -Object 'NoAutorun' -Detail "NoAutorun = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 18.10.7.2 expects 1)." }
            $v = & $n $ex.noAutoplayForNonVolume
            if ($v -ne 1) { Add-Finding -Type 'autoplay_enabled' -Object 'NoAutoplayfornonVolume' -Detail "NoAutoplayfornonVolume = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 18.10.7.1 expects 1)." }
        }
        if ((& $can 'autologon_enabled') -and $h.winlogon -and "$($h.winlogon.autoAdminLogon)" -eq '1') {
            $stored = [bool]$h.winlogon.defaultPasswordPresent
            Add-Finding -Type 'autologon_enabled' -Object 'Winlogon' -Severity $(if ($stored) { 'High' } else { 'Medium' }) -Detail "AutoAdminLogon = 1$(if ($stored) { '; the password is stored in the registry (DefaultPassword)' }) (CIS 18.5.1 expects 0)."
        }
        $il = $h.interactiveLogon
        if ($il) {
            $v = & $n $il.inactivityTimeoutSecs
            if ((& $can 'inactivity_lock_missing') -and ($null -eq $v -or $v -eq 0 -or $v -gt 900)) {
                Add-Finding -Type 'inactivity_lock_missing' -Object 'InactivityTimeoutSecs' -Detail "$(if ($null -eq $v) { 'Not set' } else { "InactivityTimeoutSecs = $v" }) (CIS 2.3.7.4 expects 1 to 900 seconds)."
            }
            if ((& $can 'logon_banner_missing') -and -not $il.legalNoticeTextSet -and -not $il.legalNoticeCaptionSet) {
                Add-Finding -Type 'logon_banner_missing' -Object 'Logon message' -Detail 'No LegalNoticeCaption or LegalNoticeText (CIS 2.3.7.5, 2.3.7.6).'
            }
            if (& $can 'interactive_logon_gaps') {
                $v = & $n $il.dontDisplayLastUserName
                if ($v -ne 1) { Add-Finding -Type 'interactive_logon_gaps' -Object 'Last signed-in user shown' -Detail "DontDisplayLastUserName = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 2.3.7.2 expects 1)." }
                $v = & $n $il.disableCad
                if ($v -eq 1) { Add-Finding -Type 'interactive_logon_gaps' -Object 'CTRL+ALT+DEL not required' -Detail 'DisableCAD = 1 (CIS 2.3.7.1 expects 0).' }
            }
        }
        if ((& $can 'uac_hardening_gaps') -and $h.uacExtra -and $S.uac) {
            $ux = $h.uacExtra
            $v = & $n $S.uac.filterAdministratorToken
            if ($v -ne 1) { Add-Finding -Type 'uac_hardening_gaps' -Object 'Admin Approval Mode for the built-in Administrator' -Detail "FilterAdministratorToken = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 2.3.17.1 expects 1)." }
            $v = & $n $ux.enableInstallerDetection
            if ($v -eq 0) { Add-Finding -Type 'uac_hardening_gaps' -Object 'Installer detection' -Detail 'EnableInstallerDetection = 0 (CIS 2.3.17.4 expects 1).' }
            $v = & $n $ux.enableSecureUiaPaths
            if ($v -eq 0) { Add-Finding -Type 'uac_hardening_gaps' -Object 'Secure UIAccess paths' -Detail 'EnableSecureUIAPaths = 0 (CIS 2.3.17.5 expects 1).' }
            $v = & $n $ux.promptOnSecureDesktop
            if ($v -eq 0) { Add-Finding -Type 'uac_hardening_gaps' -Object 'Secure desktop for prompts' -Severity 'Medium' -Detail 'PromptOnSecureDesktop = 0: elevation prompts can be spoofed or clicked by other programs (CIS 2.3.17.7 expects 1).' }
            $v = & $n $ux.enableVirtualization
            if ($v -eq 0) { Add-Finding -Type 'uac_hardening_gaps' -Object 'File and registry virtualization' -Detail 'EnableVirtualization = 0 (CIS 2.3.17.8 expects 1).' }
        }
        $v = & $n $h.noAutoUpdate
        if ((& $can 'wu_auto_updates_disabled') -and $v -eq 1) { Add-Finding -Type 'wu_auto_updates_disabled' -Object 'Automatic Updates' -Detail 'NoAutoUpdate = 1 (CIS 18.10.92.2.1 expects 0).' }
        $v = & $n $h.enableSmartScreen
        if ((& $can 'smartscreen_off') -and $v -eq 0) { Add-Finding -Type 'smartscreen_off' -Object 'SmartScreen' -Detail 'EnableSmartScreen = 0 (CIS 18.10.75.2.1 expects 1).' }
        if (& $can 'event_logs_small') {
            foreach ($lg in @($h.eventLogs | Where-Object { $_ })) {
                $b = & $n $lg.maxSizeBytes
                if ($null -ne $b -and ($b / 1KB) -lt 32768) { Add-Finding -Type 'event_logs_small' -Object "$($lg.name) log" -Detail "Maximum size $([int64]($b / 1KB)) KB (CIS $(if ($lg.name -eq 'Application') { '18.10.25.1.2' } else { '18.10.25.4.2' }) expects at least 32768 KB)." }
            }
        }
        $v = & $n $h.disableExceptionChainValidation
        if ((& $can 'sehop_disabled') -and $v -eq 1) { Add-Finding -Type 'sehop_disabled' -Object 'SEHOP' -Detail 'DisableExceptionChainValidation = 1 (CIS 18.4.6 expects 0).' }
        $v = & $n $h.safeDllSearchMode
        if ((& $can 'safe_dll_search_off') -and $v -eq 0) { Add-Finding -Type 'safe_dll_search_off' -Object 'SafeDllSearchMode' -Detail 'SafeDllSearchMode = 0 (CIS 18.5.9 expects 1).' }
        if (& $can 'lsa_weak_auth_options') {
            $v = & $n $h.allowNullSessionFallback
            if ($v -eq 1) { Add-Finding -Type 'lsa_weak_auth_options' -Object 'LocalSystem NULL session fallback' -Detail 'AllowNullSessionFallback = 1 (CIS 2.3.11.2 expects 0).' }
            $v = & $n $h.allowOnlineId
            if ($v -eq 1) { Add-Finding -Type 'lsa_weak_auth_options' -Object 'PKU2U online identities' -Detail 'AllowOnlineID = 1 (CIS 2.3.11.3 expects 0).' }
        }
    }
    # Data that other sections already hold.
    $cp = $S.credentialProtection
    if ($cp -and (& $can 'anonymous_shares_enum') -and "$($cp.restrictAnonymous)" -ne '1') {
        Add-Finding -Type 'anonymous_shares_enum' -Object 'RestrictAnonymous' -Detail "RestrictAnonymous = $(if ($null -eq $cp.restrictAnonymous) { 'not set' } else { $cp.restrictAnonymous }) (CIS 2.3.10.3 expects 1)."
    }
    $ps = $S.powershell
    if ($ps -and (& $can 'powershell_transcription_off') -and "$($ps.transcription)" -ne '1') {
        Add-Finding -Type 'powershell_transcription_off' -Object 'PowerShell transcription' -Detail 'EnableTranscripting not set to 1 (CIS 18.10.86.2, Level 2).'
    }
    $d = $S.defender
    if ($d -and (& $can 'defender_network_protection_off') -and $null -ne $d.networkProtection -and "$($d.networkProtection)" -ne '1') {
        $word = @{ '0' = 'disabled'; '2' = 'audit only' }["$($d.networkProtection)"]
        Add-Finding -Type 'defender_network_protection_off' -Object 'Network Protection' -Detail "Network Protection is $(if ($word) { $word } else { "set to $($d.networkProtection)" }) (CIS 18.10.42.6.3.1 expects enabled)."
    }
    if ($d -and (& $can 'defender_pua_off') -and $null -ne $d.puaProtection -and "$($d.puaProtection)" -ne '1') {
        $word = @{ '0' = 'disabled'; '2' = 'audit only' }["$($d.puaProtection)"]
        Add-Finding -Type 'defender_pua_off' -Object 'PUA protection' -Detail "PUA protection is $(if ($word) { $word } else { "set to $($d.puaProtection)" }) (CIS 18.10.42.16 expects enabled)."
    }
    if (& $can 'service_should_be_disabled') {
        foreach ($svc in @($S.services | Where-Object { $_ })) {
            $name = "$($svc.name)"
            if (-not $script:CisDisableServices.Contains($name)) { continue }
            if ("$($svc.state)" -ne 'Running' -and "$($svc.startMode)" -ne 'Auto') { continue }
            $sev = if ($script:CisDisableServicesMedium -contains $name) { 'Medium' } else { 'Low' }
            Add-Finding -Type 'service_should_be_disabled' -Object "service: $name" -Severity $sev -Detail "$($svc.state), start mode $($svc.startMode) (CIS $($script:CisDisableServices[$name]) expects disabled)."
        }
    }
}
# User rights (CIS 2.2.x, Level 1, Windows 11 workstation): who may hold each one. The expected
# principals are SIDs. Sev is High for the rights that lead straight to SYSTEM.
$script:CisUserRights = @(
    @{ Right = 'SeTrustedCredManAccessPrivilege'; Rule = '2.2.1'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeNetworkLogonRight'; Rule = '2.2.2'; Expect = @('S-1-5-32-544', 'S-1-5-32-555'); Sev = 'Medium' }
    @{ Right = 'SeTcbPrivilege'; Rule = '2.2.3'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeInteractiveLogonRight'; Rule = '2.2.5'; Expect = @('S-1-5-32-544', 'S-1-5-32-545'); Sev = 'Medium' }
    @{ Right = 'SeRemoteInteractiveLogonRight'; Rule = '2.2.6'; Expect = @('S-1-5-32-544', 'S-1-5-32-555'); Sev = 'Medium' }
    @{ Right = 'SeBackupPrivilege'; Rule = '2.2.7'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeCreatePagefilePrivilege'; Rule = '2.2.10'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeCreateTokenPrivilege'; Rule = '2.2.11'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeCreatePermanentPrivilege'; Rule = '2.2.13'; Expect = @(); Sev = 'Medium' }
    @{ Right = 'SeDebugPrivilege'; Rule = '2.2.15'; Expect = @('S-1-5-32-544'); Sev = 'High' }
    @{ Right = 'SeEnableDelegationPrivilege'; Rule = '2.2.21'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeRemoteShutdownPrivilege'; Rule = '2.2.22'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeLoadDriverPrivilege'; Rule = '2.2.26'; Expect = @('S-1-5-32-544'); Sev = 'High' }
    @{ Right = 'SeLockMemoryPrivilege'; Rule = '2.2.27'; Expect = @(); Sev = 'Medium' }
    @{ Right = 'SeSecurityPrivilege'; Rule = '2.2.30'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeRelabelPrivilege'; Rule = '2.2.31'; Expect = @(); Sev = 'Medium' }
    @{ Right = 'SeSystemEnvironmentPrivilege'; Rule = '2.2.32'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeManageVolumePrivilege'; Rule = '2.2.33'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeProfileSingleProcessPrivilege'; Rule = '2.2.34'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeRestorePrivilege'; Rule = '2.2.37'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeTakeOwnershipPrivilege'; Rule = '2.2.39'; Expect = @('S-1-5-32-544'); Sev = 'High' }
)
# Deny rights: principals that must be listed.
$script:CisDenyRights = @(
    @{ Right = 'SeDenyNetworkLogonRight'; Rule = '2.2.16'; Need = @('S-1-5-32-546', 'S-1-5-113') }
    @{ Right = 'SeDenyBatchLogonRight'; Rule = '2.2.17'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyServiceLogonRight'; Rule = '2.2.18'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyInteractiveLogonRight'; Rule = '2.2.19'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyRemoteInteractiveLogonRight'; Rule = '2.2.20'; Need = @('S-1-5-32-546', 'S-1-5-113') }
)
$script:PrincipalLabels = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE'; 'S-1-5-6' = 'SERVICE'
    'S-1-5-113' = 'Local account'; 'S-1-5-114' = 'Local account and member of Administrators'; 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-551' = 'Backup Operators'; 'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-568' = 'IIS_IUSRS'; 'S-1-5-90-0' = 'Window Manager Group'; 'S-1-5-83-0' = 'Virtual Machines'
}
function Get-PrincipalLabel {
    param([string]$Principal)
    if ($script:PrincipalLabels.ContainsKey($Principal)) { return $script:PrincipalLabels[$Principal] }
    return (Get-SidLabel $Principal)
}

function Invoke-PolicyChecks {
    param($S, $Config, $can, $role)
    $sp = $S.securityPolicy
    if (-not $sp) { return }
    $a = $sp.systemAccess
    $val = { param($name) if ($a -and $null -ne $a.$name -and "$($a.$name)" -match '^-?\d+$') { [int64]$a.$name } else { $null } }
    if (& $can 'password_policy_weak') {
        $v = & $val 'PasswordHistorySize';    if ($null -ne $v -and $v -lt 24) { Add-Finding -Type 'password_policy_weak' -Object 'Password history' -Detail "PasswordHistorySize = $v (CIS 1.1.1 expects 24 or more)." }
        $v = & $val 'MaximumPasswordAge';     if ($null -ne $v -and ($v -lt 1 -or $v -gt 365)) { Add-Finding -Type 'password_policy_weak' -Object 'Maximum password age' -Detail "MaximumPasswordAge = $(if ($v -lt 1) { 'never expires' } else { "$v days" }) (CIS 1.1.2 expects 1 to 365 days)." }
        $v = & $val 'MinimumPasswordAge';     if ($null -ne $v -and $v -lt 1) { Add-Finding -Type 'password_policy_weak' -Object 'Minimum password age' -Detail "MinimumPasswordAge = $v days (CIS 1.1.3 expects 1 or more)." }
        $v = & $val 'MinimumPasswordLength';  if ($null -ne $v -and $v -lt 14) { Add-Finding -Type 'password_policy_weak' -Object 'Minimum password length' -Detail "MinimumPasswordLength = $v (CIS 1.1.4 expects 14 or more)." }
        $v = & $val 'PasswordComplexity';     if ($null -ne $v -and $v -ne 1) { Add-Finding -Type 'password_policy_weak' -Object 'Password complexity' -Detail "PasswordComplexity = $v (CIS 1.1.5 expects 1)." }
        $v = & $val 'ClearTextPassword';      if ($null -ne $v -and $v -ne 0) { Add-Finding -Type 'password_policy_weak' -Object 'Reversible encryption' -Detail "ClearTextPassword = ${v}: passwords are stored reversibly (CIS 1.1.7 expects 0)." }
    }
    if (& $can 'account_lockout_weak') {
        $thr = & $val 'LockoutBadCount'
        if ($null -ne $thr -and ($thr -eq 0 -or $thr -gt 5)) {
            Add-Finding -Type 'account_lockout_weak' -Object 'Lockout threshold' -Detail "LockoutBadCount = $(if ($thr -eq 0) { '0, accounts are never locked' } else { $thr }) (CIS 1.2.2 expects 1 to 5)."
        }
        # Duration and reset only matter once a threshold is set. A duration of -1 means the account
        # stays locked until an administrator unlocks it.
        if ($null -ne $thr -and $thr -gt 0) {
            $v = & $val 'LockoutDuration'
            if ($null -ne $v -and $v -ge 0 -and $v -lt 15) { Add-Finding -Type 'account_lockout_weak' -Object 'Lockout duration' -Detail "LockoutDuration = $v minutes (CIS 1.2.1 expects 15 or more)." }
            $v = & $val 'ResetLockoutCount'
            if ($null -ne $v -and $v -lt 15) { Add-Finding -Type 'account_lockout_weak' -Object 'Lockout counter reset' -Detail "ResetLockoutCount = $v minutes (CIS 1.2.4 expects 15 or more)." }
        }
    }
    $pr = $sp.privilegeRights
    if ($pr -and (& $can 'user_rights_excessive')) {
        foreach ($spec in $script:CisUserRights) {
            $holders = $pr.($spec.Right)
            if ($null -eq $holders -and -not ($pr.PSObject.Properties.Name -contains $spec.Right)) { continue }
            $extra = @(@($holders) | Where-Object { $_ -and ($spec.Expect -notcontains "$_") })
            if ($extra.Count -gt 0) {
                $who = ($extra | ForEach-Object { Get-PrincipalLabel "$_" }) -join ', '
                Add-Finding -Type 'user_rights_excessive' -Object "right: $($spec.Right)" -Severity $spec.Sev -Detail "Also held by $who (CIS $($spec.Rule) expects $(if ($spec.Expect.Count -eq 0) { 'no one' } else { ($spec.Expect | ForEach-Object { Get-PrincipalLabel $_ }) -join ', ' }))."
            }
        }
    }
    if ($pr -and (& $can 'deny_logon_rights_missing')) {
        foreach ($spec in $script:CisDenyRights) {
            if (-not ($pr.PSObject.Properties.Name -contains $spec.Right)) { $holders = @() } else { $holders = @($pr.($spec.Right)) }
            $missing = @($spec.Need | Where-Object { $holders -notcontains $_ })
            if ($missing.Count -gt 0) {
                Add-Finding -Type 'deny_logon_rights_missing' -Object "right: $($spec.Right)" -Detail "Missing: $(($missing | ForEach-Object { Get-PrincipalLabel $_ }) -join ', ') (CIS $($spec.Rule))."
            }
        }
    }
}
function Invoke-PatchChecks {
    param($S, $Config, $can)
    if ($S.host -and $S.host.os) {
        $sup = Get-OsSupport $S.host.os
        if ($sup.Known -and $sup.EndUtc) {
            $left = [int][Math]::Floor(($sup.EndUtc - $script:RefDate).TotalDays)
            if ($left -lt 0 -and (& $can 'os_unsupported')) {
                Add-Finding -Type 'os_unsupported' -Object $sup.Name -Detail "Support ended $($sup.EndUtc.ToString('yyyy-MM-dd')) ($(-$left) days before collection)."
            }
            elseif ($left -ge 0 -and $left -le $Config.SupportWarningDays -and (& $can 'os_support_ending')) {
                Add-Finding -Type 'os_support_ending' -Object $sup.Name -Detail "Support ends $($sup.EndUtc.ToString('yyyy-MM-dd')), $left days after collection."
            }
        }
    }
    if ($S.patches -and (& $can 'updates_stale')) {
        # The Windows hotfix list is the record of the operating system's own updates. The Windows
        # Update history also holds .NET, PowerShell, Defender and store updates that arrive every
        # month whether or not Windows is patched, so it is only the fallback for when no hotfix has
        # a date.
        $osDates = @($S.patches.hotfixes | Where-Object { $_ -and $_.installedOnUtc } | ForEach-Object { ConvertTo-UtcDate $_.installedOnUtc } | Where-Object { $_ } | Sort-Object -Descending)
        $source = 'hotfix list'
        $dates = $osDates
        if ($dates.Count -eq 0 -and $S.patches.lastUpdateInstalledUtc) {
            $dates = @(ConvertTo-UtcDate $S.patches.lastUpdateInstalledUtc | Where-Object { $_ })
            $source = 'Windows Update history, no dated hotfix'
        }
        if ($dates.Count -gt 0) {
            $age = [int][Math]::Floor(($script:RefDate - $dates[0]).TotalDays)
            if ($age -gt $Config.MaxPatchAgeDays) {
                # The Windows Update screen shows the date of the last item of any kind. Say so when
                # it is later than ours, or the finding looks wrong to whoever checks it.
                $later = ''
                $hist = if ($S.patches.lastUpdateInstalledUtc) { ConvertTo-UtcDate $S.patches.lastUpdateInstalledUtc } else { $null }
                if ($hist -and $osDates.Count -gt 0 -and ($hist - $dates[0]).TotalDays -ge 1) {
                    $later = " The Windows Update history shows a later item on $($hist.ToString('yyyy-MM-dd')): that is .NET, PowerShell, Defender or app updates delivered through Microsoft Update, not an update of Windows itself."
                }
                Add-Finding -Type 'updates_stale' -Object 'Windows Update' -Detail "Last Windows update installed $($dates[0].ToString('yyyy-MM-dd')) ($source), $age days before collection (limit $($Config.MaxPatchAgeDays)).$later"
            }
        }
    }
}

# --------------------------------------------------------------------------
# Exceptions and score
# --------------------------------------------------------------------------
function Import-Exceptions {
    param([string]$Path)
    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Exceptions file not found: $Path" }
    return @([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path) | ConvertFrom-Json)
}

function Split-FindingsByException {
    # An exception is { type, host ('*' = any), object ('*' = any), reason, owner, expires }.
    # Expired ones are ignored and listed, and "expired" is judged against the newest snapshot of
    # the run.
    param($Findings, $Exceptions, [datetime]$AsOf)
    $active = New-Object System.Collections.Generic.List[object]
    $accepted = New-Object System.Collections.Generic.List[object]
    $expired = New-Object System.Collections.Generic.List[object]
    $valid = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Exceptions | Where-Object { $_ })) {
        $exp = ConvertTo-UtcDate $e.expires
        if ($null -ne $exp -and $exp -lt $AsOf) { $expired.Add($e) } else { $valid.Add($e) }
    }
    foreach ($f in $Findings) {
        $match = $null
        foreach ($e in $valid) {
            if ($e.type -ne $f.Type) { continue }
            $hostOk = (-not $e.host) -or $e.host -eq '*' -or $e.host -eq $f.Host
            $objOk = (-not $e.object) -or $e.object -eq '*' -or $e.object -eq $f.Object
            if ($hostOk -and $objOk) { $match = $e; break }
        }
        if ($match) { $accepted.Add([PSCustomObject]@{ Finding = $f; Exception = $match }) } else { $active.Add($f) }
    }
    return [PSCustomObject]@{ Active = $active.ToArray(); Accepted = $accepted.ToArray(); Expired = $expired.ToArray() }
}

function Get-HostScore {
    # IDWolf's score: one weight per triggered check at its worst severity (Critical 20, High 8,
    # Medium 3, Low 1), then 100 * e^(-penalty/100), capped at 35 with any Critical and at 65 with
    # any High.
    param($Findings)
    $weights = @{ Critical = 20; High = 8; Medium = 3; Low = 1 }
    $worstPerType = @{}
    foreach ($f in $Findings) {
        $cur = $worstPerType[$f.Type]
        if (-not $cur -or $script:SeverityRank[$f.Severity] -gt $script:SeverityRank[$cur]) { $worstPerType[$f.Type] = $f.Severity }
    }
    $penalty = 0
    foreach ($s in $worstPerType.Values) { $penalty += $weights[$s] }
    $score = 100.0 * [Math]::Exp(-$penalty / 100.0)
    $worst = @($worstPerType.Values)
    $cap = if ($worst -contains 'Critical') { 35 } elseif ($worst -contains 'High') { 65 } else { 100 }
    $score = [Math]::Max(1, [Math]::Round([Math]::Min($score, $cap)))
    $grade = if ($score -ge 85) { 'A' } elseif ($score -ge 70) { 'B' } elseif ($score -ge 55) { 'C' } elseif ($score -ge 40) { 'D' } elseif ($score -ge 25) { 'E' } else { 'F' }
    return [PSCustomObject]@{ Score = [int]$score; Grade = $grade; Penalty = $penalty; ChecksTriggered = $worstPerType.Count }
}
