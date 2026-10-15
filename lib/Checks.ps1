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
    lsa_not_protected = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1003.001'; Cis = '18.9.26.2 (L1)'; Needs = @('credentialProtection'); Roles = $script:AllRoles
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
    bitlocker_weak_encryption = @{ Category = 'Disk and Boot'; Severity = 'Low'; Mitre = 'T1005'; Needs = @('bitlocker'); Roles = $script:AllRoles
        Title = 'BitLocker volume uses a weak encryption method'
        Description = 'An encrypted volume relies on the drive''s own hardware encryption (self-encrypting drives: several were broken so that the data could be read without the key, CVE-2018-12037; Medium), or uses a 128-bit key or the older CBC mode instead of XTS-AES 256 (Low).'
        Remediation = 'Set "Choose drive encryption method and cipher strength" to XTS-AES 256 for operating system and fixed drives and turn off hardware-based encryption, then decrypt and encrypt the volume again (the method of an encrypted volume does not change on its own).' }
    bitlocker_policy_weak = @{ Category = 'Disk and Boot'; Severity = 'Medium'; Mitre = 'T1005'; Cis = '18.10.9.x (BitLocker profile)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'BitLocker policy weakens the protection of the disks'
        Description = 'A BitLocker Group Policy value lowers the protection itself: drive self-encryption trusted (several SSDs were broken, CVE-2018-12037), BitLocker allowed without a TPM, Secure Boot not used for integrity validation, no additional authentication at startup, a password protector on the OS drive. On workstations it also flags two settings whose Windows default is the problem: new DMA devices accepted while the computer is locked, and writes allowed to removable drives that are not encrypted.'
        Remediation = 'Set the listed BitLocker policies (Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption) to the CIS value. Denying writes to unencrypted removable drives changes how users work with USB sticks: roll it out with BitLocker To Go. No fix script: BitLocker policy is an organizational choice.' }
    bitlocker_policy_gaps = @{ Category = 'Disk and Boot'; Severity = 'Low'; Mitre = 'T1005'; Cis = '18.10.9.1.1 - 18.10.9.3.15 (BitLocker profile)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'BitLocker policy differs from the CIS BitLocker profile'
        Description = 'A BitLocker Group Policy value is set and differs from the CIS optional BitLocker profile: recovery options and their escrow to AD DS, data recovery agent, smart cards or passwords on data drives, TPM startup key and PIN combinations, access from earlier versions of Windows. These are organizational choices (for example escrow to Entra ID instead of AD DS): read them as a comparison with the profile, not as a vulnerability. Values that are not set are not judged.'
        Remediation = 'Compare the listed values with your BitLocker design; align them with the CIS BitLocker profile where it fits. No fix script: BitLocker policy is an organizational choice.' }
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
    llmnr_enabled = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557.001'; Cis = '18.6.4.3 (L1)'; Needs = @('network'); Roles = $script:AllRoles
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
        Description = 'Everyone, Users, Authenticated Users or Domain Users can change the service program (High) or drop files into its folder (Medium, DLL planting; High when non-admin users can also start the service): any user gets the service account, usually SYSTEM.'
        Remediation = 'Fix the ACL: only Administrators, SYSTEM and TrustedInstaller should be able to write the file and its folder. Move the program under Program Files if it lives elsewhere.' }
    task_binary_writable = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1053.005'; Needs = @('scheduledTasks', 'acl'); Roles = $script:AllRoles
        Title = 'Privileged scheduled task runs a user-writable program'
        Description = 'A task running as SYSTEM, a service account or with highest privileges starts a program that low privileged users can change (High) or whose folder they can write (Medium).'
        Remediation = 'Fix the ACL of the program and its folder, or point the task at a protected copy.' }
    autorun_writable = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1547.001'; Needs = @('autoruns', 'acl'); Roles = $script:AllRoles
        Title = 'Machine-wide autorun points to a user-writable program'
        Description = 'An HKLM Run key or the common Startup folder starts, for every user who logs on (administrators included), a program that low privileged users can change (High) or whose folder they can write (Medium).'
        Remediation = 'Fix the ACL of the program and its folder, or remove the autorun.' }
    vulnerable_driver_present = @{ Category = 'Privilege Escalation'; Severity = 'High'; Mitre = 'T1068'; Needs = @('drivers'); Roles = $script:AllRoles
        Title = 'Known vulnerable or malicious driver on the host'
        Description = 'The file of a kernel driver installed on the host has the SHA-256 of a driver in the LOLDrivers catalog. A vulnerable driver is signed and loads normally, but its flaws let an administrator, or malware that got admin rights, read and write kernel memory: that is how attackers switch off EDR agents and protections ("bring your own vulnerable driver"). Critical when the driver is a known malicious one, High for a vulnerable driver that is loaded, Medium when it is installed but not running; one level lower when LOLDrivers has not verified the sample. The match is by exact file hash, so a fixed version of the same driver does not match.'
        Remediation = 'Find the software that installed the driver; update it to a version with a fixed driver, or uninstall it and delete the driver service. A known malicious driver means the host is compromised: isolate it and investigate. Keep the Microsoft vulnerable driver blocklist on, with HVCI where the hardware allows.' }
    driver_blocklist_off = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1068'; Needs = @('drivers'); Roles = $script:AllRoles
        Title = 'Microsoft vulnerable driver blocklist turned off'
        Description = 'VulnerableDriverBlocklistEnable is set to 0: Windows loads drivers that Microsoft has blocked because attackers abuse them to reach the kernel. It is on by default on Windows 11 22H2 and later and with HVCI; a value that is not set is not judged.'
        Remediation = 'Turn on Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist (VulnerableDriverBlocklistEnable = 1, restart). If a business driver is blocked, update it instead of turning the list off.' }
    spooler_on_dc = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1187'; Needs = @('services'); Roles = @('dc')
        Title = 'Print Spooler running on a domain controller'
        Description = 'The spooler lets any domain user coerce the DC into authenticating to them (PrinterBug), feeding NTLM relay and unconstrained delegation attacks.'
        Remediation = 'Stop and disable the Print Spooler service on domain controllers.' }

    # ---------------- Logging ----------------
    audit_policy_gaps = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.002'; Cis = '17.1.1, 17.2.1 - 17.2.3, 17.3.1 - 17.3.2, 17.5.1 - 17.5.6, 17.6.1 - 17.6.4, 17.7.1 - 17.7.5, 17.8.1, 17.9.1 - 17.9.5 (L1)'; Needs = @('audit'); Roles = $script:AllRoles
        Title = 'Audit policy gaps'
        Description = 'Subcategories the CIS benchmark expects (all 27 rules of CIS section 17: account logon and management, detailed tracking, logon/logoff, object access, policy change, privilege use, system; plus Kerberos and directory changes on DCs) are not audited, so attacks leave no event to detect.'
        Remediation = 'Configure the Advanced Audit Policy for the listed subcategories (Group Policy: Advanced Audit Policy Configuration) and forward the Security log.' }
    cmdline_audit_off = @{ Category = 'Logging'; Severity = 'Medium'; Mitre = 'T1562.002'; Cis = '18.9.3.1 (L1)'; Needs = @('audit'); Roles = $script:AllRoles
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
    winrm_insecure_auth = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1021.006'; Cis = '18.10.88.1.1 - 18.10.88.2.4 (L1/L2)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'WinRM allows Basic, Digest, unencrypted traffic, or an unsafe service configuration'
        Description = 'The WinRM client or service policy explicitly allows Basic authentication, Digest authentication or unencrypted traffic, which exposes credentials and commands to anyone who can observe or relay the connection. The service can also store RunAs credentials for a listener (DisableRunAs = 0) or allow its configuration to be changed remotely over WinRM itself (AllowAutoConfig = 1, Level 2); disallowing remote AllowAutoConfig can break EDR/RMM tooling that configures WinRM remotely, so treat that one finding as a decision, not a default fix.'
        Remediation = 'Set the WinRM client and service policies to disallow Basic, Digest and unencrypted traffic (use Kerberos, or HTTPS listeners), and disallow storing RunAs credentials. Leave AllowAutoConfig alone if remote tooling depends on it.' }
    mdns_enabled = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557.001'; CisServer = '18.6.4.1 (L1)'; Needs = @('network'); Roles = $script:AllRoles
        Title = 'Multicast DNS (mDNS) enabled'
        Description = 'The host answers and asks multicast DNS on the local network, on by default. Like LLMNR and NetBIOS name resolution, it lets anyone on the segment answer a name lookup (Responder) and collect NTLM hashes or relay them.'
        Remediation = 'Set "Configure multicast DNS (mDNS) protocol" to Disabled (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient EnableMDNS = 0), together with LLMNR and NetBIOS over TCP/IP.' }
    authenticode_padding_check_off = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1553.002'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Stricter Authenticode signature check not enabled (CVE-2013-3900)'
        Description = 'EnableCertPaddingCheck is not 1: Windows accepts a signed file with extra data appended after its signature, so a signed installer can carry an attacker''s payload and still show as signed (CVE-2013-3900, in the CISA Known Exploited Vulnerabilities catalog). Microsoft left the fix opt-in because some installers built that way then look unsigned.'
        Remediation = 'After testing the installers you deploy, set EnableCertPaddingCheck = "1" under HKLM\Software\Microsoft\Cryptography\Wintrust\Config and, on 64-bit Windows, HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config, then restart. No fix script: an installer that breaks needs a decision.' }
    firewall_notifications_on = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1562.004'; Cis = '9.1.3, 9.2.3, 9.3.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Windows Firewall shows notifications when it blocks a program'
        Description = 'The firewall policy of a profile explicitly sets DisableNotifications = 0. CIS expects the notification off (1): a pop-up lets a standard user be talked into allowing a program through, and the firewall rule is created by the user, not by the administrator.'
        Remediation = 'Set "Windows Firewall: <profile>: Settings: Display a notification" to No for the Domain, Private and Public profiles.' }
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
    service_should_be_disabled = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1021'; Cis = '5.1 - 5.44, Level 1 services (L1)'; Needs = @('services'); Roles = @('workstation', 'server')
        Title = 'Service the baseline says to disable is running or automatic'
        Description = 'A service the CIS workstation baseline wants disabled (Bluetooth Audio Gateway, Bluetooth Support, Computer Browser, IIS, FTP, SSH server, RPC Locator, Routing and Remote Access, SNMP-like Simple TCP/IP, SSDP, UPnP, Xbox services, WSL and others) is running or starts automatically. Network-facing ones are Medium. Bluetooth Audio Gateway (5.1) and Bluetooth Support (5.2) are Level 2 in the benchmark; the finding still quotes the (L1) tag that this check uses throughout, since each finding carries only its own rule number, not a per-rule level. Services that are stopped and set to Manual are not listed. On a member server the CIS Windows Server benchmarks list one service, Print Spooler (rule 5.2, Level 2; on a domain controller spooler_on_dc judges it): Low, since a print server needs it.'
        Remediation = 'Disable the service (and uninstall the feature if it is not needed). On a server that legitimately runs the role, record an exception.' }
    defender_network_protection_off = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1189'; Cis = '18.10.42.6.3.1 (L1)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Defender Network Protection not enabled'
        Description = 'Network Protection is off or only auditing, so connections to known malicious sites and servers are not blocked at the network layer.'
        Remediation = 'Set Network Protection to Block mode (Intune, Group Policy or Set-MpPreference -EnableNetworkProtection Enabled) after a period in audit mode.' }
    defender_pua_off = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1204.002'; Cis = '18.10.42.16 (L1)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Defender blocking of potentially unwanted apps off'
        Description = 'PUA protection is not in block mode, so adware, bundlers and unwanted tools are not stopped.'
        Remediation = 'Enable PUA protection (Intune, Group Policy or Set-MpPreference -PUAProtection Enabled).' }
    # ---------------- EDR / endpoint protection agent ----------------
    edr_agent_stopped = @{ Category = 'Antivirus'; Severity = 'High'; Mitre = 'T1562.001'; Needs = @('services'); Roles = $script:AllRoles
        Title = 'EDR agent installed but not running'
        Description = 'A known endpoint detection and response (or endpoint protection) agent is installed, but its main service is not running. The host is blind to the product that is meant to protect it, and a stopped agent is also what an attacker who has disabled it leaves behind.'
        Remediation = 'Start the service and find out why it stopped: a crash, a failed update, a policy, or someone stopping it on purpose. Check the console of the product for tamper alerts, and treat the host as unmonitored until the agent reports again.' }
    edr_expected_missing = @{ Category = 'Antivirus'; Severity = 'High'; Mitre = 'T1562.001'; Needs = @('services'); Roles = $script:AllRoles
        Title = 'Expected EDR agent not found'
        Description = 'You told HostBadger which EDR every host should run (-ExpectedEdr), and this host has no service of that product. It is outside the coverage you think you have: nobody sees what happens on it.'
        Remediation = 'Deploy the agent (or find out why it was removed), and check that the host appears in the console of the product. If the product is installed under a service name HostBadger does not know, add it with -ExtraEdrServices.' }
    edr_not_found = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1562.001'; Needs = @('services'); Roles = $script:AllRoles
        Title = 'No EDR or endpoint protection agent found'
        Description = 'None of the services of the well-known EDR and endpoint protection products (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend Micro, Trellix, ESET, Symantec, Elastic, Cybereason, Cylance, Bitdefender, Huntress) is present. Microsoft Defender Antivirus alone is not counted as EDR. It is Low on a workstation and Medium on a server or domain controller. If you use another product, name it with -ExtraEdrServices, or declare the one you expect with -ExpectedEdr.'
        Remediation = 'Install the EDR your organization uses. If the host does run one that HostBadger does not recognise, pass its service name with -ExtraEdrServices so that it is counted.' }
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
    user_rights_excessive = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1134'; Cis = '2.2.1 - 2.2.39, Level 1 rights (L1)'; Needs = @('securityPolicy'); Roles = $script:AllRoles
        Title = 'User right granted to more principals than the baseline'
        Description = 'A privilege or logon right is held by principals the CIS Level 1 baseline does not list: the Windows 11 workstation list, or on servers the member server or domain controller list of the CIS Windows Server benchmark (for example a domain controller also expects Authenticated Users and ENTERPRISE DOMAIN CONTROLLERS on network logon, and only Administrators may add workstations to the domain, which Windows grants to every authenticated user by default). Rights such as debug programs, act as part of the operating system, create a token or load drivers are a direct path to SYSTEM, so those are High; the rest are Medium. Default Windows grants some rights more widely than CIS (for example Backup Operators), so review before tightening.'
        Remediation = 'Remove the extra principals from the right (Local Security Policy > User Rights Assignment, or the matching Group Policy), after checking that no service or backup job depends on them.' }
    deny_logon_rights_missing = @{ Category = 'Local Accounts'; Severity = 'Low'; Mitre = 'T1078.001'; Cis = '2.2.16 - 2.2.20 (L1)'; Needs = @('securityPolicy'); Roles = $script:AllRoles
        Title = 'Guests or local accounts not denied network or remote logon'
        Description = 'The deny rights for network, batch, service, local and Remote Desktop logon do not list Guests (and, for network and Remote Desktop, "Local account"), so the Guest account or a local account can log on remotely if it is ever enabled or reused. Member servers deny network logon to "Local account and member of Administrators" instead; domain controllers, which have no local accounts, only need Guests.'
        Remediation = 'Add Guests to the five deny logon rights and Local account to "Deny access to this computer from the network" and "Deny log on through Remote Desktop Services" (on member servers: "Local account and member of Administrators group" for network logon; on domain controllers Guests only).' }
    lsa_weak_auth_options = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1557'; Cis = '2.3.11.2, 2.3.11.3 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'LocalSystem NULL session fallback or PKU2U online identities allowed'
        Description = 'AllowNullSessionFallback or PKU2U AllowOnlineID is explicitly 1: services running as LocalSystem may fall back to anonymous NTLM sessions, or the host accepts authentication with online identities.'
        Remediation = 'Set "Allow LocalSystem NULL session fallback" and "Allow PKU2U authentication requests to use online identities" to Disabled.' }

    service_path_ancestor_control = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1574.010'; Needs = @('services', 'acl'); Roles = $script:AllRoles
        Title = 'Service program under a folder that a non-administrator controls'
        Description = 'A folder above the program of a service (its own folder or any folder up to the drive root, outside the Windows directory) is owned by an account that is not an administrator, or gives such an account the right to change permissions, take ownership or delete what is inside. Whoever controls a parent folder controls the whole path to the program, whatever the permissions on the program itself. High when everyone (Everyone, Users, Authenticated Users) has that control and the service runs as LocalSystem, Medium otherwise. The finding names the account and how many levels above the program the folder is; accounts that are members of the local Administrators group are not reported. The usual cause is an installer that makes the installing user the owner of the folders it creates.'
        Remediation = 'As an administrator, make Administrators and SYSTEM the owners of those folders and remove the entry of the account (icacls <folder> /setowner Administrators and /remove), or move the program under Program Files. Keep a backup of the permissions first (icacls <folder> /save). Check that the vendor''s updater still works afterwards, and report the installer behavior to the vendor.' }

    # ---------------- Pending updates and known exploited vulnerabilities (both opt-in) ----------------
    updates_pending = @{ Category = 'Patching'; Severity = 'Medium'; Mitre = 'T1190'; Needs = @('updatesPending'); Roles = $script:AllRoles
        Title = 'Windows update available but not installed'
        Description = 'The snapshot was taken with -CheckUpdates and the Windows Update Agent reported this update as missing. Severity follows the Microsoft severity rating (Critical is High, Important is Medium, anything else Low). Definition updates are not listed. Only present when the collector was asked to search (it contacts the WSUS server set by policy, or Microsoft Update).'
        Remediation = 'Install the update through the usual channel (WSUS, Intune, Windows Update) and restart if it asks. If the host is meant to be patched by another tool, check that tool reaches it.' }
    kev_software_match = @{ Category = 'Software'; Severity = 'Low'; Mitre = 'T1190'; Needs = @('software'); Roles = $script:AllRoles
        Title = 'Installed software with vulnerabilities known to be exploited (CISA KEV)'
        Description = 'An installed program matches a vendor and product in the CISA Known Exploited Vulnerabilities catalog. The match is by name only: the catalog has no version ranges, so HostBadger cannot tell whether the installed version is one of the affected ones. Treat it as a lead to verify against the vendor advisory. Medium when some of the listed vulnerabilities are used in ransomware campaigns. Only present when a KEV catalog was given (-KevFile or -KevOnline).'
        Remediation = 'Compare the installed version with the advisories for the listed CVEs, update the program or remove it if it is not needed, and add an exception if the installed version is not affected.' }
    software_eol = @{ Category = 'Software'; Severity = 'Medium'; Mitre = 'T1203'; Needs = @('software'); Roles = $script:AllRoles
        Title = 'Installed software no longer supported by its vendor'
        Description = 'An installed program is a release that its vendor no longer fixes: Flash, Silverlight, Java 6/7, old Adobe Reader and Office, Exchange, SQL Server, Python, Node.js, .NET and Visual C++ runtimes past their end of life. New vulnerabilities in it stay open for good. The release is read from the Programs and Features name (and the version for Node.js) and compared with the lifecycle table in lib\Checks.ps1, or with the endoflife.date data when it was given (-EolFile or -EolOnline), which also covers Oracle Java, Eclipse Temurin, PowerShell 7, VirtualBox and Wireshark, and judges each SQL Server instance on its service pack (2016 SP2 ended years before 2016 SP3) from the build the collector reads; per-user installs are not listed. Severity follows the product: High for browser plugins, old document readers and Exchange, Low for the Visual C++ runtimes, and Low while paid extended support still runs.'
        Remediation = 'Upgrade to a supported release, or uninstall it if nothing needs it. A Visual C++ runtime may be needed by an old program: remove it with that program. For SQL Server, Extended Security Updates can cover the gap while the upgrade is planned (add an exception if the host is enrolled).' }
    software_cve = @{ Category = 'Software'; Severity = 'Medium'; Mitre = 'T1203'; Needs = @('software'); Roles = $script:AllRoles
        Title = 'Installed software version with known vulnerabilities'
        Description = 'The installed version of a program falls in the vulnerable version range of CVEs that NVD had published before the snapshot was taken. One finding per program, with the count, the highest CVSS score, the CVEs CISA lists as exploited (KEV, from the date they were added) and the highest EPSS score (probability of exploitation in the next 30 days, FIRST). High when one is in KEV, CVSS 9.0 or more or EPSS 0.1 or more; Medium for CVSS 7.0 or EPSS 0.01; Low otherwise. Covers Python, Node.js, .NET, Notepad++, PowerShell 7, VirtualBox, Wireshark, 7-Zip, VLC, Git, GIMP, WinSCP, PuTTY, FileZilla, KeePass, Audacity, Mullvad VPN and AnyDesk; NVD has a backlog of CVEs without version data, so a very recent CVE can be missing (never a false alarm from that). Only present when the data was given (-CveFile or -CveOnline).'
        Remediation = 'Update the program to the release named in Expected (or later), starting with the ones whose CVEs are in KEV or have a high EPSS score. If the program is not needed, uninstall it.' }
    software_outdated = @{ Category = 'Software'; Severity = 'Low'; Mitre = 'T1203'; Needs = @('software'); Roles = $script:AllRoles
        Title = 'Installed software behind the latest release of its line'
        Description = 'The release line of an installed program is still maintained, but a newer version of that line came out before the snapshot was taken, with the security fixes since the installed one. For products that ship every few weeks (Firefox, Chrome, Notepad++) a line that has already been replaced counts here too. A release counts only once it is older than the grace period (-SoftwareGraceDays, 30 days), so a host waiting for its normal update is not flagged; a host several releases behind a recent one (8.9.1 when 8.9.8.1 is out) is flagged anyway, Low. Medium when the missing release is more than 180 days old. A SQL Server instance is judged on its own branch: the latest cumulative update, or the latest security-only (GDR) build for an instance that takes only those. For 7-Zip, VLC, Git, GIMP, WinSCP, PuTTY, FileZilla, KeePass, Audacity, Mullvad VPN, OBS Studio and AnyDesk the versions and their dates come from the Chocolatey community repository, and the grace period counts from the first newer release. Only present when endoflife.date data (-EolFile or -EolOnline) or Chocolatey data (-ChocoFile or -ChocoOnline) was given.'
        Remediation = 'Update the program, and check why it did not update itself: auto-update turned off, a deployment ring that does not include it, or a copy that nobody manages.' }

    # ---------------- Further settings (Microsoft documentation, DISA STIG and ACSC guidance) ----------------
    asr_other_rules_not_blocking = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1204.002'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Other attack surface reduction rules not in block mode'
        Description = 'Microsoft documents 16 more ASR rules beyond the standard three: Office child processes, code injection and executable content, obfuscated and downloaded scripts, executables from email or USB, PSExec/WMI process creation, Adobe Reader child processes, advanced ransomware protection, rebooting into Safe Mode, copied or impersonated system tools, and (judged only where Exchange Server is installed) web shell creation. The finding lists the rules that are not set to Block.'
        Remediation = 'Set the listed rules to Audit first, read the events (Microsoft-Windows-Windows Defender/Operational 1121/1122), then to Block through Intune, Group Policy or Set-MpPreference. The PSExec/WMI rule conflicts with Configuration Manager clients and the prevalence rule blocks unknown tools: judge those two separately.' }
    defender_protection_features_off = @{ Category = 'Antivirus'; Severity = 'Medium'; Mitre = 'T1562.001'; Cis = '18.10.42.5.2, 18.10.42.10.1, 18.10.42.10.4 (L1/L2)'; Needs = @('defender', 'defender.preferences'); Roles = $script:AllRoles
        Title = 'Defender protection feature turned off'
        Description = 'Behavior monitoring, scanning of downloaded files and attachments, script scanning, cloud-delivered protection (MAPS) or block at first sight is off while Defender is the active antivirus. Each one removes a layer that catches new or obfuscated malware.'
        Remediation = 'Turn the feature back on (Set-MpPreference, Group Policy or Intune) and find out why it was disabled.' }
    hvci_off = @{ Category = 'Credential Protection'; Severity = 'Low'; Mitre = 'T1068'; Needs = @('credentialProtection'); Roles = @('workstation', 'server')
        Title = 'Memory integrity (HVCI) not running'
        Description = 'Hypervisor-protected code integrity is not running, so a vulnerable or malicious kernel driver is not blocked from loading. It needs virtualization-based security and compatible drivers; on a virtual machine without nested virtualization it cannot run.'
        Remediation = 'Turn on Memory integrity (Windows Security > Device security > Core isolation, or the Group Policy "Turn On Virtualization Based Security") once the drivers are compatible.' }
    powershell_module_logging_off = @{ Category = 'Logging'; Severity = 'Low'; Mitre = 'T1059.001'; Needs = @('powershell'); Roles = $script:AllRoles
        Title = 'PowerShell module logging off'
        Description = 'EnableModuleLogging is not 1, so the pipeline execution of PowerShell modules is not written to the event log (event 4103). Together with script block logging it is what an investigation of PowerShell abuse relies on.'
        Remediation = 'Enable "Turn on Module Logging" with module name * through Group Policy or Intune, and size the PowerShell log accordingly.' }
    schannel_legacy_crypto_enabled = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Legacy TLS/SSL protocol or weak cipher explicitly enabled'
        Description = 'The SCHANNEL registry keys switch on SSL 2.0/3.0, TLS 1.0/1.1 or a weak cipher (NULL, DES, RC2, RC4, 3DES). Only values somebody set are judged: an unset value is the Windows default. SSL and the NULL/DES/RC2/RC4 ciphers are Medium, TLS 1.0/1.1 and 3DES Low.'
        Remediation = 'Remove the Enabled = 1 value (or set it to 0) for the listed protocol or cipher, after checking that no old client or server depends on it.' }
    ldap_server_signing_off = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; CisServer = '2.3.5.3, 2.3.5.4 (L1)'; Needs = @('hardening'); Roles = @('dc')
        Title = 'Domain controller does not require LDAP signing or channel binding'
        Description = 'LDAPServerIntegrity is not 2 (require signing) or LdapEnforceChannelBinding is not 2 (always), so a relayed or downgraded LDAP bind is accepted. Unset counts, because the default is not enforcing.'
        Remediation = 'Set "Domain controller: LDAP server signing requirements" to Require signing and "Domain controller: LDAP server channel binding token requirements" to Always, after auditing clients with events 2886 to 2889.' }
    dc_netlogon_policy_weak = @{ Category = 'Network Exposure'; Severity = 'High'; Mitre = 'T1210'; CisServer = '2.3.5.1, 2.3.5.2, 2.3.5.5 (L1)'; Needs = @('hardening'); Roles = @('dc')
        Title = 'Domain controller weakens Netlogon or lets Server Operators schedule tasks'
        Description = 'The domain controller keeps an exception list for vulnerable Netlogon secure channel connections (the Zerologon, CVE-2020-1472, enforcement exceptions: the accounts listed can still use the vulnerable protocol; High), refuses machine account password changes (machine passwords never rotate; Medium), or lets Server Operators schedule tasks, which run as SYSTEM on the domain controller (Medium).'
        Remediation = 'Remove the accounts from "Domain controller: Allow vulnerable Netlogon secure channel connections" (leave it Not Configured) once the devices are patched or replaced, and set "Refuse machine account password changes" and "Allow server operators to schedule tasks" to Disabled.' }
    server_baseline_gaps = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1078'; CisServer = '2.3.7.8, 2.3.13.1, 18.9.25.2 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Server setting differs from the CIS Windows Server baseline'
        Description = 'A setting that only the CIS Windows Server benchmarks ask for: the server can be shut down from the logon screen without signing in, a member server unlocks with cached credentials instead of asking a domain controller (a disabled or changed account can still unlock it), or Windows LAPS, backing up to Active Directory, does not enforce the password expiration (an administrator can push the expiry out and keep the same password).'
        Remediation = 'Set "Shutdown: Allow system to be shut down without having to log on" to Disabled; on member servers set "Interactive logon: Require Domain Controller authentication to unlock workstation" to Enabled (the server then needs a domain controller to unlock); in the Windows LAPS policy enable "Do not allow password expiration time longer than required by policy".' }
    smb_server_hardening_gaps = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; CisServer = '18.6.7.1, 18.6.8.2 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Server does not mandate a minimum SMB dialect or SMB client encryption'
        Description = 'A setting the CIS Windows Server benchmark asks for and Windows 11 does not: the SMB server has no minimum SMB 2/3 dialect set (MinSmb2Dialect), so an old client can negotiate SMB 2.0.2, or the SMB client does not require encryption (RequireEncryption), so a share without encryption is still used. Unset counts, because the Windows default enforces neither.'
        Remediation = 'Set "Mandate the minimum version of SMB" to Enabled: 3.1.1 (MinSmb2Dialect = 785) and "Require Encryption" to Enabled (RequireEncryption = 1), after checking that no legacy SMB client or server depends on the weaker setting.' }
    defender_server_baseline_gaps = @{ Category = 'Antivirus'; Severity = 'Low'; Mitre = 'T1562.001'; CisServer = '18.10.43.13.1, 18.10.43.17 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Server Defender policy differs from the CIS Windows Server baseline'
        Description = 'A Microsoft Defender policy the CIS Windows Server benchmark asks for and Windows 11 does not: the antivirus exclusions are visible to local users (HideExclusionsFromLocalUsers not 1), which tells an attacker which paths are not scanned, or a quick scan does not also scan the excluded locations (QuickScanIncludeExclusions not 1). Unset counts.'
        Remediation = 'Set "Control whether exclusions are visible to local users" to Enabled (HideExclusionsFromLocalUsers = 1) and "Scan excluded files and directories during quick scans" to Enabled (QuickScanIncludeExclusions = 1) through Group Policy (Windows Components > Microsoft Defender Antivirus).' }
    terminal_services_server_gaps = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1563.002'; CisServer = '18.10.57.3.2.1 (L2), 18.10.57.3.11.2 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Remote Desktop session settings differ from the CIS Windows Server baseline'
        Description = 'A Remote Desktop Session Host setting the CIS Windows Server benchmark asks for and Windows 11 does not: temporary folders are shared between sessions instead of one per session (PerSessionTempDir not 1), so one session can read another''s temp files, or a user is not restricted to a single session (fSingleSessionPerUser not 1, Level 2). Unset counts.'
        Remediation = 'Set "Do not use temporary folders per session" to Disabled (PerSessionTempDir = 1) and "Restrict Remote Desktop Services users to a single Remote Desktop Services session" to Enabled (fSingleSessionPerUser = 1) through Group Policy (Remote Desktop Session Host > Temporary folders / Connections).' }
    explorer_motw_bypass = @{ Category = 'System Hardening'; Severity = 'Medium'; Mitre = 'T1553.005'; CisServer = '18.10.29.2 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Mark of the Web is not applied to files copied from insecure sources'
        Description = 'The "Do not apply the Mark of the Web tag to files copied from insecure sources" policy is Enabled (DisableMotWOnInsecurePathCopy = 1), so files copied from a network share or other insecure location keep no zone marker. SmartScreen, Office Protected View and macro blocking all rely on that marker, so the setting removes a key defence against downloaded malware.'
        Remediation = 'Set "Do not apply the Mark of the Web tag to files copied from insecure sources" to Disabled (DisableMotWOnInsecurePathCopy = 0) through Group Policy (Windows Components > File Explorer).' }
    app_installer_policy_gaps = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1059'; CisServer = '18.10.18.4, 18.10.18.6 (L1), 18.10.18.7 (L2)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'App Installer (winget) is not restricted per the CIS Windows Server baseline'
        Description = 'An App Installer / Windows Package Manager policy the CIS Windows Server benchmark asks for and Windows 11 does not: the local archive malware scan can be overridden (EnableLocalArchiveMalwareScanOverride not 0), the Microsoft Store source certificate pinning can be bypassed (EnableBypassCertificatePinningForMicrosoftStore not 0), or the winget command-line interfaces are enabled (EnableWindowsPackageManagerCommandLineInterfaces not 0, Level 2). Each widens how software can be installed on a server. Unset counts, because the default leaves them enabled.'
        Remediation = 'Through Group Policy (Windows Components > Desktop App Installer) disable the local archive malware scan override and the Microsoft Store certificate pinning bypass, and, where winget is not needed on the server, disable the Windows Package Manager command-line interfaces.' }
    server_network_policy_gaps = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557'; CisServer = '18.6.4.3 (L2), 18.10.58.2 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'Server network setting differs from the CIS Windows Server baseline'
        Description = 'A network setting the CIS Windows Server benchmark asks for and Windows 11 does not: the default IPv6 DNS servers are still used (DisableIPv6DefaultDnsServers not 1, Level 2), or Internet Explorer feeds send Basic authentication in clear text over HTTP (AllowBasicAuthInClear not 0), which exposes the credentials on the wire. Unset counts, because the default is the weaker state.'
        Remediation = 'Set "Turn off default IPv6 DNS Servers" to Enabled (DisableIPv6DefaultDnsServers = 1) and "Turn on Basic feed authentication over HTTP" to Disabled (AllowBasicAuthInClear = 0) through Group Policy.' }
    ldap_client_encryption_weak = @{ Category = 'Network Exposure'; Severity = 'Medium'; Mitre = 'T1557'; CisServer = '2.3.11.8 (L1)'; Needs = @('hardening'); Roles = @('server', 'dc')
        Title = 'LDAP client does not require encryption'
        Description = 'Network security: LDAP client encryption requirements (LDAPClientConfidentiality) is below Negotiate sealing (1), so the server can make LDAP binds that are not encrypted and a man in the middle can read or tamper with the directory traffic. Unset counts as None (0).'
        Remediation = 'Set "Network security: LDAP client encryption requirements" to Negotiate sealing or Require sealing (LDAPClientConfidentiality = 1 or 2) through Group Policy, after confirming the directory clients support it.' }
    dc_security_policy_gaps = @{ Category = 'Credential Protection'; Severity = 'Medium'; Mitre = 'T1556'; CisServer = '18.9.39.1, 2.3.11.13 (L1)'; Needs = @('hardening'); Roles = @('dc')
        Title = 'Domain controller is missing a CIS Windows Server security setting'
        Description = 'A domain-controller setting the CIS Windows Server benchmark asks for and Windows 11 does not: validation of ROCA-vulnerable Windows Hello for Business keys during authentication is not at Audit or higher (SamNGCKeyROCAValidation not 1 or 2; Medium), so weak WHfB keys are accepted, or inbound NTLM authentication in the domain is not audited (AuditNTLMInDomain not 7; Low), so NTLM use across the domain is invisible. Unset counts.'
        Remediation = 'Set "Configure validation of ROCA-vulnerable WHfB keys during authentication" to Enabled: Audit (SamNGCKeyROCAValidation = 1) or Block (2), and "Network security: Restrict NTLM: Audit NTLM authentication in this domain" to Enable all (AuditNTLMInDomain = 7), through Group Policy on the domain controllers.' }
    webclient_webdav_enabled = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1187'; Needs = @('services'); Roles = $script:AllRoles
        Title = 'WebClient (WebDAV) service is enabled'
        Description = 'The WebClient (WebDAV Redirector) service is installed and not disabled. Where it runs, authentication coercion (PetitPotam, PrinterBug) can force the host to authenticate over HTTP instead of SMB, which is not protected by SMB signing and can be relayed to LDAP or AD CS web enrollment (ESC8). The service starts on a trigger, so Manual is enough to abuse. On a domain controller this is High (a relay to LDAP or AD CS is domain takeover).'
        Remediation = 'Set the WebClient service to Disabled where WebDAV is not needed (or remove the WebDAV Redirector feature), and enforce it through Group Policy (System Services).' }
    wpad_not_disabled = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1557.001'; Needs = @('hardening', 'services'); Roles = $script:AllRoles
        Title = 'WPAD auto-discovery is not disabled'
        Description = 'Web Proxy Auto-Discovery is not turned off: DisableWpad is not 1 and the WinHTTP Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) is not disabled. Clients keep looking for a "wpad" host through DNS, LLMNR, mDNS and NBT-NS, and whoever answers becomes their proxy and can capture or relay NTLM authentication.'
        Remediation = 'Set HKLM\SYSTEM\CurrentControlSet\Services\WinHttp\Parameters\DisableWpad = 1 (or disable the WinHttpAutoProxySvc service) where proxy auto-discovery is not used, and keep "wpad" in the DNS global query block list.' }
    bloatware_installed = @{ Category = 'Software'; Severity = 'Low'; Mitre = 'T1176'; Needs = @('appx', 'software'); Roles = @('workstation', 'server')
        Title = 'Preinstalled games, consumer apps or antivirus trials'
        Description = 'Store apps and programs that a managed business device rarely needs are installed or provisioned for new users: preinstalled games (Candy Crush, Solitaire, Xbox), consumer apps (TikTok, Spotify, Disney+, Netflix, Clipchamp, Bing News), and third-party antivirus trials (McAfee, Norton) that compete with Microsoft Defender and expire. Each is more code that updates on its own schedule, talks to the internet and can carry vulnerabilities; an expired antivirus trial can leave Defender in passive mode. The list is curated in lib\Checks.ps1 (OEM driver and firmware utilities are left out on purpose). Low.'
        Remediation = 'Remove what the organization does not use, for the installed users and from the provisioned list so new profiles do not get it back (Remove-AppxPackage -AllUsers, Remove-AppxProvisionedPackage -Online, or the uninstaller of the program), and keep it out of the image. HostBadger''s guided menu offers the removal as an explicit choice.' }
    brave_policy_gaps = @{ Category = 'System Hardening'; Severity = 'Medium'; Mitre = 'T1189'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Brave policy weaker than the Chrome STIG'
        Description = 'Brave is installed and one of its policies is not set as the DISA Google Chrome STIG asks of Chrome: Brave is built on Chromium and reads the same policies under HKLM\SOFTWARE\Policies\BraveSoftware\Brave. This is HostBadger applying the Chrome STIG to Brave, not a DISA STIG; the finding quotes the Chrome rule and its category. Brave''s own policies are judged too: Tor windows (TorDisabled, Medium: they bypass the proxy and network monitoring), the crypto wallet (BraveWalletDisabled) and Brave Rewards (BraveRewardsDisabled), Low. A policy that is not configured counts.'
        Remediation = 'Set the policy under HKLM\SOFTWARE\Policies\BraveSoftware\Brave through the Brave policy templates (Group Policy) or the registry, with the value the Chrome STIG rule asks for; disable Tor, the wallet and Rewards where they are not needed.' }
    script_files_execute_on_open = @{ Category = 'System Hardening'; Severity = 'Medium'; Mitre = 'T1204.002'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Script files run when they are double-clicked'
        Description = 'A double click on a JScript, VBScript, Windows Script or HTML Application file (.js, .jse, .vbs, .vbe, .wsf, .wsh, .hta) runs it through Windows Script Host or mshta instead of opening it as text. These are the attachments and downloads that phishing uses to start malware. Read from the machine-wide association of each extension; a per-user choice is not seen. The Windows Script Host types are not judged when Windows Script Host is disabled (Settings\Enabled = 0). Medium on workstations, Low on servers.'
        Remediation = 'Associate the script extensions with Notepad (txtfile), so a double click opens them as text; scripts still run when called explicitly (cscript, wscript, mshta, logon scripts). Use the fix script, or Group Policy (Preferences > Folder Options > Open With) for a fleet.' }
    lolbin_outbound_not_blocked = @{ Category = 'Network Exposure'; Severity = 'Low'; Mitre = 'T1105'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'System tools used to download payloads can reach the network'
        Description = 'No enabled Windows Firewall rule blocks outbound traffic for system tools that attackers use to download payloads or run remote scripts (certutil, mshta, wscript, cscript, regsvr32, wmic, bitsadmin). Rules in the local store and in Group Policy are read; rules pushed by Intune (MDM store) are not, and an outbound default of Block is not considered.'
        Remediation = 'Add outbound block rules for the listed programs (System32 and SysWOW64) where nothing legitimate needs them online, through Group Policy, Intune or the fix script. Check first that management tools do not depend on them (bitsadmin and wmic in some deployment scripts).' }
    removable_media_execute_allowed = @{ Category = 'System Hardening'; Severity = 'Low'; Mitre = 'T1091'; Needs = @('hardening'); Roles = @('workstation')
        Title = 'Programs can run from removable disks'
        Description = 'The Removable Storage Access policy does not deny execute access to removable disks ("Removable Disks: Deny execute access", Deny_Execute = 1) and does not deny all removable storage (Deny_All). Programs on a USB drive or SD card run like any other. Write and read access are an organizational choice and are only reported in the detail.'
        Remediation = 'Set "Removable Disks: Deny execute access" (Computer Configuration > Administrative Templates > System > Removable Storage Access) where users have no need to run programs from USB, and keep the ASR rule that blocks untrusted processes from USB in Block mode.' }
    print_point_and_print_weak = @{ Category = 'Privilege Escalation'; Severity = 'Medium'; Mitre = 'T1068'; Cis = '18.7.8, 18.7.10, 18.7.11 (L1)'; Needs = @('hardening'); Roles = $script:AllRoles
        Title = 'Point and Print allows driver installation without elevation'
        Description = 'The Point and Print policy lets standard users install printer drivers (RestrictDriverInstallationToAdministrators = 0) or suppresses the elevation prompt (NoWarningNoElevationOnInstall / NoWarningNoElevationOnUpdate = 1). That is the PrintNightmare condition: a standard user gets code running as SYSTEM through a driver.'
        Remediation = 'Set RestrictDriverInstallationToAdministrators = 1 and remove the NoWarningNoElevation values (Group Policy: Point and Print Restrictions, "Show warning and elevation prompt").' }

    # ---------------- DISA STIG, registry settings (data\stig-catalog.json) ----------------
    stig_windows10 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('workstation')
        Title = 'Windows 10 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows 10 STIG (V3R6) whose value is not the required one. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision are not judged. Windows 10 is out of support: the STIG is the last release.'
        Remediation = 'Set the policy in the finding through Group Policy or Intune, or accept the risk with an exception. Better: move the host to a supported Windows version.' }
    stig_windows11 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('workstation')
        Title = 'Windows 11 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows 11 STIG (V2R7) whose value is not the required one. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision (a banner text, an approved list) are not judged.'
        Remediation = 'Set the policy in the finding through Group Policy or Intune, or accept the risk with an exception. The STIG rule id (V-number) in the finding identifies the rule in the DISA STIG Viewer.' }
    stig_server2016 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('server', 'dc')
        Title = 'Windows Server 2016 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows Server 2016 STIG (V2R10) whose value is not the required one: the domain controller rules on a domain controller, the member server rules on a member server. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision are not judged.'
        Remediation = 'Apply the setting through Group Policy to match the Windows Server 2016 STIG. The check names the registry value and the required value; set it where the host is managed.' }
    stig_server2019 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('server', 'dc')
        Title = 'Windows Server 2019 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows Server 2019 STIG (V3R8) whose value is not the required one: the domain controller rules on a domain controller, the member server rules on a member server. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision are not judged.'
        Remediation = 'Set the policy in the finding through Group Policy, or accept the risk with an exception. The STIG rule id (V-number) in the finding identifies the rule in the DISA STIG Viewer.' }
    stig_server2022 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('server', 'dc')
        Title = 'Windows Server 2022 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows Server 2022 STIG (V2R8) whose value is not the required one: the domain controller rules on a domain controller, the member server rules on a member server. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision are not judged.'
        Remediation = 'Set the policy in the finding through Group Policy, or accept the risk with an exception. The STIG rule id (V-number) in the finding identifies the rule in the DISA STIG Viewer.' }
    stig_server2025 = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1112'; Needs = @('stig'); Roles = @('server', 'dc')
        Title = 'Windows Server 2025 setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Windows Server 2025 STIG (V1R1) whose value is not the required one: the domain controller rules on a domain controller, the member server rules on a member server. A value that is not configured counts, because the STIG asks for the policy to be set. Severity follows the STIG category (CAT I High, CAT II Medium, CAT III Low). Rules that need an organization decision are not judged.'
        Remediation = 'Apply the setting through Group Policy to match the Windows Server 2025 STIG. The check names the registry value and the required value; set it where the host is managed.' }
    stig_defender = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1562.001'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Microsoft Defender Antivirus setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Microsoft Defender Antivirus STIG (V2R8) whose value is not the required one. A value that is not configured counts. Severity follows the STIG category.'
        Remediation = 'Set the policy in the finding (Windows Components > Microsoft Defender Antivirus) through Group Policy or Intune.' }
    stig_firewall = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1562.004'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Windows Firewall setting differs from the DISA STIG'
        Description = 'One finding per registry rule of the DISA Windows Defender Firewall with Advanced Security STIG (V2R2) whose value is not the required one: profile state, default actions, logging. A value that is not configured counts.'
        Remediation = 'Set the policy in the finding (Windows Defender Firewall with Advanced Security) through Group Policy or Intune.' }
    stig_edge = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1189'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Microsoft Edge policy differs from the DISA STIG'
        Description = 'Edge is installed and a registry policy of the DISA Microsoft Edge STIG (V2R5) is not set as required. A policy that is not configured counts. Rules that need an approved list are not judged.'
        Remediation = 'Set the Edge policy in the finding through Group Policy (Microsoft Edge ADMX) or Intune.' }
    stig_chrome = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1189'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Google Chrome policy differs from the DISA STIG'
        Description = 'Chrome is installed and a registry policy of the DISA Google Chrome STIG (V2R11) is not set as required. A policy that is not configured counts. Rules that need an approved list are not judged.'
        Remediation = 'Set the Chrome policy in the finding through Group Policy (Google Chrome ADMX) or a managed-browser tool.' }
    stig_firefox = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1189'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Mozilla Firefox policy differs from the DISA STIG'
        Description = 'Firefox is installed and a registry policy of the DISA Mozilla Firefox STIG (V6R7) is not set as required. A policy that is not configured counts.'
        Remediation = 'Set the Firefox policy in the finding through Group Policy (Mozilla ADMX) or policies.json.' }
    stig_office = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1204.002'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Microsoft 365 Apps policy differs from the DISA STIG'
        Description = 'Office is installed and a per-user policy of the DISA Microsoft Office 365 ProPlus STIG (V3R5) is not set as required, in at least one of the user profiles that were loaded when the snapshot was taken (a SYSTEM collection sees only users who were signed in). A policy that is not configured counts.'
        Remediation = 'Set the Office policy in the finding through Group Policy (Office ADMX, User Configuration) or the Office cloud policy service.' }
    stig_adobe = @{ Category = 'DISA STIG'; Severity = 'Medium'; Mitre = 'T1204.002'; Needs = @('stig'); Roles = $script:AllRoles
        Title = 'Adobe Acrobat policy differs from the DISA STIG'
        Description = 'Adobe Acrobat Reader DC or Acrobat Pro DC is installed and a registry policy of its DISA STIG (Adobe Acrobat Reader DC Continuous V2R1, Adobe Acrobat Pro DC Continuous V2R1) is not set as required: Protected Mode, Enhanced Security, JavaScript, attachments, internet access from PDFs, updates. Per-user policies are judged on the user profiles loaded at collection. A policy that is not configured counts.'
        Remediation = 'Set the Acrobat policy in the finding through the Adobe Customization Wizard, the Acrobat Group Policy templates or the registry (HKLM\Software\Policies\Adobe\...\FeatureLockDown).' }
}

# What an attacker can do with each finding, shown as "Attacks it enables" in the report and written
# as attacks in CSV and JSON Lines. One entry per check of the catalog (the regression checks it).
$script:CheckAttacks = [ordered]@{
    account_lockout_weak = 'Password guessing and spraying: an attacker tries many passwords against local or domain accounts (over SMB, RDP or WinRM) without the accounts locking.'
    always_install_elevated = 'Privilege escalation to SYSTEM: any user can install a crafted .msi package (msiexec, or a one-line exploit module) and its custom actions run as SYSTEM.'
    anonymous_sam_enum = 'Account enumeration without credentials: an attacker on the network lists user and group names, the starting list for password spraying and phishing.'
    anonymous_shares_enum = 'Reconnaissance without credentials: an attacker lists the accounts and shares of the host and picks the ones to attack or to search for data.'
    app_installer_policy_gaps = 'Malicious package installation: a user or malware installs software through winget from a local or unpinned source, past the usual software controls.'
    asr_other_rules_not_blocking = 'Common initial-access and execution tricks stay open: Office macros starting processes, script-launched downloads, obfuscated scripts, WMI persistence, and USB-borne executables.'
    asr_standard_rules_missing = 'Credential theft and persistence stay open: reading LSASS memory (mimikatz), loading vulnerable signed drivers, and WMI event subscription persistence are not blocked.'
    audit_policy_gaps = 'Undetected activity: logons, privilege use, account changes or process starts that an attacker performs leave no Security log event to alert on or to investigate.'
    authenticode_padding_check_off = 'Signed-file tampering: an attacker appends a payload to a validly signed executable (CVE-2013-3900) and Windows still reports the signature as valid.'
    autologon_enabled = 'Credential theft: the password of the auto-logon account sits in the registry (Winlogon DefaultPassword or LSA secrets) where an administrator or malware reads it in clear text, and anyone with physical access gets a signed-in session.'
    autoplay_enabled = 'Removable-media infection: a USB drive or CD runs or offers its content as soon as it is inserted, the way worms and dropped "found" USB sticks spread.'
    autorun_writable = 'Privilege escalation and persistence: a user replaces the program that starts at every logon for every user (Run key) and their code runs in the session of the next administrator who logs on.'
    bitlocker_data_volume_off = 'Data theft from a lost or stolen device: removing the disk or booting another OS gives full access to the files on the data volume.'
    bitlocker_os_volume_off = 'Offline attacks on a lost or stolen device: reading files and cached credentials (SAM, LSA secrets, DPAPI keys) from the disk, or planting a backdoor by editing the system files offline.'
    bitlocker_policy_gaps = 'Weaker recovery and key handling than the profile requires: recovery keys not escrowed, or unprotected drives allowed, which makes a lost device or a recovery more exposed.'
    bitlocker_policy_weak = 'Disk protection bypass: with hardware encryption allowed, no-TPM startup, DMA left open while locked or writable unprotected USB drives, a stolen device or an insider can read the data or copy it out.'
    bitlocker_tpm_only = 'Key extraction from a stolen device: with TPM-only unlock the key is released at boot without any secret, so TPM bus sniffing, DMA or cold-boot attacks on the running machine can recover it.'
    bitlocker_weak_encryption = 'Weaker disk protection: AES-CBC 128 or hardware encryption (self-encrypting drives with known flaws) is easier to attack offline than XTS-AES 256 if the device is stolen.'
    blank_password_network_logon = 'Remote logon without a password: an attacker on the network signs in over SMB, RDP or WinRM with any local account whose password is empty.'
    builtin_admin_enabled = 'Password attacks on a known account: the RID-500 Administrator exists on every host, is exempt from lockout by default, and its shared password lets an attacker move from host to host (pass-the-hash).'
    cached_logons_high = 'Offline cracking of domain passwords: an administrator on the host dumps the cached domain logons (DCC2 hashes, mimikatz lsadump::cache) and cracks them; the more are kept, the more accounts are exposed.'
    cmdline_audit_off = 'Undetected execution: process start events (4688) carry no command line, so encoded PowerShell, LOLBins and attacker tools run without the arguments that reveal them.'
    credential_guard_off = 'Credential theft from memory: NTLM hashes and Kerberos tickets in LSASS can be dumped (mimikatz) and reused for pass-the-hash and pass-the-ticket.'
    dc_netlogon_policy_weak = 'Domain takeover: Zerologon-style Netlogon abuse (CVE-2020-1472) against an allow-listed or vulnerable channel, or Server Operators scheduling tasks that run as SYSTEM on the domain controller.'
    dc_security_policy_gaps = 'Weakened domain controller defenses: weak Windows Hello for Business keys (ROCA) accepted for logon, or NTLM use in the domain left unaudited so NTLM relay and downgrade go unnoticed.'
    defender_exclusion = 'Defense evasion: an attacker drops tools or payloads in the excluded folder, file type or process, and Defender does not scan them; the exclusion list itself tells an attacker where to hide.'
    defender_network_protection_off = 'Malicious connections are not blocked: users and malware reach phishing pages, exploit sites and command-and-control servers that Defender SmartScreen reputation would stop.'
    defender_protection_features_off = 'Defense evasion: with behavior monitoring, cloud protection or scanning of downloads and scripts off, new and fileless malware runs without being detected.'
    defender_pua_off = 'Unwanted software runs: adware, bundled installers, crypto miners and remote-access tools that Defender would block as potentially unwanted are installed and run.'
    defender_realtime_off = 'Malware runs unchecked: files are not scanned when they are written or run, so any payload an attacker brings executes without detection.'
    defender_server_baseline_gaps = 'Easier evasion on servers: local users can read the Defender exclusion list to know where to hide, and quick scans skip excluded paths an attacker may use.'
    defender_signatures_stale = 'Known malware is missed: threats released since the last signature update are not recognized.'
    defender_tamper_off = 'Defense evasion: malware or an attacker with administrator rights turns Defender off or adds exclusions (Set-MpPreference, registry) before running their tools.'
    deny_logon_rights_missing = 'Lateral movement with local accounts: an attacker who has one local password or hash (often the same on many hosts) signs in over the network or RDP; the Guest account can be used too.'
    driver_blocklist_off = 'Kernel compromise (BYOVD): an attacker with administrator rights loads a signed but vulnerable driver to kill EDR, read credentials or run code in the kernel.'
    edr_agent_stopped = 'Blind spot: the host is not monitored, so an attacker works there without detection or response, often after stopping the agent on purpose.'
    edr_expected_missing = 'Blind spot: the host lacks the agent your organization relies on for detection and response, so attacker activity there goes unseen.'
    edr_not_found = 'Blind spot: nothing on the host detects or responds to attacker activity beyond basic antivirus.'
    event_logs_small = 'Lost evidence: the logs roll over quickly, so traces of an intrusion are overwritten before anyone investigates.'
    everyone_includes_anonymous = 'Anonymous access: resources open to Everyone (shares, pipes, registry keys) become reachable by unauthenticated attackers on the network.'
    explorer_motw_bypass = 'Phishing payload execution: files copied from insecure locations lose the Mark of the Web, so SmartScreen, Office Protected View and macro blocking do not apply to them.'
    firewall_default_inbound_allow = 'Remote exploitation and lateral movement: every service listening on the host is reachable from the network, including ones nobody meant to expose.'
    firewall_drop_logging_off = 'Undetected scanning: port scans and blocked connection attempts against the host leave no trace to investigate.'
    firewall_notifications_on = 'Social engineering: when the firewall blocks a program, the user is asked to allow it, and malware that triggers the prompt may simply be allowed.'
    firewall_profile_disabled = 'Remote exploitation and lateral movement: no host firewall filters connections on that network profile, so every listening service is exposed.'
    force_guest_sharing_model = 'Unaccountable access: every network logon with a local account is mapped to Guest, so anyone reaching the shares has the same rights and nothing ties actions to a person.'
    guest_enabled = 'Access without credentials: the Guest account lets anyone sign in or reach shares and resources that Guests or Everyone can read.'
    hvci_off = 'Kernel attacks: without memory integrity, malicious or vulnerable drivers can load unsigned code into the kernel and disable security tools.'
    inactivity_lock_missing = 'Hands-on-keyboard access: an unattended unlocked session lets anyone nearby use the logged-on account and its access.'
    interactive_logon_gaps = 'Credential capture and reconnaissance: the logon screen gives away the last user name, and without CTRL+ALT+DEL a fake logon screen can collect passwords.'
    ip_stack_hardening_gaps = 'Traffic redirection: source-routed packets and ICMP redirects let an attacker on the network steer the host''s traffic through a machine they control.'
    kev_software_match = 'Exploitation of a known vulnerability: the product has vulnerabilities that attackers actively exploit in the wild (CISA KEV), often for initial access or privilege escalation.'
    laps_not_configured = 'Lateral movement with a shared password: the local administrator password is likely the same on many hosts, so one stolen hash or password opens all of them (pass-the-hash).'
    ldap_client_encryption_weak = 'Interception: LDAP traffic to domain controllers can travel without encryption, exposing directory data and credentials to an attacker in the path.'
    ldap_client_signing_off = 'LDAP tampering and relay: an attacker in the path changes LDAP queries or answers, or relays the host''s authentication to LDAP.'
    ldap_server_signing_off = 'NTLM relay to LDAP: an attacker who coerces or captures an authentication relays it to the domain controller to create accounts, set resource-based delegation or grant rights (ntlmrelayx), up to domain takeover.'
    llmnr_enabled = 'Credential capture by name poisoning: an attacker on the local network answers LLMNR lookups (Responder) and collects NTLM hashes to crack or relay.'
    lm_hash_stored = 'Password cracking: LM hashes are split, uppercase and unsalted, and are cracked in seconds once an attacker dumps the SAM or NTDS.'
    local_account_password_never_expires = 'Long-lived credentials: a password stolen or guessed once keeps working indefinitely, including on every host where it is reused.'
    local_account_password_not_required = 'Logon without a password: the account can be given, or may already have, an empty password that anyone can use.'
    local_admin_member = 'Privilege abuse and lateral movement: every extra administrator is another account whose theft gives full control of the host and its stored credentials.'
    logon_banner_missing = 'Legal exposure rather than a direct attack: without a warning banner, prosecuting or disciplining unauthorized use can be harder.'
    lsa_not_protected = 'Credential dumping: without LSA protection, tools such as mimikatz read LSASS memory to collect password hashes, Kerberos tickets and sometimes clear-text passwords.'
    lsa_weak_auth_options = 'Weaker authentication: NULL-session fallback lets LocalSystem authenticate anonymously, and PKU2U online identities open another authentication path an attacker can use.'
    mdns_enabled = 'Credential capture by name poisoning: an attacker on the local network answers mDNS lookups and collects NTLM hashes to crack or relay.'
    netbios_enabled = 'Credential capture by name poisoning: an attacker on the local network answers NetBIOS name lookups (Responder) and collects NTLM hashes to crack or relay.'
    ntlm_min_session_security_weak = 'Interception and downgrade: NTLM sessions without NTLMv2 session security and 128-bit encryption can be tampered with or decrypted by an attacker in the path.'
    ntlm_weak_lmcompat = 'Password hash cracking: LM and NTLMv1 responses captured on the network (Responder) are cracked quickly or turned into the account''s NTLM hash.'
    null_session_access = 'Access without credentials: named pipes and shares reachable through anonymous (null) sessions expose data and RPC interfaces to unauthenticated attackers.'
    os_support_ending = 'Soon no security fixes: once support ends, new Windows vulnerabilities stay exploitable on this host.'
    os_unsupported = 'Exploitation of unpatched Windows vulnerabilities: no security fixes are released for this version, so every new flaw stays open.'
    password_policy_weak = 'Password guessing and cracking: short, simple or never-changing local passwords fall quickly to spraying, brute force or offline cracking of dumped hashes.'
    powershell_module_logging_off = 'Undetected PowerShell activity: the commands that attacker scripts and modules run are not logged.'
    powershell_scriptblock_logging_off = 'Undetected PowerShell attacks: obfuscated or in-memory scripts (download cradles, AMSI bypasses, offensive frameworks) run without the decoded code being logged.'
    powershell_transcription_off = 'Lost evidence: the input and output of PowerShell sessions an attacker opens are not recorded for investigation.'
    powershell_v2_enabled = 'Security bypass by downgrade: an attacker starts powershell -version 2, which has no AMSI, script block logging or constrained language mode.'
    print_point_and_print_weak = 'Privilege escalation to SYSTEM (PrintNightmare): a user installs a malicious printer driver from a server they control without an administrator prompt.'
    rdp_enabled_workstation = 'Remote access and lateral movement: RDP on a workstation is a target for password attacks and lets an attacker with credentials take over the desktop remotely.'
    rdp_nla_disabled = 'Pre-authentication attacks on RDP: the logon screen and the RDP stack are exposed before any credentials, which helps brute force and exploits such as BlueKeep.'
    rdp_policy_gaps = 'Weaker RDP sessions: low encryption or legacy security layers allow interception, saved passwords allow logon without knowing them, and drive redirection lets data and tools move through the session.'
    remote_uac_token_filter_off = 'Pass-the-hash with local accounts: a local administrator''s hash or password gives full remote administrative access (PsExec, WMI), the classic way to move between hosts.'
    risky_listener = 'Remote exploitation: legacy or administrative services reachable from the network (Telnet, FTP, VNC, databases, SNMP) are targets for password attacks, sniffing and exploits.'
    safe_dll_search_off = 'DLL hijacking: programs look for DLLs in the current folder before the system folders, so a planted DLL is loaded by a program started from that folder.'
    schannel_legacy_crypto_enabled = 'Traffic decryption and downgrade: an attacker in the path forces old protocols or weak ciphers (SSL 3.0, TLS 1.0, RC4) and attacks them to read or alter TLS traffic.'
    secure_boot_off = 'Boot-level persistence: bootkits and modified boot loaders run before Windows and its security tools, and survive reinstalls of the OS.'
    secure_channel_unprotected = 'Domain traffic tampering: the host''s secure channel to the domain controller can be intercepted or altered, exposing logon and machine account traffic.'
    security_log_small = 'Lost evidence: the Security log rolls over quickly, so logon and privilege events of an intrusion are overwritten before anyone looks.'
    sehop_disabled = 'Easier memory-corruption exploits: structured exception handler overwrites, a common exploit technique, are not blocked.'
    server_baseline_gaps = 'Weaker server defenses: shutdown or unlock without proper logon, or LAPS passwords that stay valid past their expiry, give an attacker or insider an easier path.'
    server_network_policy_gaps = 'Interception: IPv6 default DNS servers can be spoofed (mitm6), and RSS feeds can send credentials in clear text with Basic authentication.'
    service_binary_writable = 'Privilege escalation: a user replaces the service program (or plants a DLL it loads) and the code runs with the service''s account, often SYSTEM, at the next start.'
    service_path_ancestor_control = 'Privilege escalation: a user who controls a folder above the service program can rename it and put their own program in its place, which the service runs at the next start.'
    service_should_be_disabled = 'Larger attack surface: a service the baseline says to disable is reachable or running, with its own vulnerabilities and abuse paths.'
    service_unquoted_path = 'Privilege escalation: Windows tries each space-separated part of the unquoted path, so a user who can write to one of those folders gets a program run by the service, often as SYSTEM.'
    smartscreen_off = 'Malicious downloads run: files and apps with a bad or unknown reputation are opened without the SmartScreen warning.'
    smb_client_signing_not_required = 'SMB tampering and relay: an attacker in the path alters the host''s SMB traffic, for example to serve malicious files or scripts.'
    smb_insecure_guest_auth = 'Malicious share access: the host connects to an attacker''s SMB server as guest without authentication, which allows serving malware and hides who controls the share.'
    smb_plaintext_password = 'Credential capture: the host sends clear-text passwords to SMB servers that ask for them, including an attacker''s.'
    smb_server_hardening_gaps = 'Downgrade and interception: older SMB dialects stay allowed, and SMB client traffic to servers that do not require encryption can be read in the path.'
    smb_server_signing_not_required = 'NTLM relay to SMB: an attacker who coerces or captures an authentication relays it to this host and runs commands with the victim''s rights (ntlmrelayx).'
    smb1_client_driver_enabled = 'Exploitation and downgrade over SMBv1: the old protocol has wormable flaws (EternalBlue, WannaCry) and weaker authentication.'
    smb1_server_enabled = 'Remote code execution over SMBv1: wormable exploits such as EternalBlue (used by WannaCry and NotPetya) target the SMBv1 server.'
    software_cve = 'Exploitation of the installed version: the program has published vulnerabilities an attacker can use, through a crafted file, a web page or a network service, depending on the CVE.'
    software_eol = 'Exploitation of unpatched software: the vendor no longer fixes this release, so every new vulnerability stays open for good.'
    software_outdated = 'Exploitation of fixed vulnerabilities: the installed version lacks security fixes that a newer release of the same line already has.'
    spooler_on_dc = 'Authentication coercion to domain takeover: an attacker forces the domain controller to authenticate to a host they control (PrinterBug), then relays it or abuses unconstrained delegation to compromise the domain.'
    stig_chrome = 'Browser-based attacks: phishing, malicious downloads, risky extensions or weakened browser protections that the STIG policy would prevent.'
    stig_defender = 'Defense evasion: Defender detects or blocks less than the STIG requires, so malware is more likely to run unnoticed.'
    stig_edge = 'Browser-based attacks: phishing, malicious downloads, risky extensions or weakened browser protections that the STIG policy would prevent.'
    stig_firefox = 'Browser-based attacks: phishing, malicious downloads, risky add-ons or weakened browser protections that the STIG policy would prevent.'
    stig_firewall = 'Remote exploitation and lateral movement: the firewall filters or logs less than the STIG requires, so exposed services and blocked attempts go unnoticed.'
    stig_adobe = 'Malicious PDFs: without Protected Mode, Enhanced Security and the JavaScript, attachment and URL restrictions the STIG asks for, a crafted PDF can run code, launch attachments or reach attacker sites when it is opened.'
    stig_office = 'Document-borne attacks: macros, embedded content and legacy file formats that the STIG policy would block can deliver malware through Office files.'
    stig_server2016 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    stig_server2019 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    stig_server2022 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    stig_server2025 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    stig_windows10 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    stig_windows11 = 'Depends on the rule: each DISA STIG setting closes a specific attack path (credential theft, relay, privilege escalation, logging gaps); the rule ID in the finding names it.'
    task_binary_writable = 'Privilege escalation and persistence: a user replaces the program a privileged scheduled task runs, and their code runs with the task''s account at its next trigger.'
    terminal_services_server_gaps = 'Session data exposure: shared temporary folders and several sessions per user make it easier to read another session''s files or hijack a disconnected session.'
    uac_admin_no_prompt = 'Silent elevation: malware started by an administrator gets full administrator rights without any prompt.'
    uac_disabled = 'No privilege separation: every process an administrator starts, including malware, runs with full administrator rights.'
    uac_hardening_gaps = 'UAC bypass and spoofing: the elevation prompt can be faked or driven by another program, installers elevate silently, or legacy apps write where they should not.'
    updates_pending = 'Exploitation of fixed vulnerabilities: the missing updates fix flaws that attackers can use until they are installed.'
    updates_stale = 'Exploitation of known vulnerabilities: months of security fixes may be missing, including flaws exploited in the wild.'
    user_rights_excessive = 'Privilege escalation: rights such as debug programs, backup, restore, impersonate or act as part of the OS let their holders read credentials or become SYSTEM.'
    vulnerable_driver_present = 'Kernel compromise (BYOVD): an attacker loads this known-vulnerable or malicious driver to kill security tools, read credentials or run code in the kernel.'
    wdigest_cleartext = 'Clear-text password theft: LSASS keeps the passwords of logged-on users in clear text, and mimikatz (sekurlsa::wdigest) reads them.'
    webclient_webdav_enabled = 'Authentication coercion and NTLM relay: an attacker makes the host authenticate over HTTP (WebDAV, PetitPotam) and relays it to LDAP or AD CS, which SMB signing does not stop.'
    winrm_insecure_auth = 'Credential capture and remote abuse: Basic or Digest authentication and unencrypted WinRM traffic expose credentials in the path, and RunAs credentials stored for plugins can be reused.'
    bloatware_installed = 'Larger attack surface: preinstalled apps and trials update on their own schedule, reach the internet and carry their own vulnerabilities (games and adware have shipped remote code execution flaws), and an expired third-party antivirus can leave Defender in passive mode.'
    brave_policy_gaps = 'Browser-based attacks: phishing, malicious downloads, risky extensions or weakened browser protections that the Chrome STIG policies would prevent, and Tor windows that reach the internet past the proxy and network monitoring.'
    script_files_execute_on_open = 'Malware delivery by phishing: a .js, .vbs, .wsf or .hta attachment or download runs with the user''s rights as soon as it is double-clicked, typically to download and start ransomware or a loader.'
    lolbin_outbound_not_blocked = 'Living-off-the-land downloads: an attacker uses signed Windows tools (certutil -urlcache, mshta or regsvr32 /i pointed at a remote URL, bitsadmin) to fetch payloads and run remote scripts past application allow lists.'
    removable_media_execute_allowed = 'Removable-media infection and insider attacks: a program brought on a USB drive or SD card (a dropped "found" stick, a rubber-ducky payload, an unapproved tool) runs directly from the device.'
    wpad_not_disabled = 'Traffic interception and credential capture: an attacker answers WPAD discovery, becomes the host''s web proxy and collects NTLM authentications.'
    wu_auto_updates_disabled = 'Exploitation of known vulnerabilities: security updates are not installed on their own, so the host falls behind on fixes.'
}
foreach ($t in @($script:CheckAttacks.Keys)) { if ($script:CheckCatalog.Contains($t)) { $script:CheckCatalog[$t]['Attacks'] = $script:CheckAttacks[$t] } }

# Microsoft's "standard protection" ASR rules, recommended for every device.
$script:OtherAsrRules = [ordered]@{
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless they meet a prevalence, age or trusted list criterion'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
}
# Judged only where Exchange Server is installed (the rule protects Exchange servers only).
$script:ExchangeAsrRules = [ordered]@{ 'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers' }
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
    # The remaining 14 of the 27 CIS 17.x audit-subcategory rules; this check already covered 13 of
    # them without saying so (see CHANGELOG). GUIDs verified live against `auditpol /list /subcategory:* /v`.
    @{ Guid = '0cce9239-69ae-11d9-bed3-505054503030'; Name = 'Application Group Management'; Need = 3 }
    @{ Guid = '0cce9248-69ae-11d9-bed3-505054503030'; Name = 'Plug and Play Events'; Need = 1 }
    @{ Guid = '0cce9249-69ae-11d9-bed3-505054503030'; Name = 'Group Membership'; Need = 1 }
    @{ Guid = '0cce9216-69ae-11d9-bed3-505054503030'; Name = 'Logoff'; Need = 1 }
    @{ Guid = '0cce921c-69ae-11d9-bed3-505054503030'; Name = 'Other Logon/Logoff Events'; Need = 3 }
    @{ Guid = '0cce9244-69ae-11d9-bed3-505054503030'; Name = 'Detailed File Share'; Need = 2 }
    @{ Guid = '0cce9224-69ae-11d9-bed3-505054503030'; Name = 'File Share'; Need = 3 }
    @{ Guid = '0cce9245-69ae-11d9-bed3-505054503030'; Name = 'Removable Storage'; Need = 3 }
    @{ Guid = '0cce9231-69ae-11d9-bed3-505054503030'; Name = 'Authorization Policy Change'; Need = 1 }
    @{ Guid = '0cce9232-69ae-11d9-bed3-505054503030'; Name = 'MPSSVC Rule-Level Policy Change'; Need = 3 }
    @{ Guid = '0cce9234-69ae-11d9-bed3-505054503030'; Name = 'Other Policy Change Events'; Need = 2 }
    @{ Guid = '0cce9213-69ae-11d9-bed3-505054503030'; Name = 'IPsec Driver'; Need = 3 }
    @{ Guid = '0cce9214-69ae-11d9-bed3-505054503030'; Name = 'Other System Events'; Need = 3 }
    @{ Guid = '0cce9210-69ae-11d9-bed3-505054503030'; Name = 'Security State Change'; Need = 1 }
    # Domain-controller-only subcategories of the CIS Windows Server benchmarks (section 17.2/17.4).
    # GUIDs verified live against `auditpol /list /subcategory:* /r`.
    @{ Guid = '0cce9236-69ae-11d9-bed3-505054503030'; Name = 'Computer Account Management'; Need = 1; Dc = $true }
    @{ Guid = '0cce9238-69ae-11d9-bed3-505054503030'; Name = 'Distribution Group Management'; Need = 1; Dc = $true }
    @{ Guid = '0cce923a-69ae-11d9-bed3-505054503030'; Name = 'Other Account Management Events'; Need = 1; Dc = $true }
    @{ Guid = '0cce923b-69ae-11d9-bed3-505054503030'; Name = 'Directory Service Access'; Need = 2; Dc = $true }
)

# Ports worth flagging when they listen beyond localhost. Workstation-only
# entries are normal on servers.
$script:RiskyListenPorts = @{
    'tcp/21' = 'FTP'; 'tcp/23' = 'Telnet'; 'udp/69' = 'TFTP'; 'udp/161' = 'SNMP'; 'tcp/1433' = 'SQL Server'; 'tcp/1521' = 'Oracle'
    'tcp/3306' = 'MySQL'; 'tcp/5432' = 'PostgreSQL'; 'tcp/5900' = 'VNC'; 'tcp/5901' = 'VNC'; 'tcp/6379' = 'Redis'
    'tcp/9200' = 'Elasticsearch'; 'tcp/11211' = 'Memcached'; 'udp/11211' = 'Memcached'; 'tcp/27017' = 'MongoDB'
}
$script:WorkstationOnlyListenPorts = @{ 'tcp/5985' = 'WinRM over HTTP' }

# BitLocker policy (CIS 18.10.9.x, optional BitLocker profile), from ansible-lockdown/Windows-11-CIS.
# Value name, CIS rule, expected value ('' = an empty string: access from earlier Windows disabled).
# Weak: the value lowers the protection itself. Severity per row; Unset = the Windows default is the
# problem, judged when not set too (workstations, not Home). Gaps: organizational choices, judged
# only when set.
$script:BitLockerPolicyWeak = @(
    @{ Name = 'OSHardwareEncryption'; Rule = '18.10.9.2.11'; Expected = 0; Severity = 'Medium' }
    @{ Name = 'FDVHardwareEncryption'; Rule = '18.10.9.1.10'; Expected = 0; Severity = 'Medium' }
    @{ Name = 'RDVHardwareEncryption'; Rule = '18.10.9.3.10'; Expected = 0; Severity = 'Medium' }
    @{ Name = 'EnableBDEWithNoTPM'; Rule = '18.10.9.2.14'; Expected = 0; Severity = 'Medium' }
    @{ Name = 'OSAllowSecureBootForIntegrity'; Rule = '18.10.9.2.2'; Expected = 1; Severity = 'Medium' }
    @{ Name = 'OSPassphrase'; Rule = '18.10.9.2.12'; Expected = 0; Severity = 'Medium' }
    @{ Name = 'UseAdvancedStartup'; Rule = '18.10.9.2.13'; Expected = 1; Severity = 'Low' }
    @{ Name = 'DisableExternalDMAUnderLock'; Rule = '18.10.9.4'; Expected = 1; Severity = 'Low'; Unset = $true }
    @{ Name = 'RDVDenyWriteAccess'; Rule = '18.10.9.3.14'; Expected = 1; Severity = 'Low'; Unset = $true }
)
$script:BitLockerPolicyGaps = @(
    @('FDVDiscoveryVolumeType', '18.10.9.1.1', ''), @('FDVRecovery', '18.10.9.1.2', 1), @('FDVManageDRA', '18.10.9.1.3', 1),
    @('FDVRecoveryPassword', '18.10.9.1.4', '1 or 2'), @('FDVRecoveryKey', '18.10.9.1.5', '1 or 2'), @('FDVHideRecoveryPage', '18.10.9.1.6', 1),
    @('FDVActiveDirectoryBackup', '18.10.9.1.7', 0), @('FDVActiveDirectoryInfoToStore', '18.10.9.1.8', 1), @('FDVRequireActiveDirectoryBackup', '18.10.9.1.9', 0),
    @('FDVPassphrase', '18.10.9.1.11', 0), @('FDVAllowUserCert', '18.10.9.1.12', 1), @('FDVEnforceUserCert', '18.10.9.1.13', 1),
    @('UseEnhancedPin', '18.10.9.2.1', 1), @('OSRecovery', '18.10.9.2.3', 1), @('OSManageDRA', '18.10.9.2.4', 0),
    @('OSRecoveryPassword', '18.10.9.2.5', 1), @('OSRecoveryKey', '18.10.9.2.6', 0), @('OSHideRecoveryPage', '18.10.9.2.7', 1),
    @('OSActiveDirectoryBackup', '18.10.9.2.8', 1), @('OSActiveDirectoryInfoToStore', '18.10.9.2.9', 1), @('OSRequireActiveDirectoryBackup', '18.10.9.2.10', 1),
    @('UseTPM', '18.10.9.2.15', 0), @('UseTPMPIN', '18.10.9.2.16', 1), @('UseTPMKey', '18.10.9.2.17', 0), @('UseTPMKeyPIN', '18.10.9.2.18', 0),
    @('RDVDiscoveryVolumeType', '18.10.9.3.1', ''), @('RDVRecovery', '18.10.9.3.2', 1), @('RDVManageDRA', '18.10.9.3.3', 1),
    @('RDVRecoveryPassword', '18.10.9.3.4', 0), @('RDVRecoveryKey', '18.10.9.3.5', 0), @('RDVHideRecoveryPage', '18.10.9.3.6', 1),
    @('RDVActiveDirectoryBackup', '18.10.9.3.7', 0), @('RDVActiveDirectoryInfoToStore', '18.10.9.3.8', 1), @('RDVRequireActiveDirectoryBackup', '18.10.9.3.9', 0),
    @('RDVPassphrase', '18.10.9.3.11', 0), @('RDVAllowUserCert', '18.10.9.3.12', 1), @('RDVEnforceUserCert', '18.10.9.3.13', 1),
    @('RDVDenyCrossOrg', '18.10.9.3.15', 0)
)

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
    # ServerCis: a rule that Windows 11 does not have, by its Server 2022 number ('2.3.5.2') or
    # '<benchmark>:<number>' when Server 2022 lacks it ('win10:5.8'); the Detail says where to quote
    # it with {cis}. Resolve-ExtraCis picks the host's own number and level (the extra part of
    # data\cis-map.json), or the Server 2022 (Windows 10) one when the host's benchmark lacks it.
    # Found / Expected: the value on the host and the value the framework requires, for the report
    # columns and the found/expected JSON Lines fields. A CIS-based check that does not pass them gets
    # them from its Detail ("Name = value (CIS x expects y)", see Get-FoundExpectedFromDetail).
    param([string]$Type, [string]$Object, [string]$Detail, [string]$Severity = '', [string]$ServerCis = '', [string]$Found = '', [string]$Expected = '')
    $meta = $script:CheckCatalog[$Type]
    if (-not $meta) { throw "Unknown check type: $Type" }
    # A check that follows several rules names the one that applies in the detail ("CIS 5.30 ...").
    # The profile level is the one in the catalog.
    $cis = "$($meta.Cis)"
    $bench = ''
    if ($ServerCis) {
        $x = Resolve-ExtraCis $ServerCis
        $bench = (Get-CisMap).benchmarks.($x.Bench)
        $Detail = $Detail.Replace('{cis}', "CIS $(Get-CisShortName $x.Bench) $($x.Rule)")
        $cis = "$($x.Rule) ($($x.Level))"
    }
    elseif ($cis) {
        $rule = [regex]::Match("$Detail", 'CIS (\d+(?:\.\d+)+)')
        $level = [regex]::Match($cis, '\((L\d)\)\s*$')
        if ($script:CisBench -ne 'win11') {
            # Another benchmark (Windows 10, a server): its rule, or "Windows 11 x.y" when it has none.
            $mapped = $false
            # Every number of a list ("CIS 2.3.7.5, 2.3.7.6") is translated; the benchmark is named once.
            $Detail = [regex]::Replace("$Detail", 'CIS (\d+(?:\.\d+)+(?:(?:, and |, | - | and )\d+(?:\.\d+)+)*)', [System.Text.RegularExpressions.MatchEvaluator] {
                    param($m)
                    $script:CisListMapped = $false
                    $list = [regex]::Replace($m.Groups[1].Value, '\d+(?:\.\d+)+', [System.Text.RegularExpressions.MatchEvaluator] { param($n) $x = ConvertTo-HostCisRule $n.Value; if ($x.Mapped) { $script:CisListMapped = $true }; $x.Rule })
                    "CIS $(if ($script:CisListMapped) { "$(Get-CisShortName $script:CisBench) " })$list"
                })
            if ($rule.Success) {
                $x = ConvertTo-HostCisRule $rule.Groups[1].Value
                $mapped = $x.Mapped
                $lv = if ($x.Level) { $x.Level } elseif ($level.Success) { $level.Groups[1].Value } else { '' }
                $cis = "$($x.Rule)$(if ($lv) { " ($lv)" })"
            }
            else {
                $cis = [regex]::Replace($cis, '(?<![\d.])\d+(?:\.\d+)+(?![\d.])', [System.Text.RegularExpressions.MatchEvaluator] { param($m) $x = ConvertTo-HostCisRule $m.Value; if ($x.Mapped) { $script:CisAnyMapped = $true }; $x.Rule })
                $mapped = [bool]$script:CisAnyMapped; $script:CisAnyMapped = $false
            }
            $bench = if ($mapped) { (Get-CisMap).benchmarks.($script:CisBench) } else { (Get-CisMap).benchmarks.win11 }
        }
        else {
            if ($rule.Success -and $level.Success) { $cis = "$($rule.Groups[1].Value) ($($level.Groups[1].Value))" }
            $bench = (Get-CisMap).benchmarks.win11
        }
    }
    if (-not $Severity) { $Severity = $meta.Severity }
    if (-not $Found -and -not $Expected -and ($meta.Cis -or $meta.CisServer)) {
        $fe = Get-FoundExpectedFromDetail $Detail
        if ($fe) { $Found = $fe.Found; $Expected = $fe.Expected }
    }
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
            CisBenchmark = $bench
            Found    = $Found
            Expected = $Expected
            Attacks  = "$($meta.Attacks)"
        })
}

function Get-FoundExpectedFromDetail {
    # "Name = value (CIS x expects y)", "Name not set (CIS x expects y)", "X is disabled (CIS x expects
    # enabled)", "Maximum size 20480 KB (CIS x expects at least 32768 KB)": the value and the
    # requirement. $null when the Detail does not say what is expected.
    param([string]$Detail)
    $m = [regex]::Match("$Detail", '^(?<pre>.*?)\s*\(CIS [^)]*?\bexpects (?<e>[^);]+)')
    if (-not $m.Success) { return $null }
    $pre = $m.Groups['pre'].Value.Trim().TrimEnd(':', ',', '.')
    $exp = $m.Groups['e'].Value.Trim().TrimEnd('.', ',')
    $found = if ($pre -match '^[\w.\-]+(?: \([^)]*\))? = (?<f>.+)$') { $Matches['f'] }
    elseif ($pre -match '^(?:[\w.\-]+ )?[Nn]ot set\b') { 'not set' }
    elseif ($pre -match '^[\w.\-]+ not set$') { 'not set' }
    elseif ($pre -match '^.{1,60} is (?<f>[\w ]{1,30})$') { $Matches['f'] }
    elseif ($pre -match '^Maximum size (?<f>\d+ KB)') { $Matches['f'] }
    elseif ($pre.Length -le 80) { $pre }
    else { return $null }
    # "0x20000000 (CIS ...": a value followed by its own explanation keeps only the value.
    $found = ($found -replace ':\s.*$', '' -replace ';\s.*$', '').Trim()
    return @{ Found = $found; Expected = $exp }
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

# ------------------------------------------------------------------ pending updates and installed software (KEV)
# CISA Known Exploited Vulnerabilities catalog: { vulnerabilities: [ { cveID, vendorProject, product,
# vulnerabilityName, dateAdded, knownRansomwareCampaignUse } ] }. Given as a file the user obtained
# (-KevFile) or downloaded by HostBadger (-KevOnline, lib\AI.ps1).
function ConvertFrom-KevCatalog {
    param([string]$Json)
    $doc = ConvertFrom-Json -InputObject $Json
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($doc.vulnerabilities | ForEach-Object { $_ })) {
        if (-not $v.cveID) { continue }
        $out.Add([PSCustomObject]@{ Cve = "$($v.cveID)"; Vendor = "$($v.vendorProject)"; Product = "$($v.product)"; Name = "$($v.vulnerabilityName)"; DateAdded = "$($v.dateAdded)"; Ransomware = ("$($v.knownRansomwareCampaignUse)" -eq 'Known') })
    }
    return $out.ToArray()
}

# LOLDrivers (www.loldrivers.io, Apache-2.0): known vulnerable and malicious Windows drivers. The full
# catalog (drivers.json, ~30 MB) is reduced to one entry per file hash: h SHA-256, i LOLDrivers id,
# c V vulnerable / M malicious, n file name, v verified by LOLDrivers, x CVE ids, g loads despite HVCI.
# Used by tools\Convert-LolDrivers.ps1 (data\vulnerable-drivers.json) and by -DriversOnline.
function ConvertFrom-LolDrivers {
    param([string]$Json)
    # The catalog has keys that differ only by case ("init" / "INIT"), which ConvertFrom-Json refuses:
    # PowerShell 7 reads it as hashtables, Windows PowerShell 5.1 through JavaScriptSerializer.
    if ($PSVersionTable.PSVersion.Major -ge 7) { $doc = ConvertFrom-Json -InputObject $Json -AsHashtable -Depth 64 }
    else {
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue; $ser.RecursionLimit = 256
        $doc = $ser.DeserializeObject($Json)
    }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($doc)) {
        $cat = if ("$($d['Category'])" -match '(?i)malicious') { 'M' } else { 'V' }
        # CVE ids: the CVE field when there is one, and those the description and the links name.
        $cveText = "$(@($d['CVE']) -join ' ') $(@(@($d['Commands']) | ForEach-Object { if ($_) { $_['Description'] } }) -join ' ') $(@($d['Resources']) -join ' ')"
        $cves = @([regex]::Matches($cveText, 'CVE-\d{4}-\d{4,}') | ForEach-Object { $_.Value.ToUpper() } | Sort-Object -Unique)
        foreach ($s in @($d['KnownVulnerableSamples'])) {
            if (-not $s) { continue }
            $h = "$($s['SHA256'])".Trim().ToLower()
            if ($h -notmatch '^[0-9a-f]{64}$' -or $seen.ContainsKey($h)) { continue }
            $seen[$h] = $true
            $name = "$($s['OriginalFilename'])"; if (-not $name -or $name -eq '-') { $name = "$($s['Filename'])" }
            $out.Add([ordered]@{ h = $h; i = "$($d['Id'])"; c = $cat; n = $name; v = ("$($d['Verified'])" -ieq 'true'); x = ($cves -join ' '); g = ("$($s['LoadsDespiteHVCI'])" -ieq 'true') })
        }
    }
    return $out.ToArray()
}

$script:DriverCatalog = $null
function Get-DriverCatalog {
    # The downloaded catalog when -DriversOnline was used, else the one shipped in data\.
    param($Config)
    if ($Config -and $Config.Drivers) { return @($Config.Drivers) }
    if ($null -eq $script:DriverCatalog) {
        $path = Join-Path $PSScriptRoot '..\data\vulnerable-drivers.json'
        $script:DriverCatalog = if (Test-Path -LiteralPath $path) { @((ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))).entries | ForEach-Object { $_ }) } else { @() }
    }
    return $script:DriverCatalog
}

function ConvertTo-WordText {
    param([string]$Text)
    return (' ' + (("$Text".ToLower() -replace '[^a-z0-9]+', ' ').Trim()) + ' ')
}

$script:KevVendorStop = @('inc', 'llc', 'ltd', 'corp', 'corporation', 'co', 'project', 'foundation', 'software', 'systems', 'group', 'the', 'and', 'of')
$script:KevProductStop = @('and', 'for', 'the', 'of', 'with')
# Windows components that the patch checks already cover.
$script:KevOsProduct = '(?i)\bwindows\b|win32k|\.net framework|\bdwm\b|\bsmb\b|\bkernel\b|ntlm|print spooler|common log file|desktop window|internet explorer|\bole\b|\bmshtml\b|\bactive directory\b'

$script:KevIndexCache = $null
function Get-KevIndex {
    param($Kev)
    $items = @($Kev | Where-Object { $_ })
    if ($script:KevIndexCache -and $script:KevIndexCache.Count -eq $items.Count -and $script:KevIndexCache.First -eq "$($items[0].Cve)") { return $script:KevIndexCache.Groups }
    $groups = @{}
    foreach ($e in $items) {
        if ("$($e.Vendor)" -match '(?i)^microsoft' -and "$($e.Product)" -match $script:KevOsProduct) { continue }
        $key = "$($e.Vendor)|$($e.Product)".ToLower()
        if (-not $groups.ContainsKey($key)) {
            $vt = @((ConvertTo-WordText $e.Vendor).Trim().Split(' ') | Where-Object { $_.Length -ge 2 -and $script:KevVendorStop -notcontains $_ })
            $pt = @((ConvertTo-WordText $e.Product).Trim().Split(' ') | Where-Object { $_.Length -ge 2 -and $script:KevProductStop -notcontains $_ })
            if ($pt.Count -eq 0) { continue }
            $groups[$key] = [PSCustomObject]@{ Vendor = $e.Vendor; Product = $e.Product; VendorTokens = $vt; ProductTokens = $pt; Entries = (New-Object System.Collections.Generic.List[object]) }
        }
        $groups[$key].Entries.Add($e)
    }
    $list = @($groups.Values)
    $script:KevIndexCache = @{ Count = $items.Count; First = "$($items[0].Cve)"; Groups = $list }
    return $list
}

# Software lifecycle: the end of support of releases still found on hosts, from the vendors' lifecycle
# pages (Microsoft, Adobe, Oracle, python.org, nodejs.org). Like $script:WindowsLifecycle, check a date
# before relying on it and add releases as they reach their end. Name is matched against the Programs
# and Features name, Version (when present) against its version; the first match wins. Only releases
# whose end has passed at collection give a finding.
$script:SoftwareLifecycle = @(
    @{ Product = 'Adobe Flash Player'; Name = '^Adobe Flash Player\b'; End = '2020-12-31'; Severity = 'High' }
    @{ Product = 'Adobe Shockwave Player'; Name = '^Adobe Shockwave Player\b'; End = '2019-04-09'; Severity = 'High' }
    @{ Product = 'Microsoft Silverlight'; Name = '^Microsoft Silverlight\b'; End = '2021-10-12'; Severity = 'Medium' }
    @{ Product = 'Java 6'; Name = '^Java(\(TM\))? 6\b|^Java(\(TM\))? SE Development Kit 6\b'; End = '2018-12-31'; Severity = 'High' }
    @{ Product = 'Java 7'; Name = '^Java(\(TM\))? 7\b|^Java(\(TM\))? SE Development Kit 7\b'; End = '2019-07-31'; Extended = '2022-07-19'; Severity = 'High' }
    @{ Product = 'Adobe Reader/Acrobat XI and older'; Name = '^Adobe (Reader|Acrobat)( Pro| Standard)? (XI|X|[5-9])\b'; End = '2017-10-15'; Severity = 'High' }
    @{ Product = 'Adobe Acrobat 2015'; Name = '^Adobe Acrobat\b.*\b2015\b'; End = '2020-04-07'; Severity = 'High' }
    @{ Product = 'Adobe Acrobat 2017'; Name = '^Adobe Acrobat\b.*\b2017\b'; End = '2022-06-06'; Severity = 'High' }
    @{ Product = 'Microsoft Office 2007'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2007\b'; End = '2017-10-10'; Severity = 'High' }
    @{ Product = 'Microsoft Office 2010'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2010\b'; End = '2020-10-13'; Severity = 'High' }
    @{ Product = 'Microsoft Office 2013'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2013\b'; End = '2023-04-11'; Severity = 'High' }
    @{ Product = 'Microsoft Office 2016'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2016\b'; End = '2025-10-14'; Severity = 'Medium' }
    @{ Product = 'Microsoft Office 2019'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2019\b'; End = '2025-10-14'; Severity = 'Medium' }
    @{ Product = 'Microsoft Office LTSC 2021'; Name = '^Microsoft (Office|Visio|Project)\b.*\b2021\b'; End = '2026-10-13'; Severity = 'Medium' }
    @{ Product = 'Microsoft Exchange Server 2010'; Name = '^Microsoft Exchange Server 2010\b'; End = '2020-10-13'; Severity = 'High' }
    @{ Product = 'Microsoft Exchange Server 2013'; Name = '^Microsoft Exchange Server 2013\b'; End = '2023-04-11'; Severity = 'High' }
    @{ Product = 'Microsoft Exchange Server 2016'; Name = '^Microsoft Exchange Server 2016\b'; End = '2025-10-14'; Extended = '2026-11-01'; Severity = 'High' }
    @{ Product = 'Microsoft Exchange Server 2019'; Name = '^Microsoft Exchange Server 2019\b'; End = '2025-10-14'; Extended = '2026-11-01'; Severity = 'High' }
    @{ Product = 'Microsoft SQL Server 2008'; Name = '^Microsoft SQL Server 2008( R2)?( \((32|64)-bit\))?$'; End = '2019-07-09'; Severity = 'Medium' }
    @{ Product = 'Microsoft SQL Server 2012'; Name = '^Microsoft SQL Server 2012( \((32|64)-bit\))?$'; End = '2022-07-12'; Severity = 'Medium' }
    @{ Product = 'Microsoft SQL Server 2014'; Name = '^Microsoft SQL Server 2014( \((32|64)-bit\))?$'; End = '2024-07-09'; Severity = 'Medium' }
    @{ Product = 'Microsoft SQL Server 2016'; Name = '^Microsoft SQL Server 2016( \((32|64)-bit\))?$'; End = '2026-07-14'; Severity = 'Medium' }
    @{ Product = 'Python 2'; Name = '^Python 2\.\d'; End = '2020-01-01'; Severity = 'Medium' }
    @{ Product = 'Python 3.5'; Name = '^Python 3\.5\.\d'; End = '2020-09-30'; Severity = 'Medium' }
    @{ Product = 'Python 3.6'; Name = '^Python 3\.6\.\d'; End = '2021-12-23'; Severity = 'Medium' }
    @{ Product = 'Python 3.7'; Name = '^Python 3\.7\.\d'; End = '2023-06-27'; Severity = 'Medium' }
    @{ Product = 'Python 3.8'; Name = '^Python 3\.8\.\d'; End = '2024-10-07'; Severity = 'Medium' }
    @{ Product = 'Python 3.9'; Name = '^Python 3\.9\.\d'; End = '2025-10-31'; Severity = 'Medium' }
    @{ Product = 'Microsoft Visual C++ 2005 Redistributable'; Name = '^Microsoft Visual C\+\+ 2005\b.*Redistributable'; End = '2016-04-12'; Severity = 'Low' }
    @{ Product = 'Microsoft Visual C++ 2008 Redistributable'; Name = '^Microsoft Visual C\+\+ 2008\b.*Redistributable'; End = '2018-04-10'; Severity = 'Low' }
    @{ Product = 'Microsoft Visual C++ 2010 Redistributable'; Name = '^Microsoft Visual C\+\+ 2010\b.*Redistributable'; End = '2020-07-14'; Severity = 'Low' }
    @{ Product = 'Microsoft Visual C++ 2012 Redistributable'; Name = '^Microsoft Visual C\+\+ 2012\b.*Redistributable'; End = '2023-01-10'; Severity = 'Low' }
    @{ Product = 'Microsoft Visual C++ 2013 Redistributable'; Name = '^Microsoft Visual C\+\+ 2013\b.*Redistributable'; End = '2024-04-09'; Severity = 'Low' }
)
# .NET (Core): runtimes, SDKs and the ASP.NET Core and Windows Desktop runtimes carry the release in the
# name. .NET Framework is part of Windows and not listed here.
foreach ($r in @(@('1.0', '2019-06-27'), @('1.1', '2019-06-27'), @('2.0', '2018-10-01'), @('2.1', '2021-08-19'), @('2.2', '2019-12-23'), @('3.0', '2020-03-03'), @('3.1', '2022-12-13'), @('5.0', '2022-05-10'), @('6.0', '2024-11-12'), @('7.0', '2024-05-14'))) {
    $label = if ([int]$r[0].Split('.')[0] -lt 5) { ".NET Core $($r[0])" } else { ".NET $($r[0].Split('.')[0])" }
    $script:SoftwareLifecycle += @{ Product = "Microsoft $label"; Name = ('^Microsoft (ASP\.NET Core|\.NET( Core)?( Runtime| SDK| Host( FX Resolver)?)?|Windows Desktop Runtime)( -)? ' + [regex]::Escape($r[0]) + '\.'); End = $r[1]; Severity = 'Medium' }
}
# Node.js names no release: the major version says it.
foreach ($r in @(@('[4-9]|0', '2019-12-31', '9 and older'), @('10', '2021-04-30'), @('11', '2019-06-30'), @('12', '2022-04-30'), @('13', '2020-06-01'), @('14', '2023-04-30'), @('15', '2021-06-01'), @('16', '2023-09-11'), @('17', '2022-06-01'), @('18', '2025-04-30'), @('19', '2023-06-01'), @('20', '2026-04-30'), @('21', '2024-06-01'), @('23', '2025-06-01'))) {
    $label = if ($r.Count -gt 2) { $r[2] } else { $r[0] }
    $script:SoftwareLifecycle += @{ Product = "Node.js $label"; Name = '^Node\.js\b'; Version = "^($($r[0]))\."; End = $r[1]; Severity = 'Medium' }
}

function Get-SoftwareLifecycle {
    # The lifecycle row of an installed program (name, version), or nothing.
    param($Software)
    $n = "$($Software.name)"; $v = "$($Software.version)"
    foreach ($row in $script:SoftwareLifecycle) {
        if ($n -notmatch $row.Name) { continue }
        if ($row.Version -and $v -notmatch $row.Version) { continue }
        return $row
    }
}

# Lifecycle data from endoflife.date (MIT, -EolOnline or -EolFile): the release lines of each product,
# with their end of support, paid extended support and latest version. Each entry ties a Programs and
# Features name to one product there: c is the release line ("3.12", "8", "2016"), v the installed
# version when the name or the version gives it. Rapid products (a release every few weeks, each fixed
# only until the next) are behind, not out of support, when their line has ended.
$script:EolProductMap = @(
    @{ Slug = 'python'; Label = 'Python'; Name = '^Python (?<v>(?<c>\d+\.\d+)\.\d+)' }
    @{ Slug = 'nodejs'; Label = 'Node.js'; Name = '^Node\.js$'; Version = '^(?<v>(?<c>\d+)\.\d+\.\d+)' }
    @{ Slug = 'dotnet'; Label = 'Microsoft .NET'; Name = '^Microsoft (?:ASP\.NET Core|\.NET(?: Core)? Runtime -|Windows Desktop Runtime -) (?<v>(?<c>\d+\.\d+)\.\d+)' }
    @{ Slug = 'office'; Label = 'Microsoft Office'; Name = '^Microsoft (?:Office|Visio|Project)\b.*\b(?<c>20\d\d)\b' }
    @{ Slug = 'msexchange'; Label = 'Microsoft Exchange Server'; Name = '^Microsoft Exchange Server (?<c>20\d\d)\b'; Severity = 'High' }
    @{ Slug = 'oracle-jdk'; Label = 'Java'; Name = '^Java(?:\(TM\))? (?:SE Development Kit )?(?<v>(?<c>\d+)(?: Update \d+|(?:\.\d+)+)?)(?!\S)'; Severity = 'High' }
    @{ Slug = 'eclipse-temurin'; Label = 'Eclipse Temurin'; Name = '^Eclipse Temurin J(?:DK|RE) with Hotspot (?<v>(?<c>\d+)(?:\.\d+)*(?:\+\d+)?)' }
    @{ Slug = 'firefox'; Label = 'Mozilla Firefox'; Name = '^Mozilla Firefox\b'; Version = '^(?<v>(?<c>\d+)\.\d+(?:\.\d+)*)'; Rapid = $true }
    @{ Slug = 'chrome'; Label = 'Google Chrome'; Name = '^Google Chrome$'; Version = '^(?<v>(?<c>\d+)\.\d+(?:\.\d+)*)'; Rapid = $true }
    @{ Slug = 'notepad-plus-plus'; Label = 'Notepad++'; Name = '^Notepad\+\+'; Version = '^(?<v>(?<c>\d+\.\d+)(?:\.\d+)*)'; Rapid = $true }
    @{ Slug = 'powershell'; Label = 'PowerShell'; Name = '^PowerShell \d'; Version = '^(?<v>(?<c>\d+\.\d+)\.\d+)' }
    @{ Slug = 'virtualbox'; Label = 'Oracle VirtualBox'; Name = '^Oracle (?:VM )?VirtualBox\b'; Version = '^(?<v>(?<c>\d+\.\d+)\.\d+)' }
    @{ Slug = 'wireshark'; Label = 'Wireshark'; Name = '^Wireshark\b'; Version = '^(?<v>(?<c>\d+\.\d+)\.\d+)' }
)

function ConvertTo-EolDateText {
    # PowerShell 7 turns "2026-10-13" into a local DateTime: keep the calendar date as written.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
    if ("$Value" -match '^\d{4}-\d{2}-\d{2}') { return "$Value".Substring(0, 10) }
    return ''
}

function ConvertFrom-EolCatalog {
    # endoflife.date API v1: /products/full (result is the list of products), one product (result is
    # that product), or the reduced copy HostBadger keeps next to a report (same shape). Returns
    # @{ slug = releases }, only for the products in $script:EolProductMap and SQL Server.
    param([string]$Json)
    $doc = ConvertFrom-Json -InputObject $Json
    $wanted = @($script:EolProductMap | ForEach-Object { $_.Slug }) + 'mssqlserver'
    $out = @{}
    foreach ($p in @($doc.result | ForEach-Object { $_ })) {
        $slug = "$($p.name)"
        if ($wanted -notcontains $slug) { continue }
        $rels = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($p.releases | ForEach-Object { $_ })) {
            if (-not "$($r.name)") { continue }
            $rels.Add([PSCustomObject]@{ Name = "$($r.name)"; IsEol = ($r.isEol -eq $true); EolFrom = (ConvertTo-EolDateText $r.eolFrom); EoesFrom = (ConvertTo-EolDateText $r.eoesFrom)
                    Latest = "$(if ($r.latest) { $r.latest.name })"; LatestDate = (ConvertTo-EolDateText $(if ($r.latest) { $r.latest.date }))
                    Label = "$($r.label)"; LatestGdr = "$(if ($r.custom) { $r.custom.latestGdr })" })
        }
        $out[$slug] = $rels.ToArray()
    }
    if ($out.Count -eq 0) { throw 'no product HostBadger knows (python, nodejs, dotnet...) in this file' }
    return $out
}

function ConvertTo-EolCatalogJson {
    # The reduced copy kept next to the report: the API v1 shape, only the products HostBadger maps.
    param($Catalog, [string]$Source)
    $products = foreach ($slug in @($Catalog.Keys | Sort-Object)) {
        [ordered]@{ name = $slug; releases = @($Catalog[$slug] | ForEach-Object {
                    $rel = [ordered]@{ name = $_.Name; isEol = $_.IsEol; eolFrom = $(if ($_.EolFrom) { $_.EolFrom } else { $null }); eoesFrom = $(if ($_.EoesFrom) { $_.EoesFrom } else { $null })
                        latest = $(if ($_.Latest) { [ordered]@{ name = $_.Latest; date = $(if ($_.LatestDate) { $_.LatestDate } else { $null }) } } else { $null }) }
                    if ($_.Label) { $rel['label'] = $_.Label }
                    if ($_.LatestGdr) { $rel['custom'] = [ordered]@{ latestGdr = $_.LatestGdr } }
                    $rel
                }) }
    }
    return ([ordered]@{ source = $Source; result = @($products) } | ConvertTo-Json -Depth 8)
}

function Find-EolRelease {
    # The endoflife.date release line of an installed program, or nothing (unknown product or line).
    param($Software, $Catalog)
    $n = "$($Software.name)"; $ver = "$($Software.version)"
    foreach ($m in $script:EolProductMap) {
        if ($n -notmatch $m.Name) { continue }
        $g = $Matches
        if ($m.Version) { if ($ver -match $m.Version) { $g = $Matches } else { return } }
        $rels = @($Catalog[$m.Slug] | Where-Object { $_ })
        if ($rels.Count -eq 0) { return }
        $c = "$($g['c'])"
        $rel = $rels | Where-Object { $_.Name -eq $c } | Select-Object -First 1
        # .NET 5 and later are listed by major version ("6"), the installed name says "6.0".
        if (-not $rel) { $rel = $rels | Where-Object { $_.Name -eq $c.Split('.')[0] } | Select-Object -First 1 }
        if (-not $rel) { return }
        return [PSCustomObject]@{ Map = $m; Release = $rel; Cycle = $c; Version = "$($g['v'])" }
    }
}

# SQL Server (endoflife.date mssqlserver) has one release line per service pack ("13.0-sp3", its Azure
# Connect Pack "13.0-sp3-acp", "10.50-sp3"): the Programs and Features name does not say which, so each
# instance is judged on the build the collector reads (sqlServer section).
function Get-SqlInstanceVersion {
    # The build of a SQL Server instance (13.0.6300.2): the version of the engine file, else the registry
    # PatchLevel or Version, whose second number is the service pack (13.3.6300.2 is 13.0 SP3, 10.53 is
    # 10.50 SP3).
    param($Instance)
    if ("$($Instance.fileVersion)" -match '^\d{1,2}\.\d+\.\d+') { return "$($Instance.fileVersion)".Split(' ')[0] }
    foreach ($v in @("$($Instance.patchLevel)", "$($Instance.version)")) {
        if ($v -match '^(\d{1,2})\.(\d+)\.(\d+)(\.\d+)?') { return '{0}.{1}.{2}{3}' -f $Matches[1], $(if ([int]$Matches[2] -ge 50) { 50 } else { 0 }), $Matches[3], $Matches[4] }
    }
    return ''
}

function Find-SqlRelease {
    # The release line of a SQL Server build: the same version (13.0, 10.50), then, when that version has
    # several service pack lines, the one whose latest CU or GDR build is in the same thousand (SP2 is
    # 13.0.5xxx, SP3 13.0.6xxx, its Azure Connect Pack 13.0.7xxx).
    param([string]$Version, $Releases)
    $x = Get-VersionNumbers $Version
    if ($x.Count -lt 3) { return }
    $same = @($Releases | Where-Object { $_ -and $_.Name -match '^(\d+)\.(\d+)' -and [int]$Matches[1] -eq $x[0] -and [int]$Matches[2] -eq $x[1] })
    if ($same.Count -eq 1) { return $same[0] }
    $band = [Math]::Floor($x[2] / 1000)
    $hit = @($same | Where-Object { @(@($_.Latest, $_.LatestGdr) | Where-Object { $_ -and ($n = Get-VersionNumbers $_).Count -ge 3 -and [Math]::Floor($n[2] / 1000) -eq $band }).Count -gt 0 })
    if ($hit.Count -eq 1) { return $hit[0] }
}

function Get-SqlLineName {
    # "Microsoft SQL Server 2014 SP3" from the endoflife.date label "2014 'Hekaton' SP3".
    param($Release)
    $l = if ($Release.Label) { ("$($Release.Label)" -replace " '[^']*'", '').Trim() } else { $Release.Name }
    return "Microsoft SQL Server $l"
}

# Programs that endoflife.date does not cover, judged on the versions of their Chocolatey community
# package (-ChocoOnline / -ChocoFile): every version with the date it was published, so a host is late
# only for releases that existed at collection. Id is the package id; v the installed version (from
# the version, else from the name). The download asks for every package in this list, whatever the
# hosts have, so the requests say nothing about the fleet.
$script:ChocoProductMap = @(
    @{ Id = '7zip'; Label = '7-Zip'; Name = '^7-Zip \d'; Version = '^(?<v>\d+\.\d+)' }
    @{ Id = 'vlc'; Label = 'VLC media player'; Name = '^VLC media player$'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'git'; Label = 'Git for Windows'; Name = '^Git(?: version [\d.]+)?$'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'gimp'; Label = 'GIMP'; Name = '^GIMP \d'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'winscp'; Label = 'WinSCP'; Name = '^WinSCP \d'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'putty'; Label = 'PuTTY'; Name = '^PuTTY release \d'; Version = '^(?<v>\d+\.\d+)' }
    @{ Id = 'filezilla'; Label = 'FileZilla'; Name = '^FileZilla(?: Client)? \d'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'keepass'; Label = 'KeePass'; Name = '^KeePass Password Safe 2'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'audacity'; Label = 'Audacity'; Name = '^Audacity \d'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'mullvad-app'; Label = 'Mullvad VPN'; Name = '^Mullvad VPN\b'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'obs-studio'; Label = 'OBS Studio'; Name = '^OBS Studio$'; Version = '^(?<v>\d+(?:\.\d+)+)' }
    @{ Id = 'anydesk'; Label = 'AnyDesk'; Name = '^AnyDesk$'; Version = '(?<v>\d+(?:\.\d+)+)' }
)

function ConvertTo-ChocoVersion {
    # A package version as the program's own: a pre-release is dropped, and a package fix version
    # (a fourth part that is a date, 18.5.0.20180730) is the program version 18.5.0.
    param([string]$Version)
    if (-not $Version -or $Version -match '-') { return '' }
    return ($Version -replace '\.(?:19|20)\d{6}$', '')
}

function ConvertFrom-ChocoFeed {
    # One page of the Chocolatey OData feed (FindPackagesById, Atom XML): @{ Versions; Entries } (Entries
    # counts pre-releases too, for paging), or nothing when the text is not a feed (an unknown package
    # id ends on an HTML error page).
    param([string]$Xml)
    try { $doc = [xml]$Xml } catch { return }
    if (-not $doc.feed) { return }
    $vers = New-Object System.Collections.Generic.List[object]
    # A property with an m:type attribute is an element, one without is plain text.
    $text = { param($x) if ($x -is [System.Xml.XmlElement]) { $x.InnerText } else { "$x" } }
    foreach ($e in @($doc.feed.entry | Where-Object { $_ })) {
        $p = $e.properties
        if ((& $text $p.IsPrerelease) -match '(?i)true') { continue }
        $raw = & $text $p.Version
        $pub = & $text $p.Published
        $v = ConvertTo-ChocoVersion $raw
        if ($v -and $pub) { $vers.Add([PSCustomObject]@{ Version = $v; Published = (ConvertTo-EolDateText $pub) }) }
    }
    return [PSCustomObject]@{ Versions = $vers.ToArray(); Entries = @($doc.feed.entry | Where-Object { $_ }).Count }
}

function Merge-ChocoVersions {
    # One entry per version, with its earliest publication date (a package fix republishes a version).
    param($Versions)
    $by = @{}
    foreach ($v in @($Versions | Where-Object { $_ -and $_.Version -and $_.Published })) {
        if (-not $by.ContainsKey($v.Version) -or $v.Published -lt $by[$v.Version].Published) { $by[$v.Version] = [PSCustomObject]@{ Version = $v.Version; Published = $v.Published } }
    }
    return @($by.Values | Sort-Object Published)
}

function ConvertFrom-ChocoCatalog {
    # The copy kept next to the report (<report>_choco.json): @{ id = versions }.
    param([string]$Json)
    $doc = ConvertFrom-Json -InputObject $Json
    $out = @{}
    foreach ($p in @($doc.products | ForEach-Object { $_ })) {
        if (-not "$($p.id)") { continue }
        $out["$($p.id)"] = @(Merge-ChocoVersions @($p.versions | ForEach-Object { [PSCustomObject]@{ Version = (ConvertTo-ChocoVersion "$($_.version)"); Published = (ConvertTo-EolDateText $_.published) } }))
    }
    if ($out.Count -eq 0) { throw 'no package in this file' }
    return $out
}

function ConvertTo-ChocoCatalogJson {
    param($Catalog, [string]$Source)
    # A package with no version is left out (an empty array would become {} on Windows PowerShell 5.1).
    $products = foreach ($id in @($Catalog.Keys | Sort-Object | Where-Object { @($Catalog[$_]).Count -gt 0 })) {
        [ordered]@{ id = $id; versions = @($Catalog[$id] | ForEach-Object { [ordered]@{ version = $_.Version; published = $_.Published } }) }
    }
    return ([ordered]@{ source = $Source; products = @($products) } | ConvertTo-Json -Depth 6)
}

function Find-ChocoProduct {
    # The Chocolatey entry of an installed program and its version, or nothing.
    param($Software)
    $n = "$($Software.name)"; $ver = "$($Software.version)"
    foreach ($m in $script:ChocoProductMap) {
        if ($n -notmatch $m.Name) { continue }
        $v = if ($ver -match $m.Version) { $Matches['v'] } elseif ($n -match $m.Version.TrimStart('^')) { $Matches['v'] } else { '' }
        if (-not $v) { return }
        return [PSCustomObject]@{ Map = $m; Version = "$v" }
    }
}

# Known vulnerabilities by installed version (-CveOnline / -CveFile): the CVEs of each product from
# NVD (CPE vendor:product, every version asked for, so NVD never learns what is installed), judged
# here against the version ranges of each CVE, and the EPSS score of each CVE (FIRST, the daily file
# of every CVE). Keyed by the Label of $script:EolProductMap / $script:ChocoProductMap. Products whose
# Windows builds are not described by version ranges in NVD (Office, Exchange, Oracle Java) and the
# rapid-release browsers (software_outdated covers them) are not listed.
$script:CveCpeMap = [ordered]@{
    'Python'            = @('python:python')
    'Node.js'           = @('nodejs:node.js')
    'Microsoft .NET'    = @('microsoft:.net', 'microsoft:asp.net_core')
    'Notepad++'         = @('notepad-plus-plus:notepad\+\+')
    'PowerShell'        = @('microsoft:powershell')
    'Oracle VirtualBox' = @('oracle:vm_virtualbox')
    'Wireshark'         = @('wireshark:wireshark')
    '7-Zip'             = @('7-zip:7-zip')
    'VLC media player'  = @('videolan:vlc_media_player')
    'Git for Windows'   = @('git-scm:git', 'git_for_windows_project:git_for_windows')
    'GIMP'              = @('gimp:gimp')
    'WinSCP'            = @('winscp:winscp')
    'PuTTY'             = @('putty:putty', 'simon_tatham:putty')
    'FileZilla'         = @('filezilla-project:filezilla_client')
    'KeePass'           = @('keepass:keepass')
    'Audacity'          = @('audacityteam:audacity')
    'Mullvad VPN'       = @('mullvad:mullvad_vpn')
    'AnyDesk'           = @('anydesk:anydesk')
}

function Find-InstalledProduct {
    # The product (Label) and installed version of a program, from the endoflife.date and Chocolatey
    # maps, or nothing when it is not mapped or no version can be read.
    param($Software)
    $n = "$($Software.name)"; $ver = "$($Software.version)"
    foreach ($m in $script:EolProductMap) {
        if ($n -notmatch $m.Name) { continue }
        $g = $Matches
        if ($m.Version) { if ($ver -match $m.Version) { $g = $Matches } else { return } }
        if (-not "$($g['v'])") { return }
        return [PSCustomObject]@{ Label = $m.Label; Version = "$($g['v'])" }
    }
    $c = Find-ChocoProduct $Software
    if ($c) { return [PSCustomObject]@{ Label = $c.Map.Label; Version = $c.Version } }
}

function ConvertFrom-NvdPage {
    # One page of the NVD CVE API 2.0: @{ Total; Start; Count; Cves }, each CVE reduced to what the
    # check needs: id, publication date, CVSS base score (NVD's own v3.1 score first), the date CISA
    # added it to KEV, and the vulnerable version ranges of the given CPE vendor:product names.
    param([string]$Json, [string[]]$Cpe)
    $doc = ConvertFrom-Json -InputObject $Json
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($w in @($doc.vulnerabilities | ForEach-Object { $_ })) {
        $c = $w.cve
        if (-not $c.id -or "$($c.vulnStatus)" -match '(?i)rejected') { continue }
        $ranges = New-Object System.Collections.Generic.List[object]
        $stack = New-Object System.Collections.Generic.Stack[object]
        foreach ($cfg in @($c.configurations | ForEach-Object { $_ })) { foreach ($nd in @($cfg.nodes | ForEach-Object { $_ })) { $stack.Push($nd) } }
        while ($stack.Count -gt 0) {
            $nd = $stack.Pop()
            foreach ($ch in @($nd.children | Where-Object { $_ })) { $stack.Push($ch) }
            foreach ($cm in @($nd.cpeMatch | Where-Object { $_ -and $_.vulnerable -eq $true })) {
                $parts = "$($cm.criteria)" -split '(?<!\\):'
                if ($parts.Count -lt 6) { continue }
                $vp = "$($parts[3]):$($parts[4])"
                if ($Cpe -notcontains $vp) { continue }
                $exact = if ($parts[5] -notin '*', '-', '') { $parts[5] -replace '\\', '' } else { '' }
                $ranges.Add([ordered]@{ cpe = $vp; version = $exact; si = "$($cm.versionStartIncluding)"; se = "$($cm.versionStartExcluding)"; ei = "$($cm.versionEndIncluding)"; ee = "$($cm.versionEndExcluding)" })
            }
        }
        if ($ranges.Count -eq 0) { continue }
        $score = $null
        foreach ($set in 'cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2') {
            $ms = @($c.metrics.$set | Where-Object { $_ })
            if ($ms.Count -eq 0) { continue }
            $pick = @($ms | Where-Object { $_.type -eq 'Primary' }) + $ms | Select-Object -First 1
            $score = [double]$pick.cvssData.baseScore; break
        }
        $out.Add([ordered]@{ id = "$($c.id)"; published = (ConvertTo-EolDateText $c.published); score = $score; kev = (ConvertTo-EolDateText $c.cisaExploitAdd); ranges = $ranges.ToArray() })
    }
    return [PSCustomObject]@{ Total = [int]$doc.totalResults; Start = [int]$doc.startIndex; Count = @($doc.vulnerabilities).Count; Cves = $out.ToArray() }
}

function Test-CveAffects {
    # Whether an installed version falls in one of a CVE's vulnerable ranges (or is its exact version).
    param($Ranges, [string]$Version)
    foreach ($r in @($Ranges | Where-Object { $_ })) {
        if ($r.version) { if ((Compare-SoftwareVersion $Version $r.version) -eq 0) { return $true }; continue }
        if ($r.si -and (Compare-SoftwareVersion $Version $r.si) -lt 0) { continue }
        if ($r.se -and (Compare-SoftwareVersion $Version $r.se) -le 0) { continue }
        if ($r.ei -and (Compare-SoftwareVersion $Version $r.ei) -gt 0) { continue }
        if ($r.ee -and (Compare-SoftwareVersion $Version $r.ee) -ge 0) { continue }
        return $true
    }
    return $false
}

function ConvertFrom-EpssCsv {
    # The EPSS daily file (#model_version...,score_date:...; cve,epss,percentile): @{ Date; Scores },
    # only for the CVEs asked for when a list is given.
    param([string]$Text, $Wanted)
    $date = if ($Text -match 'score_date:(\d{4}-\d{2}-\d{2})') { $Matches[1] } else { '' }
    $scores = @{}
    foreach ($line in $Text.Split("`n")) {
        if (-not $line.StartsWith('CVE-')) { continue }
        $f = $line.TrimEnd("`r").Split(',')
        if ($f.Count -lt 3 -or ($Wanted -and -not $Wanted.Contains($f[0]))) { continue }
        $scores[$f[0]] = [double]::Parse($f[1], [Globalization.CultureInfo]::InvariantCulture)
    }
    return [PSCustomObject]@{ Date = $date; Scores = $scores }
}

function ConvertFrom-CveCatalog {
    # The copy kept next to the report (<report>_cve.json): @{ Products = @{ Label = cves }; Epss;
    # EpssDate }.
    param([string]$Json)
    $doc = ConvertFrom-Json -InputObject $Json
    $prod = @{}
    foreach ($p in @($doc.products | ForEach-Object { $_ })) {
        if (-not "$($p.label)") { continue }
        $prod["$($p.label)"] = @($p.cves | ForEach-Object {
                [ordered]@{ id = "$($_.id)"; published = (ConvertTo-EolDateText $_.published); score = $(if ($null -ne $_.score) { [double]$_.score } else { $null }); kev = (ConvertTo-EolDateText $_.kev)
                    ranges = @($_.ranges | ForEach-Object { [ordered]@{ cpe = "$($_.cpe)"; version = "$($_.version)"; si = "$($_.si)"; se = "$($_.se)"; ei = "$($_.ei)"; ee = "$($_.ee)" } }) }
            })
    }
    if ($prod.Count -eq 0) { throw 'no product in this file' }
    $epss = @{}
    foreach ($e in @($doc.epss | ForEach-Object { $_ })) { if ("$($e.cve)") { $epss["$($e.cve)"] = [double]$e.epss } }
    return @{ Products = $prod; Epss = $epss; EpssDate = "$($doc.epssDate)" }
}

function ConvertTo-CveCatalogJson {
    param($Catalog, [string]$Source)
    $products = foreach ($l in @($Catalog.Products.Keys | Sort-Object | Where-Object { @($Catalog.Products[$_]).Count -gt 0 })) {
        [ordered]@{ label = $l; cves = @($Catalog.Products[$l]) }
    }
    $epss = @(foreach ($k in @($Catalog.Epss.Keys | Sort-Object)) { [ordered]@{ cve = $k; epss = $Catalog.Epss[$k] } })
    $doc = [ordered]@{ source = $Source; epssDate = "$($Catalog.EpssDate)"; products = @($products) }
    if ($epss.Count -gt 0) { $doc['epss'] = $epss }
    return ($doc | ConvertTo-Json -Depth 8)
}

function Get-VersionNumbers {
    # The numbers of a version in order, without build metadata ("25.0.4.1+1" -> 25, 0, 4, 1).
    param([string]$Version)
    return @([regex]::Matches(($Version -replace '\+\S*$', ''), '\d+') | ForEach-Object { [long]$_.Value })
}

function Get-SoftwareVersionGap {
    # How far the first number that differs is behind, below the release line: 8.9.1 -> 8.9.8.1 is 7,
    # 7.4.20 -> 7.4.21 is 1. 0 when equal or when the major version differs.
    param([string]$Installed, [string]$Latest)
    $x = Get-VersionNumbers $Installed; $y = Get-VersionNumbers $Latest
    for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) {
        $p = if ($i -lt $x.Count) { $x[$i] } else { [long]0 }
        $q = if ($i -lt $y.Count) { $y[$i] } else { [long]0 }
        if ($p -ne $q) { if ($i -eq 0) { return 0 }; return [Math]::Max(0, $q - $p) }
    }
    return 0
}

function Compare-SoftwareVersion {
    # -1, 0 or 1, comparing the numbers in order: "8 Update 431" < "8u503", "157.0" < "157.0.1".
    # Build metadata after "+" is not compared.
    param([string]$A, [string]$B)
    $x = Get-VersionNumbers $A
    $y = Get-VersionNumbers $B
    for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) {
        # Not $a/$b: variables ignore case, and those would be the [string] parameters.
        $p = if ($i -lt $x.Count) { $x[$i] } else { [long]0 }
        $q = if ($i -lt $y.Count) { $y[$i] } else { [long]0 }
        if ($p -lt $q) { return -1 }
        if ($p -gt $q) { return 1 }
    }
    return 0
}

function Invoke-SoftwareChecks {
    param($S, $Config, $can)
    if ((& $can 'software_eol') -or (& $can 'software_outdated') -or (& $can 'software_cve')) {
        # Days a program may take to pick up a new release (auto-update, a monthly ring) before it is late.
        $grace = if ($Config.SoftwareGraceDays) { [int]$Config.SoftwareGraceDays } else { 30 }
        $seen = @{}
        $emit = {
            param($Type, $Object, $Severity, $Detail, $Found, $Expected)
            if (-not (& $can $Type) -or $seen.ContainsKey("$Type|$Object")) { return }
            $seen["$Type|$Object"] = $true
            Add-Finding -Type $Type -Object $Object -Severity $Severity -Detail $Detail -Found $Found -Expected $Expected
        }
        # SQL Server instances against endoflife.date: one finding per release line, on the oldest build
        # of its instances. Once every instance is placed, the Programs and Features rows of SQL Server
        # are left to it; an instance whose line cannot be told leaves them to the table.
        $sqlRels = if ($Config.Eol) { @($Config.Eol['mssqlserver'] | Where-Object { $_ }) } else { @() }
        $sqlInst = @($S.sqlServer | Where-Object { $_ })
        $sqlDone = $false
        if ($sqlRels.Count -gt 0 -and $sqlInst.Count -gt 0) {
            $byProduct = [ordered]@{}
            $sqlDone = $true
            foreach ($i in $sqlInst) {
                $v = Get-SqlInstanceVersion $i
                $r = if ($v) { Find-SqlRelease $v $sqlRels } else { $null }
                if (-not $r) { $sqlDone = $false; continue }
                $name = Get-SqlLineName $r
                # The Object keeps the table's product name (2008 R2 is "Microsoft SQL Server 2008").
                $product = if ($name -match '^Microsoft SQL Server (\d{4}(?: R2)?|\d+\.\d+)') { "Microsoft SQL Server $($Matches[1])" } else { $name }
                $row = Get-SoftwareLifecycle ([PSCustomObject]@{ name = $product; version = '' })
                if ($row) { $product = $row.Product }
                $end = ConvertTo-UtcDate $r.EolFrom
                # A supported line: behind the latest cumulative update, or, on the GDR branch (security
                # fixes only, builds in their own thousand: 16.0.1xxx against CU 16.0.4xxx), behind the
                # latest GDR. endoflife.date dates only the latest CU.
                $cu = "$($r.Latest)".Split(' ')[0]; $gdr = "$($r.LatestGdr)"
                $vn = Get-VersionNumbers $v; $cn = Get-VersionNumbers $cu; $gn = Get-VersionNumbers $gdr
                $onGdr = $gn.Count -ge 3 -and $cn.Count -ge 3 -and [Math]::Floor($vn[2] / 1000) -eq [Math]::Floor($gn[2] / 1000) -and [Math]::Floor($gn[2] / 1000) -ne [Math]::Floor($cn[2] / 1000)
                if (-not $byProduct.Contains($product)) { $byProduct[$product] = New-Object System.Collections.Generic.List[object] }
                $byProduct[$product].Add([PSCustomObject]@{ Version = $v; Release = $r; Name = $name; Row = $row; End = $end
                        Ended = $(if ($end) { $end -le $script:RefDate } else { $r.IsEol }); OnGdr = $onGdr; Target = $(if ($onGdr) { $gdr } else { $cu }) })
            }
            foreach ($product in @($byProduct.Keys)) {
                $all = $byProduct[$product].ToArray()
                $count = { param($list, $first) if ($all.Count -eq 1) { "1 instance at build $($first.Version) ($($first.Name))" } else { "$(@($list).Count) of $($all.Count) instances, the oldest at build $($first.Version) ($($first.Name))" } }
                $ended = @($all | Where-Object { $_.Ended } | Sort-Object @{ Expression = { $_.Release.EolFrom } }, @{ Expression = { $_.Version } })
                if ($ended.Count -gt 0) {
                    $x = $ended[0]; $r = $x.Release
                    foreach ($e in $ended) { if ((Compare-SoftwareVersion $e.Version $x.Version) -lt 0) { $x = $e; $r = $e.Release } }
                    $endText = if ($x.End) { $x.End.ToString('yyyy-MM-dd') } else { 'on a date endoflife.date does not give' }
                    $days = if ($x.End) { [int][Math]::Floor(($script:RefDate - $x.End).TotalDays) } else { $null }
                    $sev = if ($x.Row) { $x.Row.Severity } else { 'Medium' }
                    $ext = ConvertTo-UtcDate $r.EoesFrom
                    $extText = ''
                    if ($ext -and $ext -gt $script:RefDate) { $sev = 'Low'; $extText = " Paid extended support (ESU) runs until $($ext.ToString('yyyy-MM-dd')): Low while the host is covered by it." }
                    elseif ($ext) { $extText = " Paid extended support ended $($ext.ToString('yyyy-MM-dd'))." }
                    & $emit 'software_eol' "software: $product" $sev ("SQL Server: {0}. Support for {1} ended {2}{3} (endoflife.date).{4}" -f (& $count $ended $x), $x.Name, $endText, $(if ($null -ne $days) { ", $days days before collection" } else { '' }), $extText) "$($x.Name), end of life $endText" 'a supported release or service pack'
                }
                $late = @($all | Where-Object { -not $_.Ended -and $_.Target -and ($rd = ConvertTo-UtcDate $_.Release.LatestDate) -and $rd -le $script:RefDate -and [Math]::Floor(($script:RefDate - $rd).TotalDays) -gt $grace -and (Compare-SoftwareVersion $_.Version $_.Target) -lt 0 })
                if ($late.Count -gt 0) {
                    $x = $late[0]; foreach ($e in $late) { if ((Compare-SoftwareVersion $e.Version $x.Version) -lt 0) { $x = $e } }
                    $r = $x.Release; $rd = ConvertTo-UtcDate $r.LatestDate
                    $lag = [int][Math]::Floor(($script:RefDate - $rd).TotalDays)
                    $how = if ($x.OnGdr) { "the latest security-only (GDR) build is $($x.Target); the latest cumulative update, $($r.Latest), came out $($rd.ToString('yyyy-MM-dd'))" } else { "$($r.Latest) came out $($rd.ToString('yyyy-MM-dd'))" }
                    & $emit 'software_outdated' "software: $product" $(if ($lag -gt 180) { 'Medium' } else { 'Low' }) ("SQL Server: {0}. {1} is still supported, but {2}, {3} days before collection, with the fixes since {4} (endoflife.date)." -f (& $count $late $x), $x.Name, $how, $lag, $x.Version) $x.Version "$($x.Target) or later"
                }
            }
        }
        foreach ($sw in @($S.software | Where-Object { $_ })) {
            if ($seen.Count -ge 100) { break }
            if ($sqlDone -and "$($sw.name)" -match '^Microsoft SQL Server \d{4}( R2)?( \((32|64)-bit\))?$') { continue }
            if ($Config.Cve -and (& $can 'software_cve')) {
                # Known vulnerabilities of the installed version: CVEs published before collection whose
                # NVD ranges hold it. KEV only from the date CISA added the CVE, EPSS as downloaded.
                $ip = Find-InstalledProduct $sw
                $cves = if ($ip) { @($Config.Cve.Products[$ip.Label] | Where-Object { $_ }) } else { @() }
                $hits = @($cves | Where-Object { ($d = ConvertTo-UtcDate $_.published) -and $d -le $script:RefDate -and (Test-CveAffects $_.ranges $ip.Version) })
                if ($hits.Count -gt 0) {
                    $epssOf = { param($id) if ($Config.Cve.Epss -and $Config.Cve.Epss.ContainsKey($id)) { [double]$Config.Cve.Epss[$id] } else { $null } }
                    $kev = @($hits | Where-Object { $_.kev -and ($k = ConvertTo-UtcDate $_.kev) -and $k -le $script:RefDate })
                    $byScore = @($hits | Sort-Object @{ Expression = { if ($null -ne $_.score) { [double]$_.score } else { -1 } }; Descending = $true }, @{ Expression = { $_.id }; Descending = $false })
                    $byEpss = @($hits | Where-Object { $null -ne (& $epssOf $_.id) } | Sort-Object @{ Expression = { & $epssOf $_.id }; Descending = $true }, @{ Expression = { $_.id }; Descending = $false })
                    $maxScore = if ($null -ne $byScore[0].score) { [double]$byScore[0].score } else { 0 }
                    $maxEpss = if ($byEpss.Count -gt 0) { & $epssOf $byEpss[0].id } else { 0 }
                    $sev = if ($kev.Count -gt 0 -or $maxScore -ge 9 -or $maxEpss -ge 0.1) { 'High' } elseif ($maxScore -ge 7 -or $maxEpss -ge 0.01) { 'Medium' } else { 'Low' }
                    # The release that fixes them all, when every range has an upper bound.
                    $fix = ''
                    $ends = @($hits | ForEach-Object { $_.ranges } | Where-Object { $_ -and -not $_.version } | ForEach-Object { if ($_.ee) { $_.ee } elseif ($_.ei) { "after $($_.ei)" } else { '?' } })
                    if ($ends.Count -gt 0 -and $ends -notcontains '?' -and -not ($ends | Where-Object { $_ -like 'after *' })) { $fix = $ends[0]; foreach ($e in $ends) { if ((Compare-SoftwareVersion $e $fix) -gt 0) { $fix = $e } } }
                    $parts = New-Object System.Collections.Generic.List[string]
                    $parts.Add("highest CVSS $(if ($maxScore -gt 0) { $maxScore.ToString('0.0', [Globalization.CultureInfo]::InvariantCulture) } else { 'not scored' }) ($($byScore[0].id))")
                    if ($kev.Count -gt 0) { $parts.Add("$($kev.Count) in the CISA KEV catalog of exploited vulnerabilities ($((@($kev | Select-Object -First 3 | ForEach-Object { $_.id })) -join ', '))") }
                    if ($byEpss.Count -gt 0) { $parts.Add("highest EPSS $($maxEpss.ToString('0.000', [Globalization.CultureInfo]::InvariantCulture)) ($($byEpss[0].id)$(if ($Config.Cve.EpssDate) { ", scores of $($Config.Cve.EpssDate)" }))") }
                    $worst = @($byScore | Select-Object -First 5 | ForEach-Object { $_.id }) -join ', '
                    $vver = if ("$($sw.version)") { "version $($sw.version)" } else { 'no version recorded' }
                    & $emit 'software_cve' "software: $($ip.Label)" $sev ("Installed as {0} ({1}). {2} known vulnerabilit{3} published before collection affect{8} {4} {5} (NVD): {6}. Worst: {7}." -f $sw.name, $vver, $hits.Count, $(if ($hits.Count -eq 1) { 'y' } else { 'ies' }), $ip.Label, $ip.Version, ($parts -join '; '), $worst, $(if ($hits.Count -eq 1) { 's' } else { '' })) "$($ip.Version): $($hits.Count) CVE" $(if ($fix) { "$fix or later" } else { 'a release that fixes them' })
                }
            }
            $row = Get-SoftwareLifecycle $sw
            $hit = if ($Config.Eol) { Find-EolRelease $sw $Config.Eol } else { $null }
            $ver = if ("$($sw.version)") { "version $($sw.version)" } else { 'no version recorded' }
            if ($hit) {
                # The downloaded lifecycle data wins over the table; the table still names the product
                # (so a finding keeps its Object whether or not the data was given) and its severity.
                $r = $hit.Release
                $product = if ($row) { $row.Product } else { "$($hit.Map.Label) $($r.Name)" }
                $end = ConvertTo-UtcDate $r.EolFrom
                $ended = if ($end) { $end -le $script:RefDate } else { $r.IsEol }
                $endText = if ($end) { $end.ToString('yyyy-MM-dd') } else { 'on a date endoflife.date does not give' }
                $days = if ($end) { [int][Math]::Floor(($script:RefDate - $end).TotalDays) } else { $null }
                if ($ended -and $hit.Map.Rapid) {
                    if ($null -ne $days -and $days -le $grace) { continue }
                    $sev = if ($null -eq $days -or $days -gt 180) { 'Medium' } else { 'Low' }
                    & $emit 'software_outdated' "software: $($hit.Map.Label)" $sev ("Installed as {0} ({1}). Release line {2} stopped receiving fixes {3}{4}: {5} ships a new release every few weeks and fixes only the newest (endoflife.date)." -f $sw.name, $ver, $hit.Cycle, $endText, $(if ($null -ne $days) { ", $days days before collection" } else { '' }), $hit.Map.Label) "$($hit.Map.Label) $($hit.Cycle)" 'the current release'
                }
                elseif ($ended) {
                    $sev = if ($row) { $row.Severity } elseif ($hit.Map.Severity) { $hit.Map.Severity } else { 'Medium' }
                    $ext = ConvertTo-UtcDate $r.EoesFrom
                    $extText = ''
                    if ($ext -and $ext -gt $script:RefDate) { $sev = 'Low'; $extText = " Paid extended support runs until $($ext.ToString('yyyy-MM-dd')): Low while the host is covered by it." }
                    elseif ($ext) { $extText = " Paid extended support ended $($ext.ToString('yyyy-MM-dd'))." }
                    & $emit 'software_eol' "software: $product" $sev ("Installed as {0} ({1}). Support for {2} ended {3}{4} (endoflife.date).{5}" -f $sw.name, $ver, $product, $endText, $(if ($null -ne $days) { ", $days days before collection" } else { '' }), $extText) "$product, end of life $endText" 'a supported release'
                }
                elseif ($hit.Version -and $r.Latest) {
                    # Only a release out before collection, and long enough ago to have been installed.
                    $rd = ConvertTo-UtcDate $r.LatestDate
                    if (-not $rd -or $rd -gt $script:RefDate) { continue }
                    if ((Compare-SoftwareVersion $hit.Version $r.Latest) -ge 0) { continue }
                    $lag = [int][Math]::Floor(($script:RefDate - $rd).TotalDays)
                    if ($lag -gt $grace) {
                        & $emit 'software_outdated' "software: $($hit.Map.Label)" $(if ($lag -gt 180) { 'Medium' } else { 'Low' }) ("Installed as {0} ({1}). {2} {3} is still supported, but {4} came out {5}, {6} days before collection, with the fixes since {7} (endoflife.date)." -f $sw.name, $ver, $hit.Map.Label, $hit.Cycle, $r.Latest, $rd.ToString('yyyy-MM-dd'), $lag, $hit.Version) $hit.Version "$($r.Latest) or later"
                    }
                    elseif ((Get-SoftwareVersionGap $hit.Version $r.Latest) -ge 2) {
                        # The newest release is recent, but the host is several releases behind it: the
                        # ones in between are older (the data gives only the newest one's date).
                        & $emit 'software_outdated' "software: $($hit.Map.Label)" 'Low' ("Installed as {0} ({1}). {2} {3} is still supported, but the installed version is several releases behind {4} (out {5}); the releases in between came out earlier, on dates endoflife.date does not give." -f $sw.name, $ver, $hit.Map.Label, $hit.Cycle, $r.Latest, $rd.ToString('yyyy-MM-dd')) $hit.Version "$($r.Latest) or later"
                    }
                }
                continue
            }
            $choco = if ($Config.Choco) { Find-ChocoProduct $sw } else { $null }
            if ($choco -and $Config.Choco.ContainsKey($choco.Map.Id)) {
                # Only versions published before collection; late once the first of them is older than
                # the grace period.
                $newer = @($Config.Choco[$choco.Map.Id] | Where-Object { $_ -and ($d = ConvertTo-UtcDate $_.Published) -and $d -le $script:RefDate -and (Compare-SoftwareVersion $_.Version $choco.Version) -gt 0 } | Sort-Object Published)
                if ($newer.Count -gt 0) {
                    $first = $newer[0]
                    $top = $newer[0]; foreach ($n in $newer) { if ((Compare-SoftwareVersion $n.Version $top.Version) -gt 0) { $top = $n } }
                    $lag = Get-AgeDays $first.Published
                    if ($lag -gt $grace) {
                        & $emit 'software_outdated' "software: $($choco.Map.Label)" $(if ($lag -gt 180) { 'Medium' } else { 'Low' }) ("Installed as {0} ({1}). {2} newer release{3} came out before collection: the first, {4}, on {5} ({6} days before collection), the newest {7} on {8} (Chocolatey community repository)." -f $sw.name, $ver, $newer.Count, $(if ($newer.Count -eq 1) { '' } else { 's' }), $first.Version, $first.Published, $lag, $top.Version, $top.Published) $choco.Version "$($top.Version) or later"
                    }
                }
            }
            if (-not $row) { continue }
            $left = Get-AgeDays $row.End
            if ($null -eq $left -or $left -le 0) { continue }
            $sev = $row.Severity; $extText = ''
            if ($row.Extended) {
                $extLeft = Get-AgeDays $row.Extended
                if ($extLeft -le 0) { $sev = 'Low'; $extText = " Paid extended support runs until $($row.Extended): Low while the host is covered by it." }
                else { $extText = " Paid extended support ended $($row.Extended)." }
            }
            & $emit 'software_eol' "software: $($row.Product)" $sev ("Installed as {0} ({1}). Support for {2} ended {3}, {4} days before collection.{5}" -f $sw.name, $ver, $row.Product, $row.End, $left, $extText) "$($row.Product), end of life $($row.End)" 'a supported release'
        }
    }
    if (& $can 'updates_pending') {
        $up = $S.updatesPending
        $seen = @{}
        foreach ($u in @($up.pending | Where-Object { $_ })) {
            if ("$($u.categories)" -match '(?i)definition') { continue }
            $sev = switch -Regex ("$($u.severity)") { '^Critical$' { 'High' } '^Important$' { 'Medium' } default { 'Low' } }
            $label = if ("$($u.kb)") { "$($u.kb)" } else { "$($u.title)".Substring(0, [Math]::Min(60, "$($u.title)".Length)) }
            $obj = "update: $label"
            if ($seen.ContainsKey($obj)) { continue }
            $seen[$obj] = $true
            Add-Finding -Type 'updates_pending' -Object $obj -Severity $sev -Detail ("{0}. Reported by {1}{2}{3}." -f "$($u.title)".TrimEnd('.'), $(if ($up.source) { $up.source } else { 'the Windows Update Agent' }), $(if ($u.severity) { ", Microsoft severity $($u.severity)" } else { '' }), $(if ($u.rebootRequired) { '; needs a restart' } else { '' }))
        }
    }
    if (& $can 'kev_software_match') {
        $index = Get-KevIndex $Config.Kev
        $matched = @{}
        $limit = 100
        foreach ($sw in @($S.software | Where-Object { $_ })) {
            if ($matched.Count -ge $limit) { break }
            $hayName = ConvertTo-WordText $sw.name
            $hayAll = ConvertTo-WordText "$($sw.publisher) $($sw.name)"
            foreach ($g in $index) {
                if (-not $hayName.Contains(" $($g.ProductTokens[0]) ")) { continue }
                $ok = $true
                foreach ($tk in $g.ProductTokens) { if (-not $hayName.Contains(" $tk ")) { $ok = $false; break } }
                if (-not $ok) { continue }
                foreach ($tk in $g.VendorTokens) { if (-not $hayAll.Contains(" $tk ")) { $ok = $false; break } }
                if (-not $ok) { continue }
                $key = "$($g.Vendor)|$($g.Product)".ToLower()
                if ($matched.ContainsKey($key)) { continue }
                $matched[$key] = $true
                $entries = @($g.Entries | Sort-Object DateAdded -Descending)
                $ransom = @($entries | Where-Object { $_.Ransomware }).Count
                $cves = (@($entries | Select-Object -First 3 | ForEach-Object { $_.Cve }) -join ', ')
                $ver = if ("$($sw.version)") { "version $($sw.version)" } else { 'no version recorded' }
                $detail = ("Installed as {0} ({1}). CISA KEV lists {2} exploited vulnerabilit{3} for {4} {5}, newest {6} (added {7}){8}. The catalog has no version ranges: compare {9} with the vendor advisories." -f $sw.name, $ver, $entries.Count, $(if ($entries.Count -eq 1) { 'y' } else { 'ies' }), $g.Vendor, $g.Product, $entries[0].Cve, $entries[0].DateAdded, $(if ($ransom -gt 0) { "; $ransom used in ransomware campaigns" } else { '' }), $ver) + " Others: $cves."
                Add-Finding -Type 'kev_software_match' -Object "software: $($g.Vendor) $($g.Product)" -Severity $(if ($ransom -gt 0) { 'Medium' } else { 'Low' }) -Detail $detail
            }
        }
    }
}

# ------------------------------------------------------------------ DISA STIG registry rules
# data\stig-catalog.json comes from tools\Convert-PowerStigData.ps1 (PowerSTIG data, MIT; STIG content
# by DISA). Entry: id, p (product), s (H/M/L), h (M machine, U per user), k (key under the hive), n
# (value name), t (D/S/M/N), e (P present, A absent), x (expected: eq, in, range, absent), d (why).
$script:StigCatalog = $null
$script:StigProductType = @{ win10 = 'stig_windows10'; win11 = 'stig_windows11'; defender = 'stig_defender'; firewall = 'stig_firewall'; edge = 'stig_edge'; chrome = 'stig_chrome'; firefox = 'stig_firefox'; office = 'stig_office'; adobereader = 'stig_adobe'; adobepro = 'stig_adobe'
    srv2016dc = 'stig_server2016'; srv2016ms = 'stig_server2016'; srv2019dc = 'stig_server2019'; srv2019ms = 'stig_server2019'; srv2022dc = 'stig_server2022'; srv2022ms = 'stig_server2022'; srv2025dc = 'stig_server2025'; srv2025ms = 'stig_server2025' }
$script:StigIdPrefix = @{ win10 = 'WN10'; win11 = 'WN11'; defender = 'MSDA'; firewall = 'WFW'; edge = 'EDGE'; chrome = 'CHRM'; firefox = 'FFOX'; office = 'O365'; adobereader = 'ARDC'; adobepro = 'AADC'
    srv2016dc = 'WN16-DC'; srv2016ms = 'WN16-MS'; srv2019dc = 'WN19-DC'; srv2019ms = 'WN19-MS'; srv2022dc = 'WN22-DC'; srv2022ms = 'WN22-MS'; srv2025dc = 'WN25-DC'; srv2025ms = 'WN25-MS' }

function Get-StigCatalog {
    if ($null -eq $script:StigCatalog) {
        $path = Join-Path $PSScriptRoot '..\data\stig-catalog.json'
        # Windows PowerShell 5.1 hands a JSON array back as one object: the second pipe takes it apart.
        $script:StigCatalog = if (Test-Path -LiteralPath $path) { @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) | ForEach-Object { $_ }) } else { @() }
    }
    return $script:StigCatalog
}

# data\cis-map.json comes from tools\Convert-CisMapping.ps1 (ansible-lockdown roles, MIT): for each
# rule of the CIS Windows 11 benchmark, the same setting in the Windows Server 2022 and 2019
# benchmarks. The checks and their expected values stay the Windows 11 ones (the thresholds are the
# same); on a server, a finding quotes the server rule instead.
$script:CisMap = $null
$script:CisBench = 'win11'
$script:CurrentRole = 'unknown'

function Get-CisMap {
    if ($null -eq $script:CisMap) {
        $path = Join-Path $PSScriptRoot '..\data\cis-map.json'
        $script:CisMap = if (Test-Path -LiteralPath $path) { ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) } else { [pscustomobject]@{ benchmarks = [pscustomobject]@{ win11 = 'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0' }; rules = [pscustomobject]@{} } }
    }
    return $script:CisMap
}

function Get-CisBenchmark {
    # srv2022, srv2019, srv2016, win10, or win11 (every other Windows: the rule numbers the checks
    # are written with).
    param($Snapshot)
    $os = if ($Snapshot.host) { $Snapshot.host.os }
    if (-not $os) { return 'win11' }
    $caption = "$($os.caption)"
    $build = "$($os.build)"
    $server = "$($os.productType)" -in @('2', '3') -or $caption -match 'Server'
    if ($caption -match 'Server 2022' -or ($server -and $build -eq '20348')) { return 'srv2022' }
    if ($caption -match 'Server 2019' -or ($server -and $build -eq '17763')) { return 'srv2019' }
    if ($caption -match 'Server 2016' -or ($server -and $build -eq '14393')) { return 'srv2016' }
    if (-not $server -and ($caption -match 'Windows 10' -or ($build -match '^\d+$' -and [int]$build -lt 22000 -and [int]$build -ge 10240))) { return 'win10' }
    return 'win11'
}

function Get-CisShortName {
    # "Server 2022", "Windows 10": the name a finding quotes before the rule number.
    param([string]$Bench)
    $m = Get-CisMap
    if ($m.short -and $m.short.$Bench) { return "$($m.short.$Bench)" }
    return ("$($m.benchmarks.$Bench)" -replace '^CIS Microsoft Windows | Benchmark.*$', '')
}

# Rules that only the server benchmarks have, quoted with -ServerCis, and the benchmarks that lack
# one (Server 2016 v3.0.0 still covers legacy LAPS, not Windows LAPS): there the Server 2022 rule is
# quoted.
$script:ServerCisMissing = @{ srv2016 = @('18.9.25.2') }

function Resolve-ExtraCis {
    # The benchmark, rule and level to quote for an Add-Finding -ServerCis key on this host:
    # @{ Bench; Rule; Level }. Keys found in the extra part of data\cis-map.json follow it; the others
    # (a Windows 11 rule that also has a server-only meaning, like 18.9.25.2) keep their number.
    param([string]$Key)
    $entry = $null
    $m = Get-CisMap
    if ($m.extra -and ($m.extra.PSObject.Properties.Name -contains $Key)) { $entry = $m.extra.$Key }
    if ($entry) {
        $anchor = if ($Key -match '^(\w+):') { $Matches[1] } else { 'srv2022' }
        $b = if ($entry.PSObject.Properties.Name -contains $script:CisBench) { $script:CisBench } else { $anchor }
        $hits = @($entry.$b | Where-Object { $_ })
        $want = if ($script:CurrentRole -eq 'dc') { 'DC' } else { 'MS' }
        $hit = @(@($hits | Where-Object { $_.a -eq $want }) + @($hits | Where-Object { $_.a -eq 'both' }) + $hits)[0]
        return @{ Bench = $b; Rule = "$($hit.r)"; Level = "$($hit.l)" }
    }
    $b = $script:CisBench
    if ($b -notlike 'srv*' -or @($script:ServerCisMissing[$b]) -contains $Key) { $b = 'srv2022' }
    return @{ Bench = $b; Rule = ($Key -replace '^\w+:', ''); Level = 'L1' }
}

function ConvertTo-HostCisRule {
    # The rule number to quote on this host for a Windows 11 rule: @{ Rule; Level; Mapped }.
    param([string]$Rule)
    if ($script:CisBench -eq 'win11') { return @{ Rule = $Rule; Level = ''; Mapped = $true } }
    $entry = (Get-CisMap).rules.$Rule
    $hits = if ($entry) { @($entry.($script:CisBench) | Where-Object { $_ }) } else { @() }
    $want = if ($script:CurrentRole -eq 'dc') { 'DC' } else { 'MS' }
    $hit = @($hits | Where-Object { $_.a -eq $want }) + @($hits | Where-Object { $_.a -eq 'both' }) | Select-Object -First 1
    if ($hit) { return @{ Rule = "$($hit.r)"; Level = "$($hit.l)"; Mapped = $true } }
    return @{ Rule = "Windows 11 $Rule"; Level = ''; Mapped = $false }
}

function Test-StigValue {
    # $null when the value is what the rule asks for, else a short text saying how it differs.
    param($Entry, [bool]$Present, $Value)
    $x = $Entry.x
    if ($x.op -eq 'absent') { if ($Present) { return "set to $Value, the STIG wants it not set" } return $null }
    if (-not $Present) {
        if ($x.op -in 'in', 'range' -and $x.absentOk) { return $null }
        return 'not configured'
    }
    switch ($x.op) {
        'eq' {
            if ($Entry.t -eq 'D') {
                $a = ConvertTo-Int64OrNull $Value; $b = ConvertTo-Int64OrNull $x.v
                if ($null -ne $a -and $null -ne $b) { if ($a -eq $b) { return $null } else { return "set to $Value, expected $($x.v)" } }
            }
            if ("$Value".Trim() -ieq "$($x.v)".Trim()) { return $null }
            return "set to $Value, expected $($x.v)"
        }
        'in' {
            $a = ConvertTo-Int64OrNull $Value
            if ($null -ne $a -and @($x.v | Where-Object { (ConvertTo-Int64OrNull $_) -eq $a }).Count -gt 0) { return $null }
            return "set to $Value, expected $(@($x.v) -join ' or ')"
        }
        'range' {
            $a = ConvertTo-Int64OrNull $Value
            $min = ConvertTo-Int64OrNull $x.min; $max = ConvertTo-Int64OrNull $x.max
            if ($null -ne $a -and ($null -eq $min -or $a -ge $min) -and ($null -eq $max -or $a -le $max)) { return $null }
            $want = if ($null -ne $min -and $null -ne $max) { "$min to $max" } elseif ($null -ne $min) { "$min or more" } else { "$max or less" }
            return "set to $Value, expected $want"
        }
    }
    return $null
}

function Get-StigExpectedText {
    # What a STIG rule asks for, in words: "1", "1 or 2", "32768 or more", "not set".
    param($Entry)
    $x = $Entry.x
    $t = switch ($x.op) {
        'absent' { 'not set' }
        'eq' { "$($x.v)" }
        'in' { @($x.v) -join ' or ' }
        'range' {
            $min = ConvertTo-Int64OrNull $x.min; $max = ConvertTo-Int64OrNull $x.max
            if ($null -ne $min -and $null -ne $max) { "$min to $max" } elseif ($null -ne $min) { "$min or more" } else { "$max or less" }
        }
        default { '' }
    }
    if ($t -and $x.absentOk) { $t += ' (or not set)' }
    return $t
}

function Invoke-StigChecks {
    param($S, $Config, $can)
    $st = $S.stig
    if (-not $st) { return }
    $machine = @{}
    foreach ($m in @($st.machine | Where-Object { $_ })) { $machine[("$($m.k)|$($m.n)").ToLower()] = $m.v }
    $users = @($st.users | Where-Object { $_ })
    $userMaps = @()
    foreach ($u in $users) {
        $map = @{}
        foreach ($m in @($u.values | Where-Object { $_ })) { $map[("$($m.k)|$($m.n)").ToLower()] = $m.v }
        $userMaps += , $map
    }
    $caption = if ($S.host -and $S.host.os) { "$($S.host.os.caption)" } else { '' }
    # Windows Server: the domain controller or the member server STIG of that version, by role.
    $srvBench = Get-CisBenchmark $S
    $dc = (Get-SnapshotRole $S) -eq 'dc'
    $ms = (Get-SnapshotRole $S) -eq 'server'
    # Server 2025 (build 26100) has no CIS benchmark of its own, so Get-CisBenchmark does not name it;
    # the STIG layer detects it directly for the Server 2025 STIG.
    $isServerOs = ("$($S.host.os.productType)" -in @('2', '3')) -or ($caption -match 'Server')
    $srv2025 = ($caption -match 'Server 2025') -or ($isServerOs -and "$($S.host.os.build)" -eq '26100')
    $installed = @{
        win10 = ($caption -match 'Windows 10'); win11 = ($caption -match 'Windows 11'); defender = $true; firewall = $true
        edge = ($st.products.edge -eq $true); chrome = ($st.products.chrome -eq $true); firefox = ($st.products.firefox -eq $true); office = ($st.products.office -eq $true)
        adobereader = ($st.products.adobereader -eq $true); adobepro = ($st.products.adobepro -eq $true)
        srv2016dc = ($srvBench -eq 'srv2016' -and $dc); srv2016ms = ($srvBench -eq 'srv2016' -and $ms)
        srv2019dc = ($srvBench -eq 'srv2019' -and $dc); srv2019ms = ($srvBench -eq 'srv2019' -and $ms)
        srv2022dc = ($srvBench -eq 'srv2022' -and $dc); srv2022ms = ($srvBench -eq 'srv2022' -and $ms)
        srv2025dc = ($srv2025 -and $dc); srv2025ms = ($srv2025 -and $ms)
    }
    $sev = @{ H = 'High'; M = 'Medium'; L = 'Low' }
    foreach ($e in (Get-StigCatalog)) {
        $type = $script:StigProductType["$($e.p)"]
        if (-not $type -or -not $installed["$($e.p)"] -or -not (& $can $type)) { continue }
        Step-Spinner "Analyzing $($script:CurrentHost): DISA STIG rules"
        $id = ("$($e.k)|$($e.n)").ToLower()
        $obj = "$($script:StigIdPrefix["$($e.p)"]) $($e.id): $($e.n)"
        $loc = "$(if ($e.h -eq 'U') { 'HKCU' } else { 'HKLM' })\$($e.k)\$($e.n)"
        if ($e.h -eq 'M') {
            $script:StigEvaluated++; $script:StigEvaluatedBy[$type] = 1 + [int]$script:StigEvaluatedBy[$type]
            $has = $machine.ContainsKey($id)
            $why = Test-StigValue -Entry $e -Present $has -Value $machine[$id]
            if ($why) { Add-Finding -Type $type -Object $obj -Severity $sev["$($e.s)"] -Found $(if ($has) { "$($machine[$id])" } else { 'not configured' }) -Expected (Get-StigExpectedText $e) -Detail "$loc $why. $($e.d)" }
        }
        elseif ($userMaps.Count -gt 0) {
            $script:StigEvaluated++; $script:StigEvaluatedBy[$type] = 1 + [int]$script:StigEvaluatedBy[$type]
            $bad = 0; $first = ''; $firstFound = ''
            foreach ($map in $userMaps) {
                $has = $map.ContainsKey($id)
                $why = Test-StigValue -Entry $e -Present $has -Value $map[$id]
                if ($why) { $bad++; if (-not $first) { $first = $why; $firstFound = $(if ($has) { "$($map[$id])" } else { 'not configured' }) } }
            }
            if ($bad -gt 0) { Add-Finding -Type $type -Object $obj -Severity $sev["$($e.s)"] -Found $firstFound -Expected (Get-StigExpectedText $e) -Detail "$loc $first (user policy; $bad of $($userMaps.Count) loaded user profile(s)). $($e.d)" }
        }
    }
    # Brave: the Chrome STIG machine rules read under Brave's own policy key, and three policies of
    # Brave itself. An adaptation, not a DISA STIG: not counted in the STIG compliance figures.
    if ($st.products.brave -eq $true -and (& $can 'brave_policy_gaps')) {
        $cp = 'Software\Policies\Google\Chrome'; $bp = 'Software\Policies\BraveSoftware\Brave'
        foreach ($e in @(Get-StigCatalog | Where-Object { $_.p -eq 'chrome' -and $_.h -eq 'M' -and "$($_.k)".StartsWith($cp, [StringComparison]::OrdinalIgnoreCase) })) {
            $bk = $bp + "$($e.k)".Substring($cp.Length)
            $id = ("$bk|$($e.n)").ToLower()
            $has = $machine.ContainsKey($id)
            $why = Test-StigValue -Entry $e -Present $has -Value $machine[$id]
            if ($why) { Add-Finding -Type 'brave_policy_gaps' -Object "Brave (DTBC $($e.id)): $($e.n)" -Severity $sev["$($e.s)"] -Found $(if ($has) { "$($machine[$id])" } else { 'not configured' }) -Expected (Get-StigExpectedText $e) -Detail "HKLM\$bk\$($e.n) $why (Chrome STIG rule $($e.id), applied to Brave). $($e.d)" }
        }
        foreach ($own in @(@('TorDisabled', 'Medium', 'Tor windows reach the internet past the proxy and network monitoring'), @('BraveWalletDisabled', 'Low', 'the built-in crypto wallet stays available'), @('BraveRewardsDisabled', 'Low', 'Brave Rewards (ads and payments) stays available'))) {
            $id = ("$bp|$($own[0])").ToLower()
            if ("$($machine[$id])" -ne '1') { Add-Finding -Type 'brave_policy_gaps' -Object "Brave: $($own[0])" -Severity $own[1] -Found $(if ($machine.ContainsKey($id)) { "$($machine[$id])" } else { 'not configured' }) -Expected '1' -Detail "HKLM\$bp\$($own[0]) is $(if ($machine.ContainsKey($id)) { $machine[$id] } else { 'not configured' }): $($own[2])." }
        }
    }
}

function Invoke-DriverChecks {
    param($S, $Config, $can)
    $dr = $S.drivers
    if (-not $dr) { return }
    if (& $can 'vulnerable_driver_present') {
        $index = @{}
        foreach ($e in @(Get-DriverCatalog $Config)) { if ($e -and $e.h) { $index["$($e.h)".ToLower()] = $e } }
        $lower = @{ Critical = 'High'; High = 'Medium'; Medium = 'Low' }
        foreach ($d in @($dr.list | Where-Object { $_ -and $_.sha256 })) {
            $e = $index["$($d.sha256)".ToLower()]
            if (-not $e) { continue }
            $running = "$($d.state)" -eq 'Running'
            $sev = if ($e.c -eq 'M') { 'Critical' } elseif ($running) { 'High' } else { 'Medium' }
            if (-not $e.v) { $sev = $lower[$sev] }
            $what = if ($e.c -eq 'M') { 'a known malicious driver' } else { 'a known vulnerable driver' }
            $extra = @()
            if ($e.x) { $extra += "$($e.x)" }
            if ($e.g) { $extra += 'loads even with HVCI on' }
            if (-not $e.v) { $extra += 'sample not verified by LOLDrivers' }
            $detail = "$($d.path) is $what ($($e.n), LOLDrivers $($e.i)$(if ($extra.Count) { '; ' + ($extra -join '; ') })); state $($d.state), start $($d.startMode)."
            Add-Finding -Type 'vulnerable_driver_present' -Object "driver: $($d.name)" -Severity $sev -Detail $detail
        }
    }
    if ((& $can 'driver_blocklist_off') -and "$($dr.blocklistEnable)" -eq '0') {
        Add-Finding -Type 'driver_blocklist_off' -Object 'Vulnerable driver blocklist' -Found '0' -Expected '1' -Detail 'VulnerableDriverBlocklistEnable = 0: Windows loads drivers that Microsoft blocks as vulnerable.'
    }
}

function Invoke-HostChecks {
    # Returns @{ Findings; NotEvaluated } for one snapshot.
    param($Snapshot, [hashtable]$Config)
    $script:Findings = New-Object System.Collections.Generic.List[object]
    $script:StigEvaluated = 0; $script:StigEvaluatedBy = @{}
    $script:CurrentHost = Get-SnapshotHostName $Snapshot
    $script:RefDate = ConvertTo-UtcDate $Snapshot.meta.collectedAtUtc
    if (-not $script:RefDate) { throw "$($Snapshot._path): meta.collectedAtUtc missing" }
    $role = Get-SnapshotRole $Snapshot
    $script:CurrentRole = $role
    $script:CisBench = Get-CisBenchmark $Snapshot
    $extra = @{}

    # Defender in passive mode (another antivirus is primary): its switches are off by design, so
    # its checks say nothing about this host.
    $d = $Snapshot.defender
    if ($d -and $d.amRunningMode -and "$($d.amRunningMode)" -notmatch '(?i)^normal$') {
        foreach ($t in @('defender_realtime_off', 'defender_tamper_off', 'defender_signatures_stale', 'defender_exclusion', 'asr_standard_rules_missing', 'defender_network_protection_off', 'defender_pua_off', 'stig_defender', 'asr_other_rules_not_blocking', 'defender_protection_features_off', 'defender_server_baseline_gaps')) {
            $extra[$t] = "Microsoft Defender Antivirus runs in '$($d.amRunningMode)': another antivirus is primary, check that product"
        }
    }
    if ($Snapshot.credentialProtection -and $null -eq $Snapshot.credentialProtection.credentialGuardRunning) {
        $extra['credential_guard_off'] = 'Device Guard status (Win32_DeviceGuard) not readable'
        $extra['hvci_off'] = 'Device Guard status (Win32_DeviceGuard) not readable'
    }

    $ne = @(Get-NotEvaluatedChecks -Snapshot $Snapshot -Extra $extra)
    # Opt-in checks are not "not evaluated" when nobody asked for them: pending updates exist only in a
    # snapshot taken with -CheckUpdates, KEV matching only when a catalog was given, the
    # software release check only with endoflife.date data.
    $optionalOff = @{}
    if (-not $Snapshot.meta.options.checkUpdates) { $optionalOff['updates_pending'] = $true }
    if (-not $Config.Kev -or @($Config.Kev).Count -eq 0) { $optionalOff['kev_software_match'] = $true }
    if ((-not $Config.Eol -or $Config.Eol.Count -eq 0) -and (-not $Config.Choco -or $Config.Choco.Count -eq 0)) { $optionalOff['software_outdated'] = $true }
    if (-not $Config.Cve -or -not $Config.Cve.Products -or $Config.Cve.Products.Count -eq 0) { $optionalOff['software_cve'] = $true }
    $ne = @($ne | Where-Object { -not $optionalOff.ContainsKey($_.Type) })
    $skip = @{}; foreach ($n in $ne) { $skip[$n.Type] = $true }
    foreach ($k in $optionalOff.Keys) { $skip[$k] = $true }
    $can = { param($t) (-not $skip.ContainsKey($t)) -and ($role -eq 'unknown' -or $script:CheckCatalog[$t].Roles -contains $role) }

    $groups = [ordered]@{
        'credential' = { Invoke-CredentialChecks $Snapshot $Config $can }
        'antivirus'  = { Invoke-AntivirusChecks $Snapshot $Config $can }
        'disk'       = { Invoke-DiskChecks $Snapshot $Config $can $role }
        'network'    = { Invoke-NetworkChecks $Snapshot $Config $can $role }
        'accounts'   = { Invoke-AccountChecks $Snapshot $Config $can }
        'privesc'    = { Invoke-PrivescChecks $Snapshot $Config $can }
        'drivers'    = { Invoke-DriverChecks $Snapshot $Config $can }
        'logging'    = { Invoke-LoggingChecks $Snapshot $Config $can $role }
        'baseline'   = { Invoke-BaselineChecks $Snapshot $Config $can $role }
        'stig'       = { Invoke-StigChecks $Snapshot $Config $can }
        'software'   = { Invoke-SoftwareChecks $Snapshot $Config $can }
        'policy'     = { Invoke-PolicyChecks $Snapshot $Config $can $role }
        'edr'        = { Invoke-EdrChecks $Snapshot $Config $can $role }
        'patching'   = { Invoke-PatchChecks $Snapshot $Config $can }
    }
    foreach ($g in $groups.Keys) {
        # One broken group becomes a warning, not a lost report.
        Step-Spinner "Analyzing $($script:CurrentHost): $g checks"
        try { & $groups[$g] }
        catch { Stop-Spinner; Write-Warning "${script:CurrentHost}: $g checks failed: $($_.Exception.Message)" }
    }
    return [PSCustomObject]@{ Findings = $script:Findings.ToArray(); NotEvaluated = $ne; StigEvaluated = $script:StigEvaluated; StigByType = $script:StigEvaluatedBy; Off = @($optionalOff.Keys) }
}

function Invoke-CredentialChecks {
    param($S, $Config, $can)
    $c = $S.credentialProtection
    if (& $can 'lsa_not_protected') {
        if (@(1, 2) -notcontains [int]$c.runAsPPL -or $null -eq $c.runAsPPL) {
            Add-Finding -Type 'lsa_not_protected' -Object 'LSA' -Detail "RunAsPPL = $(if ($null -eq $c.runAsPPL) { 'not set' } else { $c.runAsPPL }) (CIS 18.9.26.2 expects 1, with UEFI lock; 2 without the lock is accepted here)."
        }
    }
    if ((& $can 'credential_guard_off') -and $c.credentialGuardRunning -eq $false) {
        Add-Finding -Type 'credential_guard_off' -Object 'Credential Guard' -Detail "Not running (VBS status $($c.vbsStatus): 0 off, 1 configured, 2 running)."
    }
    if ((& $can 'hvci_off') -and $c.hvciRunning -eq $false) {
        Add-Finding -Type 'hvci_off' -Object 'Memory integrity' -Detail "HVCI is not running (VBS status $($c.vbsStatus))."
    }
    if ((& $can 'wdigest_cleartext') -and "$($c.wdigestUseLogonCredential)" -eq '1') {
        Add-Finding -Type 'wdigest_cleartext' -Object 'WDigest' -Found '1' -Expected '0' -Detail 'UseLogonCredential = 1.'
    }
    if (& $can 'cached_logons_high') {
        $limit = if ((Get-SnapshotRole $S) -eq 'server') { $Config.MaxCachedLogonsServer } else { $Config.MaxCachedLogonsWorkstation }
        # Unset means the Windows default of 10.
        $n = if ("$($c.cachedLogonsCount)" -match '^\d+$') { [int]"$($c.cachedLogonsCount)" } else { 10 }
        if ($n -gt $limit) { Add-Finding -Type 'cached_logons_high' -Object 'CachedLogonsCount' -Found "$n" -Expected "$limit or fewer" -Detail "$n cached logons (limit $limit)." }
    }
    if ((& $can 'lm_hash_stored') -and "$($c.noLmHash)" -eq '0') {
        Add-Finding -Type 'lm_hash_stored' -Object 'NoLMHash' -Found '0' -Expected '1' -Detail 'NoLMHash = 0.'
    }
    if (& $can 'ntlm_weak_lmcompat') {
        $lvl = if ("$($c.lmCompatibilityLevel)" -match '^\d+$') { [int]"$($c.lmCompatibilityLevel)" } else { $null }
        $eff = if ($null -eq $lvl) { 3 } else { $lvl }
        if ($eff -lt 5) { Add-Finding -Type 'ntlm_weak_lmcompat' -Object 'LmCompatibilityLevel' -Found "$eff$(if ($null -eq $lvl) { ' (not set)' })" -Expected '5' -Detail "Level $eff$(if ($null -eq $lvl) { ' (not set, Windows default)' })." }
    }
    if ((& $can 'anonymous_sam_enum') -and "$($c.restrictAnonymousSam)" -eq '0') {
        Add-Finding -Type 'anonymous_sam_enum' -Object 'RestrictAnonymousSAM' -Found '0' -Expected '1' -Detail 'RestrictAnonymousSAM = 0.'
    }
}

function Invoke-AntivirusChecks {
    param($S, $Config, $can)
    $d = $S.defender
    if (-not $d) { return }
    if ((& $can 'defender_realtime_off') -and (-not $d.realTimeProtectionEnabled -or -not $d.antivirusEnabled)) {
        Add-Finding -Type 'defender_realtime_off' -Object 'Microsoft Defender' -Found 'off' -Expected 'on' -Detail "Antivirus enabled: $($d.antivirusEnabled); real-time protection: $($d.realTimeProtectionEnabled)."
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
    if (& $can 'asr_other_rules_not_blocking') {
        $set = @{}
        foreach ($r in @($d.asrRules | Where-Object { $_ })) { $set["$($r.id)".ToLower()] = $r.action }
        $rules = [ordered]@{}
        foreach ($k in $script:OtherAsrRules.Keys) { $rules[$k] = $script:OtherAsrRules[$k] }
        if (@($S.software | Where-Object { $_ -and "$($_.name)" -match '^Microsoft Exchange Server' }).Count -gt 0) { foreach ($k in $script:ExchangeAsrRules.Keys) { $rules[$k] = $script:ExchangeAsrRules[$k] } }
        $missing = @($rules.Keys | Where-Object { "$($set[$_])" -ne '1' })
        if ($missing.Count -gt 0) {
            $audit = @($missing | Where-Object { "$($set[$_])" -in '2', '6' }).Count
            $txt = ($missing | ForEach-Object { "$($rules[$_]) [$(if ($set.ContainsKey($_)) { "action $($set[$_])" } else { 'not set' })]" }) -join '; '
            Add-Finding -Type 'asr_other_rules_not_blocking' -Object 'ASR (other rules)' -Detail "$($missing.Count) of $($rules.Count) not blocking$(if ($audit) { " ($audit in audit or warn mode)" }): $txt."
        }
    }
    if (& $can 'defender_protection_features_off') {
        if ($d.behaviorMonitorEnabled -eq $false) { Add-Finding -Type 'defender_protection_features_off' -Object 'Behavior monitoring' -Found 'off' -Expected 'on' -Detail 'Behavior monitoring is off.' }
        if ($d.ioavProtectionEnabled -eq $false) { Add-Finding -Type 'defender_protection_features_off' -Object 'Downloaded files and attachments' -Found 'off' -Expected 'on' -Detail 'Scanning of downloaded files and attachments (IOAV) is off.' }
        if ($d.disableScriptScanning -eq $true) { Add-Finding -Type 'defender_protection_features_off' -Object 'Script scanning' -Found 'off' -Expected 'on' -Detail 'DisableScriptScanning is on.' }
        if ($null -ne $d.mapsReporting -and "$($d.mapsReporting)" -eq '0') { Add-Finding -Type 'defender_protection_features_off' -Object 'Cloud-delivered protection' -Severity 'Low' -Found '0' -Expected '1 or 2' -Detail 'MAPS reporting is disabled (0); STIG and CIS ask for Advanced (2).' }
        if ($d.disableBlockAtFirstSeen -eq $true) { Add-Finding -Type 'defender_protection_features_off' -Object 'Block at first sight' -Severity 'Low' -Found 'off' -Expected 'on' -Detail 'DisableBlockAtFirstSeen is on.' }
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
        if (& $can 'bitlocker_weak_encryption') {
            # EncryptionMethod of Get-BitLockerVolume: Hardware is the drive's own encryption, the 128-bit
            # and the CBC (Aes*) methods are weaker than XTS-AES 256. None / empty: not encrypted, judged above.
            foreach ($v in @($vols | Where-Object { "$($_.encryptionMethod)" -match '(?i)^(Hardware|Aes128|Aes128Diffuser|Aes256|Aes256Diffuser|XtsAes128)$' })) {
                $m = "$($v.encryptionMethod)"
                $why = if ($m -eq 'Hardware') { "the drive's own hardware encryption" } elseif ($m -match '128') { 'a 128-bit key' } else { 'CBC mode, not XTS' }
                Add-Finding -Type 'bitlocker_weak_encryption' -Object "volume $($v.mountPoint) encryption" -Severity $(if ($m -eq 'Hardware') { 'Medium' } else { 'Low' }) -Found $m -Expected 'XtsAes256' -Detail "$m on the $("$($v.volumeType)".ToLower()) volume $($v.mountPoint): $why."
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
        Add-Finding -Type 'smb1_server_enabled' -Object 'SMB server' -Found 'enabled' -Expected 'disabled' -Detail 'EnableSMB1Protocol = True.'
    }
    if ((& $can 'smb_server_signing_not_required') -and $n.smbServerSigningRequired -eq $false) {
        Add-Finding -Type 'smb_server_signing_not_required' -Object 'SMB server' -Severity $(if ($role -eq 'dc') { 'High' } else { 'Medium' }) -Found 'not required' -Expected 'required' -Detail 'RequireSecuritySignature = False.'
    }
    if ((& $can 'smb_client_signing_not_required') -and $n.smbClientSigningRequired -eq $false) {
        Add-Finding -Type 'smb_client_signing_not_required' -Object 'SMB client' -Found 'not required' -Expected 'required' -Detail 'RequireSecuritySignature = False.'
    }
    if ((& $can 'llmnr_enabled') -and "$($n.llmnrPolicyEnableMulticast)" -ne '0') {
        Add-Finding -Type 'llmnr_enabled' -Object 'DNS client' -Found $(if ($null -eq $n.llmnrPolicyEnableMulticast) { 'not set (LLMNR on)' } else { "$($n.llmnrPolicyEnableMulticast)" }) -Expected '0' -Detail $(if ($null -eq $n.llmnrPolicyEnableMulticast) { 'EnableMulticast policy not set (LLMNR on by default).' } else { "EnableMulticast = $($n.llmnrPolicyEnableMulticast)." })
    }
    # mDNS is on unless the policy or the DNS client's own setting turns it off. Snapshots from before
    # these fields existed are not judged.
    if ((& $can 'mdns_enabled') -and ($n.PSObject.Properties.Name -contains 'mdnsPolicyEnable')) {
        $pol = "$($n.mdnsPolicyEnable)"; $svc = "$($n.mdnsServiceEnable)"
        if ($pol -ne '0' -and -not ($pol -eq '' -and $svc -eq '0')) {
            $found = if ($pol -ne '') { $pol } elseif ($svc -ne '') { "$svc (DNS client setting)" } else { 'not set (mDNS on by default)' }
            Add-Finding -Type 'mdns_enabled' -Object 'DNS client: mDNS' -ServerCis '18.6.4.1' -Found $found -Expected '0' -Detail "EnableMDNS $(if ($pol -ne '') { "policy = $pol" } else { 'policy not set' }) ({cis} expects 0, mDNS off)."
        }
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
            Add-Finding -Type 'rdp_nla_disabled' -Object 'RDP' -Found '0' -Expected '1' -Detail 'RDP enabled, UserAuthentication = 0.'
        }
        if ((& $can 'rdp_enabled_workstation') -and $r.rdpEnabled -eq $true) {
            Add-Finding -Type 'rdp_enabled_workstation' -Object 'RDP' -Found '0' -Expected '1' -Detail 'fDenyTSConnections = 0.'
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
                Add-Finding -Type 'guest_enabled' -Object "account: $($u.name)" -Found 'enabled' -Expected 'disabled' -Detail 'Guest account enabled.'
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
        if ((& $can 'uac_disabled') -and "$($u.enableLua)" -eq '0') { Add-Finding -Type 'uac_disabled' -Object 'UAC' -Found '0' -Expected '1' -Detail 'EnableLUA = 0.' }
        if ((& $can 'uac_admin_no_prompt') -and "$($u.consentPromptBehaviorAdmin)" -eq '0') { Add-Finding -Type 'uac_admin_no_prompt' -Object 'UAC' -Found '0' -Expected '1 or 2' -Detail 'ConsentPromptBehaviorAdmin = 0.' }
        if ((& $can 'remote_uac_token_filter_off') -and "$($u.localAccountTokenFilterPolicy)" -eq '1') { Add-Finding -Type 'remote_uac_token_filter_off' -Object 'UAC' -Found '1' -Expected '0' -Detail 'LocalAccountTokenFilterPolicy = 1.' }
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
            $fileWritable = @($w | Where-Object { $_.scope -eq 'file' }).Count -gt 0
            $starters = @($svc.startableBy | Where-Object { $_ })
            $sev = if ($fileWritable -or $starters.Count -gt 0) { 'High' } else { 'Medium' }
            $detail = "$($svc.executable), runs as $($svc.account) ($($svc.state)): writable by $(Get-WriterText $w)."
            if (-not $fileWritable) { $detail += ' The program itself is not writable, but files can be added to its folder: a DLL placed there can be loaded by the service if the program looks for one in its folder (DLL planting; whether it does is not checked).' }
            if (-not $fileWritable -and "$($svc.executable)" -match '(?i)^[a-z]:\\programdata\\') { $detail += ' The ProgramData folder lets users create files by default and this folder inherits that: the program was installed under ProgramData, not Program Files.' }
            if ($starters.Count -gt 0) { $detail += " $((@($starters | ForEach-Object { Get-SidLabel $_ }) -join ', ')) can start the service, so the planted code runs on demand." }
            elseif ("$($svc.startMode)" -eq 'Auto') { $detail += ' It starts at boot.' }
            Add-Finding -Type 'service_binary_writable' -Object "service: $($svc.name)" -Severity $sev -Detail $detail
        }
    }
    if (& $can 'service_path_ancestor_control') {
        $adminSids = @{}; foreach ($m in @($S.localAccounts.administrators | Where-Object { $_ })) { $adminSids["$($m.sid)"] = $true }
        $names = @{}; foreach ($u in @($S.localAccounts.users | Where-Object { $_ })) { $names["$($u.sid)"] = "$($u.name)" }
        $everyone = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')
        $unknownAdmins = ($S.localAccounts.administratorsReadable -ne $true)
        foreach ($svc in $services) {
            $items = @($svc.ancestorControl | Where-Object { $_ -and -not $adminSids.ContainsKey("$($_.sid)") })
            if ($items.Count -eq 0) { continue }
            $parts = @(); $broad = $false
            foreach ($it in ($items | Sort-Object { [int]$_.level }, kind, sid | Select-Object -First 4)) {
                $who = if ($names.ContainsKey("$($it.sid)")) { $names["$($it.sid)"] } else { Get-SidLabel "$($it.sid)" }
                if ($everyone -contains "$($it.sid)") { $broad = $true }
                $where = if ([int]$it.level -eq 1) { 'the program''s own folder' } else { "the folder $([int]$it.level - 1) level(s) above the program's folder" }
                $parts += $(if ("$($it.kind)" -eq 'owner') { "$who owns $where" } else { "$who has $($it.rights) on $where" })
            }
            $sev = if ($broad -and "$($svc.account)" -match '(?i)^(localsystem|nt authority\\system)$') { 'High' } else { 'Medium' }
            Add-Finding -Type 'service_path_ancestor_control' -Object "service: $($svc.name)" -Severity $sev -Detail ("Runs as $($svc.account). " + ($parts -join '; ') + '. Whoever controls a parent folder controls the whole path to the program.' + $(if ($unknownAdmins) { ' The local Administrators group could not be read: check that this account is not an administrator.' } else { '' }))
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
        Add-Finding -Type 'cmdline_audit_off' -Object 'Process creation events' -Found $(if ($null -eq $a.processCreationIncludeCmdLine) { 'not set' } else { "$($a.processCreationIncludeCmdLine)" }) -Expected '1' -Detail 'ProcessCreationIncludeCmdLine_Enabled not set to 1.'
    }
    if ($a -and (& $can 'security_log_small') -and $null -ne $a.securityLogMaxSizeBytes) {
        $kb = [int64]$a.securityLogMaxSizeBytes / 1KB
        if ($kb -lt $Config.MinSecurityLogKB) { Add-Finding -Type 'security_log_small' -Object 'Security log' -Found "$([int64]$kb) KB" -Expected "at least $($Config.MinSecurityLogKB) KB" -Detail "Maximum size $([int64]$kb) KB (minimum $($Config.MinSecurityLogKB) KB)." }
    }
    $p = $S.powershell
    if ($p) {
        if ((& $can 'powershell_scriptblock_logging_off') -and "$($p.scriptBlockLogging)" -ne '1') {
            Add-Finding -Type 'powershell_scriptblock_logging_off' -Object 'PowerShell' -Found $(if ($null -eq $p.scriptBlockLogging) { 'not set' } else { "$($p.scriptBlockLogging)" }) -Expected '1' -Detail 'EnableScriptBlockLogging not set to 1.'
        }
        if ((& $can 'powershell_module_logging_off') -and "$($p.moduleLogging)" -ne '1') {
            Add-Finding -Type 'powershell_module_logging_off' -Object 'PowerShell module logging' -Detail 'EnableModuleLogging not set to 1.'
        }
        if ((& $can 'powershell_v2_enabled') -and "$($p.v2EngineVersion)" -eq '2.0') {
            Add-Finding -Type 'powershell_v2_enabled' -Object 'PowerShell 2.0' -Detail 'The 2.0 engine is registered (optional feature installed).'
        }
    }
}

# Settings from the CIS Windows 11 Enterprise benchmark (v3.0.0). Each finding quotes its rule
# number. A value that isn't set is judged only where the Windows default is itself the problem.
$script:CisDisableServices = @{
    BTAGService = '5.1'; bthserv = '5.2'; Browser = '5.3'; iisadmin = '5.6'; irmon = '5.7'; LxssManager = '5.9'; FTPSVC = '5.10'; sshd = '5.12'; RpcLocator = '5.23'
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
            # A domain controller needs LSARPC, NETLOGON and SAMR there (CIS for servers expects them):
            # only the other pipes count. Older snapshots have no such count: the total is used.
            $nonDc = & $n $h.nullSessionPipesNonDcCount
            if ($role -eq 'dc' -and $null -ne $nonDc) {
                if ($nonDc -gt 0) { Add-Finding -Type 'null_session_access' -Object 'NullSessionPipes' -Detail "$nonDc named pipe(s) besides LSARPC, NETLOGON and SAMR listed as accessible anonymously (CIS 2.3.10.6 expects only those on a domain controller)." }
            }
            else {
                $c = & $n $h.nullSessionPipesCount
                if ($c -gt 0) { Add-Finding -Type 'null_session_access' -Object 'NullSessionPipes' -Detail "$c named pipe(s) listed as accessible anonymously (CIS 2.3.10.6 expects none)." }
            }
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
        if ((& $can 'authenticode_padding_check_off') -and ($h.PSObject.Properties.Name -contains 'certPaddingCheck')) {
            # Both registry views on 64-bit Windows: 32-bit programs verify signatures through the second.
            $missing = @()
            if ("$($h.certPaddingCheck)" -ne '1') { $missing += 'Wintrust\Config' }
            if ($h.is64BitOs -eq $true -and "$($h.certPaddingCheckWow)" -ne '1') { $missing += 'Wow6432Node\...\Wintrust\Config' }
            if ($missing.Count -gt 0) {
                Add-Finding -Type 'authenticode_padding_check_off' -Object 'Authenticode padding check' -Found $(if ("$($h.certPaddingCheck)" -eq '') { 'not set' } else { "$($h.certPaddingCheck)" }) -Expected '1' -Detail "EnableCertPaddingCheck is not 1 under $($missing -join ' and ') (opt-in fix for CVE-2013-3900)."
            }
        }
        $bp = $h.bitlockerPolicy
        if ((& $can 'bitlocker_policy_weak') -and $bp) {
            # Home has no BitLocker Group Policy: only an explicit value is judged there.
            $judgeUnset = $role -eq 'workstation' -and -not (Test-HomeEdition $S)
            foreach ($r in $script:BitLockerPolicyWeak) {
                $v = & $n $bp.($r.Name)
                if ($null -eq $v -and $r.Unset -and $judgeUnset) {
                    Add-Finding -Type 'bitlocker_policy_weak' -Object "BitLocker policy: $($r.Name)" -Severity $r.Severity -Detail "$($r.Name) not set (CIS $($r.Rule) expects $($r.Expected); the Windows default does not apply this protection)."
                }
                elseif ($null -ne $v -and $v -ne $r.Expected) {
                    Add-Finding -Type 'bitlocker_policy_weak' -Object "BitLocker policy: $($r.Name)" -Severity $r.Severity -Detail "$($r.Name) = $v (CIS $($r.Rule) expects $($r.Expected))."
                }
            }
        }
        if ((& $can 'bitlocker_policy_gaps') -and $bp) {
            foreach ($r in $script:BitLockerPolicyGaps) {
                $raw = $bp.($r[0])
                if ($null -eq $raw) { continue }
                $exp = $r[2]
                if ($exp -is [string] -and $exp -eq '') {
                    if ("$raw" -ne '') { Add-Finding -Type 'bitlocker_policy_gaps' -Object "BitLocker policy: $($r[0])" -Detail "$($r[0]) = '$raw' (CIS $($r[1]) expects an empty value: no access from earlier versions of Windows)." }
                    continue
                }
                $v = & $n $raw
                $ok = if ($exp -eq '1 or 2') { $v -eq 1 -or $v -eq 2 } else { $v -eq $exp }
                if (-not $ok) { Add-Finding -Type 'bitlocker_policy_gaps' -Object "BitLocker policy: $($r[0])" -Detail "$($r[0]) = $raw (CIS $($r[1]) expects $exp)." }
            }
        }
        if ((& $can 'firewall_notifications_on') -and $h.firewallPolicy) {
            foreach ($row in @(@('domainDisableNotifications', 'Domain', '9.1.3'), @('privateDisableNotifications', 'Private', '9.2.3'), @('publicDisableNotifications', 'Public', '9.3.3'))) {
                $v = & $n $h.firewallPolicy.($row[0])
                if ($null -ne $v -and $v -ne 1) { Add-Finding -Type 'firewall_notifications_on' -Object "profile: $($row[1])" -Detail "DisableNotifications = $v (CIS $($row[2]) expects 1)." }
            }
        }
        if ((& $can 'winrm_insecure_auth') -and $h.winrm) {
            $w = $h.winrm
            foreach ($row in @(@('clientAllowBasic', 'WinRM client: Basic authentication', 'AllowBasic', '18.10.88.1.1'), @('clientAllowUnencryptedTraffic', 'WinRM client: unencrypted traffic', 'AllowUnencryptedTraffic', '18.10.88.1.2'),
                    @('clientAllowDigest', 'WinRM client: Digest authentication', 'AllowDigest', '18.10.88.1.3'), @('serviceAllowBasic', 'WinRM service: Basic authentication', 'AllowBasic', '18.10.88.2.1'),
                    @('serviceAllowUnencryptedTraffic', 'WinRM service: unencrypted traffic', 'AllowUnencryptedTraffic', '18.10.88.2.3'), @('serviceAllowAutoConfig', 'WinRM service: remote configuration via WinRM', 'AllowAutoConfig', '18.10.88.2.2'))) {
                $v = & $n $w.($row[0])
                if ($v -eq 1) { Add-Finding -Type 'winrm_insecure_auth' -Object $row[1] -Detail "$($row[2]) = 1 (CIS $($row[3]) expects 0)." }
            }
            $v = & $n $w.serviceDisableRunAs
            if ($v -ne 1) { Add-Finding -Type 'winrm_insecure_auth' -Object 'WinRM service: RunAs credential storage' -Detail "DisableRunAs = $(if ($null -eq $v) { 'not set' } else { $v }) (CIS 18.10.88.2.4 expects 1; unset also allows storing credentials)." }
        }
        if ((& $can 'schannel_legacy_crypto_enabled') -and $h.schannel) {
            # Enabled is a DWORD: any non-zero value (0xFFFFFFFF reads as -1) switches it on.
            foreach ($pr in @($h.schannel.protocols | Where-Object { $_ })) {
                $v = & $n $pr.enabled
                if ($null -ne $v -and $v -ne 0) {
                    $ssl = "$($pr.name)" -like 'SSL*'
                    Add-Finding -Type 'schannel_legacy_crypto_enabled' -Object "protocol: $($pr.name) ($("$($pr.side)".ToLower()))" -Severity $(if ($ssl) { 'Medium' } else { 'Low' }) -Detail "$($pr.name) is explicitly enabled for the $("$($pr.side)".ToLower()) side (Enabled = $v)."
                }
            }
            foreach ($ci in @($h.schannel.ciphers | Where-Object { $_ })) {
                $v = & $n $ci.enabled
                if ($null -ne $v -and $v -ne 0) {
                    Add-Finding -Type 'schannel_legacy_crypto_enabled' -Object "cipher: $($ci.name)" -Severity $(if ("$($ci.name)" -like 'Triple DES*') { 'Low' } else { 'Medium' }) -Detail "The $($ci.name) cipher is explicitly enabled (Enabled = $v)."
                }
            }
        }
        if ((& $can 'ldap_server_signing_off') -and $h.ldapServer) {
            $v = & $n $h.ldapServer.integrity
            if ($v -ne 2) { Add-Finding -Type 'ldap_server_signing_off' -Object 'LDAP server signing' -ServerCis '2.3.5.4' -Detail "LDAPServerIntegrity = $(if ($null -eq $v) { 'not set (negotiate)' } else { $v }) ({cis} expects 2, require signing)." }
            $v = & $n $h.ldapServer.channelBinding
            if ($v -ne 2) { Add-Finding -Type 'ldap_server_signing_off' -Object 'LDAP channel binding' -ServerCis '2.3.5.3' -Detail "LdapEnforceChannelBinding = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 2, always)." }
        }
        if ((& $can 'dc_netlogon_policy_weak') -and $h.netlogon) {
            $nl = $h.netlogon
            if ($nl.vulnerableChannelAllowListPresent -eq $true) { Add-Finding -Type 'dc_netlogon_policy_weak' -Object 'Netlogon: VulnerableChannelAllowList' -Severity 'High' -ServerCis '2.3.5.2' -Found 'set' -Expected 'not configured' -Detail 'An exception list for vulnerable Netlogon secure channel connections (Zerologon) is set ({cis} expects it not configured).' }
            $v = & $n $nl.refusePasswordChange
            if ($v -eq 1) { Add-Finding -Type 'dc_netlogon_policy_weak' -Object 'Netlogon: RefusePasswordChange' -Severity 'Medium' -ServerCis '2.3.5.5' -Detail 'RefusePasswordChange = 1: machine account passwords are never changed ({cis} expects 0).' }
        }
        if ((& $can 'dc_netlogon_policy_weak') -and $h.serverLogon) {
            $v = & $n $h.serverLogon.submitControl
            if ($v -eq 1) { Add-Finding -Type 'dc_netlogon_policy_weak' -Object 'Server Operators: schedule tasks' -Severity 'Medium' -ServerCis '2.3.5.1' -Detail 'SubmitControl = 1: Server Operators can schedule tasks that run as SYSTEM ({cis} expects 0).' }
        }
        if ((& $can 'server_baseline_gaps') -and $h.serverLogon) {
            $v = & $n $h.serverLogon.shutdownWithoutLogon
            if ($v -eq 1) { Add-Finding -Type 'server_baseline_gaps' -Object 'Shutdown without logon' -ServerCis '2.3.13.1' -Detail 'ShutdownWithoutLogon = 1 ({cis} expects 0).' }
            $v = & $n $h.serverLogon.forceUnlockLogon
            if ($role -eq 'server' -and $v -eq 0) { Add-Finding -Type 'server_baseline_gaps' -Object 'Unlock without domain controller' -ServerCis '2.3.7.8' -Detail 'ForceUnlockLogon = 0: the server unlocks with cached credentials ({cis} expects 1).' }
        }
        $lp = $S.laps
        if ((& $can 'server_baseline_gaps') -and $role -eq 'server' -and $lp -and "$($lp.windowsLapsBackupDirectory)" -eq '2' -and "$($lp.windowsLapsPasswordExpirationProtection)" -eq '0') {
            Add-Finding -Type 'server_baseline_gaps' -Object 'Windows LAPS: password expiration protection' -ServerCis '18.9.25.2' -Detail "PasswordExpirationProtectionEnabled = 0 in the $($lp.windowsLapsPolicyRoot) policy: the password expiry can be pushed beyond the policy ({cis} expects 1)."
        }
        if ((& $can 'smb_server_hardening_gaps') -and $h.serverSmb) {
            $v = & $n $h.serverSmb.minSmb2Dialect
            if ($v -ne 785) { Add-Finding -Type 'smb_server_hardening_gaps' -Object 'SMB server: minimum dialect' -ServerCis '18.6.7.1' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '785 (3.1.1)' -Detail "MinSmb2Dialect = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 785, SMB 3.1.1)." }
            $v = & $n $h.serverSmb.clientRequireEncryption
            if ($v -ne 1) { Add-Finding -Type 'smb_server_hardening_gaps' -Object 'SMB client: require encryption' -ServerCis '18.6.8.2' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "RequireEncryption = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1)." }
        }
        if ((& $can 'defender_server_baseline_gaps') -and $h.defenderPolicy) {
            $v = & $n $h.defenderPolicy.hideExclusionsFromLocalUsers
            if ($v -ne 1) { Add-Finding -Type 'defender_server_baseline_gaps' -Object 'Defender: exclusions hidden from local users' -ServerCis '18.10.43.17' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "HideExclusionsFromLocalUsers = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1)." }
            $v = & $n $h.defenderPolicy.quickScanIncludeExclusions
            if ($v -ne 1) { Add-Finding -Type 'defender_server_baseline_gaps' -Object 'Defender: quick scan includes exclusions' -ServerCis '18.10.43.13.1' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "QuickScanIncludeExclusions = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1)." }
        }
        if ((& $can 'terminal_services_server_gaps') -and $h.terminalServicesPolicy) {
            $v = & $n $h.terminalServicesPolicy.perSessionTempDir
            if ($v -ne 1) { Add-Finding -Type 'terminal_services_server_gaps' -Object 'Remote Desktop: per-session temporary folders' -ServerCis '18.10.57.3.11.2' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "PerSessionTempDir = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1, a temporary folder per session)." }
            $v = & $n $h.terminalServicesPolicy.singleSessionPerUser
            if ($v -ne 1) { Add-Finding -Type 'terminal_services_server_gaps' -Object 'Remote Desktop: single session per user' -ServerCis '18.10.57.3.2.1' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "fSingleSessionPerUser = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1)." }
        }
        if ((& $can 'explorer_motw_bypass') -and $h.serverPolicy) {
            $v = & $n $h.serverPolicy.disableMotwInsecureCopy
            if ($v -eq 1) { Add-Finding -Type 'explorer_motw_bypass' -Object 'Explorer: Mark of the Web on insecure copy' -ServerCis '18.10.29.2' -Found '1' -Expected '0' -Detail 'DisableMotWOnInsecurePathCopy = 1: files copied from insecure sources keep no zone marker ({cis} expects 0, the policy Disabled).' }
        }
        if ((& $can 'app_installer_policy_gaps') -and $h.serverPolicy -and $h.serverPolicy.appInstaller) {
            $ai = $h.serverPolicy.appInstaller
            $v = & $n $ai.localArchiveMalwareScanOverride
            if ($v -ne 0) { Add-Finding -Type 'app_installer_policy_gaps' -Object 'App Installer: local archive malware scan override' -ServerCis '18.10.18.4' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '0' -Detail "EnableLocalArchiveMalwareScanOverride = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 0, no override)." }
            $v = & $n $ai.bypassCertPinningForStore
            if ($v -ne 0) { Add-Finding -Type 'app_installer_policy_gaps' -Object 'App Installer: Store certificate pinning bypass' -ServerCis '18.10.18.6' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '0' -Detail "EnableBypassCertificatePinningForMicrosoftStore = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 0)." }
            $v = & $n $ai.commandLineInterfaces
            if ($v -ne 0) { Add-Finding -Type 'app_installer_policy_gaps' -Object 'App Installer: winget command-line interfaces' -ServerCis '18.10.18.7' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '0' -Detail "EnableWindowsPackageManagerCommandLineInterfaces = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 0)." }
        }
        if ((& $can 'server_network_policy_gaps') -and $h.serverPolicy) {
            $v = & $n $h.serverPolicy.ipv6DefaultDnsDisabled
            if ($v -ne 1) { Add-Finding -Type 'server_network_policy_gaps' -Object 'DNS client: default IPv6 DNS servers' -ServerCis '18.6.4.3' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1' -Detail "DisableIPv6DefaultDnsServers = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1, default IPv6 DNS off)." }
            $v = & $n $h.serverPolicy.ieFeedBasicAuthInClear
            if ($v -ne 0) { Add-Finding -Type 'server_network_policy_gaps' -Object 'Internet Explorer feeds: Basic auth in clear' -ServerCis '18.10.58.2' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '0' -Detail "AllowBasicAuthInClear = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 0, no Basic auth over HTTP)." }
        }
        if ((& $can 'ldap_client_encryption_weak') -and $h.serverPolicy) {
            $v = & $n $h.serverPolicy.ldapClientConfidentiality
            if (($null -eq $v) -or ($v -lt 1)) { Add-Finding -Type 'ldap_client_encryption_weak' -Object 'LDAP client encryption' -ServerCis '2.3.11.8' -Found $(if ($null -eq $v) { 'not set (None)' } else { "$v" }) -Expected '1 or 2 (Negotiate/Require sealing)' -Detail "LDAPClientConfidentiality = $(if ($null -eq $v) { 'not set (None)' } else { $v }) ({cis} expects at least 1, Negotiate sealing)." }
        }
        if ((& $can 'dc_security_policy_gaps') -and $h.serverPolicy) {
            $v = & $n $h.serverPolicy.samNgcRocaValidation
            if ($v -ne 1 -and $v -ne 2) { Add-Finding -Type 'dc_security_policy_gaps' -Object 'ROCA-vulnerable WHfB key validation' -Severity 'Medium' -ServerCis '18.9.39.1' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '1 or 2 (Audit/Block)' -Detail "SamNGCKeyROCAValidation = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 1, Audit, or 2, Block)." }
            $v = & $n $h.serverPolicy.auditNtlmInDomain
            if ($v -ne 7) { Add-Finding -Type 'dc_security_policy_gaps' -Object 'Audit NTLM authentication in this domain' -Severity 'Low' -ServerCis '2.3.11.13' -Found $(if ($null -eq $v) { 'not set' } else { "$v" }) -Expected '7 (Enable all)' -Detail "AuditNTLMInDomain = $(if ($null -eq $v) { 'not set' } else { $v }) ({cis} expects 7, Enable all)." }
        }
        if ((& $can 'print_point_and_print_weak') -and $h.pointAndPrint) {
            $pp = $h.pointAndPrint
            $v = & $n $pp.restrictDriverInstallToAdmins
            if ($v -eq 0) { Add-Finding -Type 'print_point_and_print_weak' -Object 'RestrictDriverInstallationToAdministrators' -Found '0' -Expected '1' -Detail 'RestrictDriverInstallationToAdministrators = 0: standard users can install printer drivers.' }
            $v = & $n $pp.noWarningNoElevationOnInstall
            if ($v -eq 1) { Add-Finding -Type 'print_point_and_print_weak' -Object 'NoWarningNoElevationOnInstall' -Severity 'High' -Found '1' -Expected '0 or not set' -Detail 'NoWarningNoElevationOnInstall = 1: installing a driver from a print server needs no elevation (PrintNightmare condition).' }
            $v = & $n $pp.noWarningNoElevationOnUpdate
            if ($v -eq 1) { Add-Finding -Type 'print_point_and_print_weak' -Object 'NoWarningNoElevationOnUpdate' -Severity 'High' -Found '1' -Expected '0 or not set' -Detail 'NoWarningNoElevationOnUpdate = 1: updating a driver from a print server needs no elevation.' }
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
                Add-Finding -Type 'logon_banner_missing' -Object 'Logon message' -Found 'not set' -Expected 'a title and a text' -Detail 'No LegalNoticeCaption or LegalNoticeText (CIS 2.3.7.5, 2.3.7.6).'
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
        Add-Finding -Type 'powershell_transcription_off' -Object 'PowerShell transcription' -Found $(if ($null -eq $ps.transcription) { 'not set' } else { "$($ps.transcription)" }) -Expected '1' -Detail 'EnableTranscripting not set to 1 (CIS 18.10.86.2, Level 2).'
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
            if ("$($svc.state)" -ne 'Running' -and "$($svc.startMode)" -ne 'Auto') { continue }
            if ($role -eq 'server') {
                # The server benchmarks list one service: Print Spooler on a member server (Windows 11
                # 5.17, quoted as the server's own 5.2, L2). On a domain controller spooler_on_dc judges it.
                if ($name -eq 'Spooler') { Add-Finding -Type 'service_should_be_disabled' -Object "service: $name" -Severity 'Low' -Detail "$($svc.state), start mode $($svc.startMode) (CIS 5.17 expects disabled unless this is a print server)." }
                continue
            }
            if (-not $script:CisDisableServices.Contains($name)) { continue }
            $sev = if ($script:CisDisableServicesMedium -contains $name) { 'Medium' } else { 'Low' }
            Add-Finding -Type 'service_should_be_disabled' -Object "service: $name" -Severity $sev -Detail "$($svc.state), start mode $($svc.startMode) (CIS $($script:CisDisableServices[$name]) expects disabled)."
        }
    }
    if (& $can 'webclient_webdav_enabled') {
        $wc = @($S.services | Where-Object { "$($_.name)" -eq 'WebClient' }) | Select-Object -First 1
        if ($wc -and "$($wc.startMode)" -ne 'Disabled') {
            $sev = if ($role -eq 'dc') { 'High' } elseif ($role -eq 'server') { 'Medium' } else { 'Low' }
            Add-Finding -Type 'webclient_webdav_enabled' -Object 'service: WebClient' -Severity $sev -Detail "WebClient (WebDAV) is $($wc.state), start mode $($wc.startMode): coercion (PetitPotam) can force the host to authenticate over HTTP for NTLM relay."
        }
    }
    if ((& $can 'wpad_not_disabled') -and $h) {
        $wpad = & $n $h.wpadDisabled
        $svc = @($S.services | Where-Object { "$($_.name)" -eq 'WinHttpAutoProxySvc' }) | Select-Object -First 1
        $svcDisabled = $svc -and "$($svc.startMode)" -eq 'Disabled'
        if ($wpad -ne 1 -and -not $svcDisabled) {
            Add-Finding -Type 'wpad_not_disabled' -Object 'WPAD auto-discovery' -Detail "DisableWpad = $(if ($null -eq $wpad) { 'not set' } else { $wpad }) and the WinHttpAutoProxySvc service is $(if ($svc) { "$($svc.startMode.ToLower())" } else { 'present' }): clients still resolve 'wpad', which an attacker can answer to capture NTLM."
        }
    }
    if (& $can 'bloatware_installed') {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($b in $script:BloatwareApps) {
            $pk = @(if ($b.Appx) { @($S.appx | Where-Object { $_ -and "$($_.name)" -match $b.Appx }) })
            $pg = @(if ($b.Program) { @($S.software | Where-Object { $_ -and "$($_.name)" -match $b.Program }) })
            if ($pk.Count -eq 0 -and $pg.Count -eq 0) { continue }
            $where = @()
            if (@($pk | Where-Object { [int]$_.users -gt 0 }).Count) { $where += 'installed' }
            if (@($pk | Where-Object { $_.provisioned -eq $true }).Count) { $where += 'provisioned for new users' }
            if ($pg.Count) { $where += 'program' }
            $hits.Add("$($b.Label) ($($where -join ', '))")
        }
        if ($hits.Count -gt 0) { Add-Finding -Type 'bloatware_installed' -Object 'preinstalled apps' -Found "$($hits.Count) found" -Expected 'none' -Detail "$($hits -join '; ')." }
    }
    # Fields added in 1.3: a snapshot that predates them is not judged on them.
    if ((& $can 'script_files_execute_on_open') -and $h -and $null -ne $h.fileAssociations) {
        $wshOff = "$($h.scriptHostEnabled)" -eq '0'
        $runs = @()
        foreach ($a in @($h.fileAssociations | Where-Object { $_ })) {
            $ext = "$($a.ext)".ToLower()
            if (-not $script:ScriptRunProgIds.Contains($ext)) { continue }
            if ($wshOff -and $ext -ne '.hta') { continue }
            # It runs when the ProgId is the script host's own, or the open command calls a script host.
            if ("$($a.progId)" -eq $script:ScriptRunProgIds[$ext] -or "$($a.openCommand)" -match '(?i)\b(wscript|cscript|mshta)(\.exe)?\b') { $runs += $ext }
        }
        if ($runs.Count -gt 0) {
            $sev = if ($role -eq 'workstation') { 'Medium' } else { 'Low' }
            foreach ($ext in $runs) {
                $a = @($h.fileAssociations | Where-Object { "$($_.ext)".ToLower() -eq $ext })[0]
                Add-Finding -Type 'script_files_execute_on_open' -Object "file type: $ext" -Severity $sev -Found "$($a.progId)" -Expected 'txtfile (opens as text)' -Detail "$ext opens with $($a.progId)$(if ("$($a.openCommand)") { " ($($a.openCommand))" }): a double click runs the script."
            }
        }
    }
    if ((& $can 'lolbin_outbound_not_blocked') -and $h -and $null -ne $h.lolbinOutboundBlocks) {
        $blocked = @($h.lolbinOutboundBlocks | Where-Object { $_ } | ForEach-Object { "$($_.program)".ToLower() } | Select-Object -Unique)
        $open = @($script:Lolbins | Where-Object { $blocked -notcontains $_ })
        if ($open.Count -gt 0) {
            Add-Finding -Type 'lolbin_outbound_not_blocked' -Object 'outbound: system tools' -Found ($open -join ', ') -Expected 'blocked outbound' -Detail "$($open.Count) of $($script:Lolbins.Count) tools have no outbound block rule: $($open -join ', ')$(if ($blocked.Count -gt 0) { "; blocked: $($blocked -join ', ')" })."
        }
    }
    if ((& $can 'removable_media_execute_allowed') -and $h -and $null -ne $h.removableStorage) {
        $rs = $h.removableStorage
        if ("$($rs.denyAll)" -ne '1' -and "$($rs.disksDenyExecute)" -ne '1') {
            $other = @(); if ("$($rs.disksDenyWrite)" -eq '1') { $other += 'write denied' }; if ("$($rs.disksDenyRead)" -eq '1') { $other += 'read denied' }
            Add-Finding -Type 'removable_media_execute_allowed' -Object 'Removable disks' -Found $(if ($null -eq $rs.disksDenyExecute) { 'not configured' } else { "Deny_Execute = $($rs.disksDenyExecute)" }) -Expected 'Deny_Execute = 1' -Detail "Removable Disks: Deny execute access is $(if ($null -eq $rs.disksDenyExecute) { 'not configured' } else { "set to $($rs.disksDenyExecute)" }) and Deny_All is not set$(if ($other.Count) { " ($($other -join ', '))" })."
        }
    }
}
# Store apps (package name) and programs (Programs and Features name) that a business device rarely
# needs. OEM driver and firmware utilities are not listed: they often deliver BIOS and driver updates.
$script:BloatwareApps = @(
    @{ Label = 'King games (Candy Crush...)'; Appx = '^king\.com\.' }
    @{ Label = 'Microsoft Solitaire Collection'; Appx = '^Microsoft\.MicrosoftSolitaireCollection$' }
    @{ Label = 'Xbox apps'; Appx = '^Microsoft\.(XboxApp|XboxGamingOverlay|XboxGameOverlay|XboxSpeechToTextOverlay|Xbox\.TCUI|GamingApp)$' }
    @{ Label = 'Bing News, Weather, Sports, Finance'; Appx = '^Microsoft\.(BingNews|BingWeather|BingSports|BingFinance)$' }
    @{ Label = 'Groove Music, Movies & TV'; Appx = '^Microsoft\.(ZuneMusic|ZuneVideo)$' }
    @{ Label = 'Mixed Reality Portal'; Appx = '^Microsoft\.MixedReality\.Portal$' }
    @{ Label = 'Skype (Store app)'; Appx = '^Microsoft\.SkypeApp$' }
    @{ Label = 'Get Started, Feedback Hub, Office Hub, Cortana'; Appx = '^Microsoft\.(Getstarted|WindowsFeedbackHub|MicrosoftOfficeHub|549981C3F5F10)$' }
    @{ Label = 'Clipchamp'; Appx = '^Clipchamp\.Clipchamp$' }
    @{ Label = 'Spotify'; Appx = '^SpotifyAB\.SpotifyMusic$' }
    @{ Label = 'Disney+'; Appx = '^Disney\.' }
    @{ Label = 'Facebook, Instagram'; Appx = '^Facebook\.' }
    @{ Label = 'TikTok'; Appx = '^BytedancePte\.Ltd\.TikTok$' }
    @{ Label = 'Prime Video'; Appx = '^AmazonVideo\.PrimeVideo$' }
    @{ Label = 'Netflix'; Appx = '^4DF9E0F8\.Netflix$' }
    @{ Label = 'McAfee (trial)'; Appx = '^5A894077\.McAfeeSecurity$'; Program = '^McAfee (LiveSafe|Total Protection|Security Scan|WebAdvisor|Safe Connect)\b' }
    @{ Label = 'Norton (trial)'; Program = '^Norton (Security|360|Security Ultra|AntiVirus)\b' }
    @{ Label = 'WildTangent Games'; Program = '^WildTangent\b' }
)
# The STIG release behind each check type, for the dashboard (keep in step with tools\New-CoverageDoc.ps1).
$script:StigTypeLabel = [ordered]@{
    stig_windows11 = 'Windows 11 V2R7'; stig_windows10 = 'Windows 10 V3R6'; stig_server2025 = 'Windows Server 2025 V1R1'; stig_server2022 = 'Windows Server 2022 V2R8'
    stig_server2019 = 'Windows Server 2019 V3R8'; stig_server2016 = 'Windows Server 2016 V2R10'; stig_defender = 'Defender Antivirus V2R8'; stig_firewall = 'Windows Firewall V2R2'
    stig_edge = 'Microsoft Edge V2R5'; stig_chrome = 'Google Chrome V2R11'; stig_firefox = 'Mozilla Firefox V6R7'; stig_office = 'Microsoft 365 Apps V3R5'; stig_adobe = 'Adobe Acrobat V2R1'
}
# ACSC Essential Eight: the HostBadger checks that bear on each mitigation strategy, from a host. This
# is coverage of related settings, not an Essential Eight maturity assessment: multi-factor
# authentication and backups cannot be seen from a host, and application control is only touched at
# its edges (drivers, script hosts, removable media).
$script:E8Strategies = [ordered]@{
    patch_apps = @{ Label = 'Patch applications'; Checks = @('software_eol', 'software_outdated', 'software_cve', 'kev_software_match') }
    patch_os   = @{ Label = 'Patch operating systems'; Checks = @('os_unsupported', 'os_support_ending', 'updates_stale', 'updates_pending', 'wu_auto_updates_disabled') }
    mfa        = @{ Label = 'Multi-factor authentication'; Checks = @(); Note = 'not visible from a host' }
    admin      = @{ Label = 'Restrict administrative privileges'; Checks = @('local_admin_member', 'builtin_admin_enabled', 'laps_not_configured', 'remote_uac_token_filter_off', 'uac_disabled', 'uac_admin_no_prompt', 'user_rights_excessive', 'deny_logon_rights_missing', 'credential_guard_off', 'lsa_not_protected', 'wdigest_cleartext', 'autologon_enabled') }
    appcontrol = @{ Label = 'Application control'; Checks = @('driver_blocklist_off', 'vulnerable_driver_present', 'script_files_execute_on_open', 'removable_media_execute_allowed', 'lolbin_outbound_not_blocked', 'always_install_elevated') }
    macros     = @{ Label = 'Restrict Microsoft Office macros'; Checks = @('stig_office', 'asr_other_rules_not_blocking') }
    userapp    = @{ Label = 'User application hardening'; Checks = @('stig_edge', 'stig_chrome', 'stig_firefox', 'stig_adobe', 'powershell_v2_enabled', 'powershell_scriptblock_logging_off', 'powershell_module_logging_off', 'cmdline_audit_off', 'smartscreen_off') }
    backups    = @{ Label = 'Regular backups'; Checks = @(); Note = 'not visible from a host' }
}
# Script extensions and the ProgId Windows gives them when they run on a double click.
$script:ScriptRunProgIds = [ordered]@{ '.js' = 'JSFile'; '.jse' = 'JSEFile'; '.vbs' = 'VBSFile'; '.vbe' = 'VBEFile'; '.wsf' = 'WSFFile'; '.wsh' = 'WSHFile'; '.hta' = 'htafile' }
# Tools the collector looks for in outbound block rules (keep in step with $lolbins in the collector).
$script:Lolbins = @('certutil.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'wmic.exe', 'bitsadmin.exe')
# User rights (CIS 2.2.x, Level 1): who may hold each one. The expected principals are SIDs. Expect
# is the Windows 11 workstation; Dc and Ms, when given, the domain controller and member server
# variants of the CIS Windows Server 2022/2019 benchmarks (the rule number follows data\cis-map.json).
# ServerRule: a right only the server benchmark has (quoted with its server number). Sev is High for
# the rights that lead straight to SYSTEM.
$script:CisUserRights = @(
    @{ Right = 'SeTrustedCredManAccessPrivilege'; Rule = '2.2.1'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeNetworkLogonRight'; Rule = '2.2.2'; Expect = @('S-1-5-32-544', 'S-1-5-32-555'); Dc = @('S-1-5-32-544', 'S-1-5-11', 'S-1-5-9'); Ms = @('S-1-5-32-544', 'S-1-5-11'); Sev = 'Medium' }
    @{ Right = 'SeTcbPrivilege'; Rule = '2.2.3'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeMachineAccountPrivilege'; ServerRule = '2.2.5'; Dc = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeInteractiveLogonRight'; Rule = '2.2.5'; Expect = @('S-1-5-32-544', 'S-1-5-32-545'); Dc = @('S-1-5-32-544', 'S-1-5-9'); Ms = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeRemoteInteractiveLogonRight'; Rule = '2.2.6'; Expect = @('S-1-5-32-544', 'S-1-5-32-555'); Dc = @('S-1-5-32-544'); Ms = @('S-1-5-32-544', 'S-1-5-32-555'); Sev = 'Medium' }
    @{ Right = 'SeBackupPrivilege'; Rule = '2.2.7'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeCreatePagefilePrivilege'; Rule = '2.2.10'; Expect = @('S-1-5-32-544'); Sev = 'Medium' }
    @{ Right = 'SeCreateTokenPrivilege'; Rule = '2.2.11'; Expect = @(); Sev = 'High' }
    @{ Right = 'SeCreatePermanentPrivilege'; Rule = '2.2.13'; Expect = @(); Sev = 'Medium' }
    # Virtual Machines holds it once Hyper-V is installed: CIS accepts it there (not on a DC).
    @{ Right = 'SeCreateSymbolicLinkPrivilege'; Rule = '2.2.14'; Expect = @('S-1-5-32-544', 'S-1-5-83-0'); Dc = @('S-1-5-32-544'); Ms = @('S-1-5-32-544', 'S-1-5-83-0'); Sev = 'Medium' }
    @{ Right = 'SeDebugPrivilege'; Rule = '2.2.15'; Expect = @('S-1-5-32-544'); Sev = 'High' }
    @{ Right = 'SeEnableDelegationPrivilege'; Rule = '2.2.21'; Expect = @(); Dc = @('S-1-5-32-544'); Sev = 'High' }
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
    @{ Right = 'SeSyncAgentPrivilege'; ServerRule = '2.2.48'; Dc = @(); Sev = 'Medium' }
)
# Deny rights: principals that must be listed.
$script:CisDenyRights = @(
    @{ Right = 'SeDenyNetworkLogonRight'; Rule = '2.2.16'; Need = @('S-1-5-32-546', 'S-1-5-113'); Dc = @('S-1-5-32-546'); Ms = @('S-1-5-32-546', 'S-1-5-114') }
    @{ Right = 'SeDenyBatchLogonRight'; Rule = '2.2.17'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyServiceLogonRight'; Rule = '2.2.18'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyInteractiveLogonRight'; Rule = '2.2.19'; Need = @('S-1-5-32-546') }
    @{ Right = 'SeDenyRemoteInteractiveLogonRight'; Rule = '2.2.20'; Need = @('S-1-5-32-546', 'S-1-5-113'); Dc = @('S-1-5-32-546') }
)
# The expected principals of a user-right spec for this host's role ($null: not judged on this role).
function Get-UserRightExpect {
    param($Spec, [string]$Role, [string]$Field = 'Expect')
    if ($Role -eq 'dc' -and $Spec.ContainsKey('Dc')) { return , @($Spec.Dc) }
    if ($Role -eq 'server' -and $Spec.ContainsKey('Ms')) { return , @($Spec.Ms) }
    if ($Spec.ContainsKey($Field)) { return , @($Spec[$Field]) }
    return $null
}
$script:PrincipalLabels = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE'; 'S-1-5-6' = 'SERVICE'
    'S-1-5-113' = 'Local account'; 'S-1-5-114' = 'Local account and member of Administrators'; 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests'; 'S-1-5-9' = 'ENTERPRISE DOMAIN CONTROLLERS'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-551' = 'Backup Operators'; 'S-1-5-32-555' = 'Remote Desktop Users'
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
            $expect = Get-UserRightExpect -Spec $spec -Role $role
            if ($null -eq $expect) { continue }
            $holders = $pr.($spec.Right)
            if ($null -eq $holders -and -not ($pr.PSObject.Properties.Name -contains $spec.Right)) { continue }
            $extra = @(@($holders) | Where-Object { $_ -and ($expect -notcontains "$_") })
            if ($extra.Count -gt 0) {
                $who = ($extra | ForEach-Object { Get-PrincipalLabel "$_" }) -join ', '
                $want = if ($expect.Count -eq 0) { 'no one' } else { ($expect | ForEach-Object { Get-PrincipalLabel $_ }) -join ', ' }
                $held = (@($holders) | Where-Object { $_ } | ForEach-Object { Get-PrincipalLabel "$_" }) -join ', '
                if ($spec.ServerRule) { Add-Finding -Type 'user_rights_excessive' -Object "right: $($spec.Right)" -Severity $spec.Sev -ServerCis $spec.ServerRule -Found $held -Expected $want -Detail "Also held by $who ({cis} expects $want)." }
                else { Add-Finding -Type 'user_rights_excessive' -Object "right: $($spec.Right)" -Severity $spec.Sev -Found $held -Expected $want -Detail "Also held by $who (CIS $($spec.Rule) expects $want)." }
            }
        }
    }
    if ($pr -and (& $can 'deny_logon_rights_missing')) {
        foreach ($spec in $script:CisDenyRights) {
            $need = Get-UserRightExpect -Spec $spec -Role $role -Field 'Need'
            if (-not ($pr.PSObject.Properties.Name -contains $spec.Right)) { $holders = @() } else { $holders = @($pr.($spec.Right)) }
            $missing = @($need | Where-Object { $holders -notcontains $_ })
            if ($missing.Count -gt 0) {
                $listed = (@($holders) | Where-Object { $_ } | ForEach-Object { Get-PrincipalLabel "$_" }) -join ', '
                Add-Finding -Type 'deny_logon_rights_missing' -Object "right: $($spec.Right)" -Found $(if ($listed) { $listed } else { 'no one' }) -Expected "at least $(($need | ForEach-Object { Get-PrincipalLabel $_ }) -join ', ')" -Detail "Missing: $(($missing | ForEach-Object { Get-PrincipalLabel $_ }) -join ', ') (CIS $($spec.Rule))."
            }
        }
    }
}
# Well-known EDR and endpoint protection products, found by the name of their main Windows service
# or by the display name of a service. The names come from the vendors' own documentation and
# common practice. A product that is missing here can still be counted with -ExtraEdrServices.
# OnboardOnly: the service exists on every machine and only means "installed" once it runs or starts
# automatically (the Defender for Endpoint "Sense" service is there, stopped, even if never onboarded).
$script:EdrProducts = @(
    @{ Key = 'CrowdStrike'; Name = 'CrowdStrike Falcon'; Services = @('CSFalconService'); Display = 'CrowdStrike|Falcon Sensor' }
    @{ Key = 'SentinelOne'; Name = 'SentinelOne'; Services = @('SentinelAgent'); Display = 'SentinelOne|Sentinel Agent' }
    @{ Key = 'DefenderForEndpoint'; Name = 'Microsoft Defender for Endpoint'; Services = @('Sense'); Display = 'Advanced Threat Protection'; OnboardOnly = $true }
    @{ Key = 'CarbonBlack'; Name = 'VMware Carbon Black'; Services = @('CbDefense', 'CarbonBlack'); Display = 'Carbon Black' }
    @{ Key = 'CortexXDR'; Name = 'Palo Alto Cortex XDR'; Services = @('cyserver', 'CyveraService'); Display = 'Cortex XDR|Cyvera' }
    @{ Key = 'Sophos'; Name = 'Sophos Intercept X'; Services = @('SEDService'); Display = 'Sophos Endpoint Defense|Sophos Intercept' }
    @{ Key = 'TrendMicro'; Name = 'Trend Micro Apex One / Deep Security'; Services = @('ntrtscan', 'ds_agent'); Display = 'Trend Micro (Apex One|Security Agent|Deep Security)' }
    @{ Key = 'Trellix'; Name = 'Trellix / FireEye / McAfee ENS'; Services = @('xagt', 'mfefire'); Display = 'FireEye Endpoint|Trellix' }
    @{ Key = 'ESET'; Name = 'ESET'; Services = @('ekrn'); Display = '^ESET' }
    @{ Key = 'Symantec'; Name = 'Symantec / Broadcom Endpoint Protection'; Services = @('SepMasterService'); Display = 'Symantec Endpoint Protection|Broadcom Endpoint' }
    @{ Key = 'Elastic'; Name = 'Elastic Defend'; Services = @('ElasticEndpoint'); Display = 'Elastic Endpoint|Elastic Defend' }
    @{ Key = 'Cybereason'; Name = 'Cybereason'; Services = @('CybereasonActiveProbe'); Display = 'Cybereason' }
    @{ Key = 'Cylance'; Name = 'Cylance'; Services = @('CylanceSvc'); Display = 'Cylance' }
    @{ Key = 'Bitdefender'; Name = 'Bitdefender GravityZone'; Services = @('EPSecurityService'); Display = 'Bitdefender Endpoint Security' }
    @{ Key = 'Huntress'; Name = 'Huntress'; Services = @('HuntressAgent'); Display = 'Huntress' }
)

# The EDR agents a host has, from its list of services. Each entry has a Key, a Name, a State (running
# or stopped) and the services that matched. Nothing is returned if the service list is missing.
function Get-EdrInventory {
    param($Snapshot, [string[]]$ExtraServices = @())
    $svcs = @($Snapshot.services | Where-Object { $_ })
    if ($svcs.Count -eq 0) { return }
    $out = New-Object System.Collections.Generic.List[object]
    $products = @($script:EdrProducts)
    foreach ($x in @($ExtraServices | Where-Object { $_ })) { $products += @{ Key = "$x"; Name = "$x"; Services = @("$x"); Display = '' } }
    foreach ($pr in $products) {
        $hits = @($svcs | Where-Object {
                $n = "$($_.name)"; $d = "$($_.displayName)"
                (@($pr.Services) | Where-Object { $_ -ieq $n }).Count -gt 0 -or ($pr.Display -and $d -match $pr.Display)
            })
        if ($hits.Count -eq 0) { continue }
        $running = @($hits | Where-Object { "$($_.state)" -eq 'Running' })
        if ($pr.OnboardOnly -and $running.Count -eq 0 -and @($hits | Where-Object { "$($_.startMode)" -eq 'Auto' }).Count -eq 0) { continue }
        $out.Add([PSCustomObject]@{
                Key      = $pr.Key
                Name     = $pr.Name
                State    = $(if ($running.Count -gt 0) { 'running' } else { 'stopped' })
                Services = @($hits | ForEach-Object { "$($_.name)" })
                Detail   = (@($hits | ForEach-Object { "$($_.name) ($($_.state), start mode $($_.startMode))" }) -join '; ')
            })
    }
    return $out.ToArray()
}

function Invoke-EdrChecks {
    param($S, $Config, $can, $role)
    if (@($S.services | Where-Object { $_ }).Count -eq 0) { return }
    $inv = @(Get-EdrInventory -Snapshot $S -ExtraServices @($Config.ExtraEdrServices))
    foreach ($p in @($inv | Where-Object { $_.State -ne 'running' })) {
        if (& $can 'edr_agent_stopped') { Add-Finding -Type 'edr_agent_stopped' -Object "agent: $($p.Name)" -Detail "Not running: $($p.Detail)." }
    }
    $expected = @($Config.ExpectedEdr | Where-Object { $_ })
    if ($expected.Count -gt 0) {
        foreach ($e in $expected) {
            # A known product (by key or name), or else any service whose name or display name contains the text.
            $known = @($script:EdrProducts | Where-Object { $_.Key -ieq "$e" -or $_.Name -like "*$e*" })
            $found = if ($known.Count -gt 0) { @($inv | Where-Object { $k = $_.Key; @($known | Where-Object { $_.Key -eq $k }).Count -gt 0 }).Count -gt 0 }
            else { @($S.services | Where-Object { "$($_.name)" -like "*$e*" -or "$($_.displayName)" -like "*$e*" }).Count -gt 0 }
            if (-not $found -and (& $can 'edr_expected_missing')) { Add-Finding -Type 'edr_expected_missing' -Object "expected: $e" -Detail "No service of $(if ($known.Count -gt 0) { $known[0].Name } else { "'$e'" }) among the $(@($S.services).Count) services of this host." }
        }
    }
    elseif ($inv.Count -eq 0 -and (& $can 'edr_not_found')) {
        Add-Finding -Type 'edr_not_found' -Object 'EDR agent' -Severity $(if ($role -eq 'workstation') { 'Low' } else { 'Medium' }) -Detail "No service of a known EDR or endpoint protection product among the $(@($S.services).Count) services of this host (Microsoft Defender Antivirus alone is not counted)."
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
    # The score of a host: one weight per triggered check at its worst severity (Critical 20, High 8,
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
