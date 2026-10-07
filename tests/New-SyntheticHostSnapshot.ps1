<#
.SYNOPSIS
    Writes synthetic HostBadger snapshots for tests and demos. No real host
    data: names, SIDs and paths are made up.
.PARAMETER Scenario
    weak      a neglected domain workstation: triggers nearly every check
    hardened  a well configured member server: two Low findings (built-in
              Administrator under LAPS, a server admin group)
    laptop    a managed laptop: TPM-only BitLocker, Windows support ending
              soon, a narrow Defender exclusion
    dc        a domain controller with the DC-only problems
    partial   collected as a standard user, Defender in passive mode, ACLs
              skipped: shows the "not evaluated" handling
.PARAMETER OutFile
    Where to write the JSON.
.PARAMETER CollectedAtUtc
    Collection time (default 2026-10-01T08:00:00Z, so ages are stable).
#>
param(
    [ValidateSet('weak', 'hardened', 'laptop', 'dc', 'partial')][string]$Scenario = 'weak',
    [Parameter(Mandatory)][string]$OutFile,
    [string]$CollectedAtUtc = '2026-10-01T08:00:00Z'
)

$domainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
$machineSid = @{ weak = 'S-1-5-21-4000000001-4000000002-4000000003'; hardened = 'S-1-5-21-5000000001-5000000002-5000000003'
    laptop = 'S-1-5-21-7000000001-7000000002-7000000003'; dc = $domainSid; partial = 'S-1-5-21-6000000001-6000000002-6000000003' }[$Scenario]
$name = @{ weak = 'WKS-ACCT-017'; hardened = 'SRV-APP-02'; laptop = 'LT-SALES-112'; dc = 'DC01'; partial = 'WKS-HR-004' }[$Scenario]
$role = @{ weak = 'workstation'; hardened = 'server'; laptop = 'workstation'; dc = 'dc'; partial = 'workstation' }[$Scenario]

function Svc([string]$n, [string]$path, [string]$exe, [string]$account = 'LocalSystem', [string]$state = 'Running', $writable = @()) {
    [ordered]@{ name = $n; displayName = $n; startMode = 'Auto'; state = $state; account = $account; pathName = $path; executable = $exe; writableBy = @($writable) }
}
function W([string]$scope, [string]$sid, [string]$rights = 'Modify, Synchronize') { [ordered]@{ scope = $scope; sid = $sid; rights = $rights } }
function Audit([string]$guid, [int]$value, [string]$n) { [ordered]@{ name = $n; guid = $guid; inclusion = ''; value = $value } }

$allAudit = @(
    @('0cce923f-69ae-11d9-bed3-505054503030', 'Credential Validation'), @('0cce9242-69ae-11d9-bed3-505054503030', 'Kerberos Authentication Service'),
    @('0cce9240-69ae-11d9-bed3-505054503030', 'Kerberos Service Ticket Operations'), @('0cce9237-69ae-11d9-bed3-505054503030', 'Security Group Management'),
    @('0cce9235-69ae-11d9-bed3-505054503030', 'User Account Management'), @('0cce923c-69ae-11d9-bed3-505054503030', 'Directory Service Changes'),
    @('0cce922b-69ae-11d9-bed3-505054503030', 'Process Creation'), @('0cce9215-69ae-11d9-bed3-505054503030', 'Logon'),
    @('0cce9217-69ae-11d9-bed3-505054503030', 'Account Lockout'), @('0cce921b-69ae-11d9-bed3-505054503030', 'Special Logon'),
    @('0cce9227-69ae-11d9-bed3-505054503030', 'Other Object Access Events'), @('0cce922f-69ae-11d9-bed3-505054503030', 'Audit Policy Change'),
    @('0cce9230-69ae-11d9-bed3-505054503030', 'Authentication Policy Change'), @('0cce9228-69ae-11d9-bed3-505054503030', 'Sensitive Privilege Use'),
    @('0cce9211-69ae-11d9-bed3-505054503030', 'Security System Extension'), @('0cce9212-69ae-11d9-bed3-505054503030', 'System Integrity')
)
$fullAudit = @($allAudit | ForEach-Object { Audit $_[0] 3 $_[1] })
$standardAsr = @(
    [ordered]@{ id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; action = 1 }, [ordered]@{ id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; action = 1 },
    [ordered]@{ id = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; action = 1 })
$baseServices = @(
    (Svc 'Dnscache' 'C:\Windows\system32\svchost.exe -k NetworkService -p' 'C:\Windows\system32\svchost.exe' 'NT AUTHORITY\NetworkService'),
    (Svc 'CSFalconService' '"C:\Program Files\CrowdStrike\CSFalconService.exe"' 'C:\Program Files\CrowdStrike\CSFalconService.exe'),
    (Svc 'Spooler' 'C:\Windows\System32\spoolsv.exe' 'C:\Windows\System32\spoolsv.exe' 'LocalSystem' $(if ($Scenario -eq 'hardened') { 'Stopped' } else { 'Running' }))
)

# CIS-conformant local policy: who holds each right (SIDs), and the account policy.
$A = 'S-1-5-32-544'; $RDU = 'S-1-5-32-555'; $USR = 'S-1-5-32-545'; $GST = 'S-1-5-32-546'; $LOCACC = 'S-1-5-113'
$cleanRights = [ordered]@{
    SeTrustedCredManAccessPrivilege = @(); SeNetworkLogonRight = @($A, $RDU); SeTcbPrivilege = @(); SeInteractiveLogonRight = @($A, $USR)
    SeRemoteInteractiveLogonRight = @($A, $RDU); SeBackupPrivilege = @($A); SeCreatePagefilePrivilege = @($A); SeCreateTokenPrivilege = @()
    SeCreatePermanentPrivilege = @(); SeDebugPrivilege = @($A); SeEnableDelegationPrivilege = @(); SeRemoteShutdownPrivilege = @($A)
    SeLoadDriverPrivilege = @($A); SeLockMemoryPrivilege = @(); SeSecurityPrivilege = @($A); SeRelabelPrivilege = @()
    SeSystemEnvironmentPrivilege = @($A); SeManageVolumePrivilege = @($A); SeProfileSingleProcessPrivilege = @($A); SeRestorePrivilege = @($A)
    SeTakeOwnershipPrivilege = @($A)
    SeDenyNetworkLogonRight = @($GST, $LOCACC); SeDenyBatchLogonRight = @($GST); SeDenyServiceLogonRight = @($GST)
    SeDenyInteractiveLogonRight = @($GST); SeDenyRemoteInteractiveLogonRight = @($GST, $LOCACC)
}

# ------------------------------------------------------------------ hardened baseline
$s = [ordered]@{
    meta                 = [ordered]@{
        tool = 'HostBadger'; kind = 'host'; computerName = $name; schemaVersion = 1; collectorVersion = '1.0'; synthetic = $true
        collectedAtUtc = $CollectedAtUtc; collectedBy = 'NT AUTHORITY\SYSTEM'; runningAsSystem = $true; runningAsAdmin = $true; psVersion = '5.1.20348.2849'
        options = [ordered]@{ skipAcl = $false }
        sectionsCollected = @('host', 'patches', 'defender', 'bitlocker', 'boot', 'credentialProtection', 'network', 'remoteAccess', 'localAccounts', 'laps', 'uac', 'powershell', 'audit', 'securityPolicy', 'hardening', 'services', 'scheduledTasks', 'autoruns')
        collectionErrors = @()
    }
    host                 = [ordered]@{
        name = $name; dnsDomain = 'corp.example'; partOfDomain = $true; domainRole = @{ workstation = 1; server = 3; dc = 5 }[$role]; role = $role; machineSid = $machineSid
        manufacturer = 'Contoso'; model = 'Virtual'; hypervisor = $true
        os = [ordered]@{ caption = 'Microsoft Windows Server 2022 Standard'; version = '10.0.20348'; build = 20348; ubr = 4171; displayVersion = '21H2'; editionId = 'ServerStandard'; productType = 3; architecture = '64-bit'; installDateUtc = '2024-02-01T10:00:00Z'; lastBootUtc = '2026-09-20T03:00:00Z' }
    }
    patches              = [ordered]@{ hotfixes = @([ordered]@{ id = 'KB5065306'; description = 'Security Update'; installedOnUtc = '2026-09-10T00:00:00Z' }); lastUpdateInstalledUtc = '2026-09-10T03:12:00Z' }
    defender             = [ordered]@{ present = $true; amRunningMode = 'Normal'; amServiceEnabled = $true; antivirusEnabled = $true; realTimeProtectionEnabled = $true; behaviorMonitorEnabled = $true; ioavProtectionEnabled = $true; isTamperProtected = $true; signatureUpdatedUtc = '2026-09-30T22:00:00Z'; exclusionsReadable = $true; exclusionPaths = @(); exclusionExtensions = @(); exclusionProcesses = @(); asrRules = $standardAsr; puaProtection = 1; networkProtection = 1 }
    bitlocker            = [ordered]@{ featureInstalled = $true; volumes = @([ordered]@{ mountPoint = 'C:'; volumeType = 'OperatingSystem'; protectionStatus = 'On'; volumeStatus = 'FullyEncrypted'; encryptionMethod = 'XtsAes256'; keyProtectors = @('Tpm', 'RecoveryPassword') }) }
    boot                 = [ordered]@{ secureBootEnabled = $true; firmware = 'UEFI' }
    credentialProtection = [ordered]@{ runAsPPL = 2; lsaCfgFlags = 1; credentialGuardRunning = $true; hvciRunning = $true; vbsStatus = 2; wdigestUseLogonCredential = 0; cachedLogonsCount = '1'; lmCompatibilityLevel = 5; noLmHash = 1; restrictAnonymous = 1; restrictAnonymousSam = 1 }
    network              = [ordered]@{
        smb1ServerEnabled = $false; smbServerSigningRequired = $true; smbClientSigningRequired = $true; llmnrPolicyEnableMulticast = 0
        netbios = @([ordered]@{ adapter = 'vmxnet3 Ethernet Adapter'; tcpipNetbiosOptions = 2 })
        firewallProfiles = @('Domain', 'Private', 'Public' | ForEach-Object { [ordered]@{ name = $_; enabled = $true; defaultInboundAction = 'Block'; logBlocked = 'True' } })
        listening = @([ordered]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 445; process = 'System' }, [ordered]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 443; process = 'w3wp' }, [ordered]@{ protocol = 'tcp'; address = '127.0.0.1'; port = 6379; process = 'redis-server' })
    }
    remoteAccess         = [ordered]@{ rdpEnabled = $true; rdpNlaRequired = $true }
    localAccounts        = [ordered]@{
        users = @(
            [ordered]@{ name = 'LocalAdm'; sid = "$machineSid-500"; enabled = $true; passwordRequired = $true; passwordExpires = $false; lastLogonUtc = $null; passwordLastSetUtc = '2026-09-25T00:00:00Z' },
            [ordered]@{ name = 'Guest'; sid = "$machineSid-501"; enabled = $false; passwordRequired = $false; passwordExpires = $false; lastLogonUtc = $null; passwordLastSetUtc = $null })
        administrators = @([ordered]@{ path = "$name/LocalAdm"; sid = "$machineSid-500"; class = 'User' }, [ordered]@{ path = 'CORP/Domain Admins'; sid = "$domainSid-512"; class = 'Group' }, [ordered]@{ path = 'CORP/Server Admins'; sid = "$domainSid-1105"; class = 'Group' })
        administratorsReadable = $true
    }
    laps                 = [ordered]@{ windowsLapsBackupDirectory = 2; legacyLapsEnabled = $null; legacyLapsCseInstalled = $false }
    uac                  = [ordered]@{ enableLua = 1; consentPromptBehaviorAdmin = 2; localAccountTokenFilterPolicy = $null; filterAdministratorToken = 1; alwaysInstallElevated = $null }
    powershell           = [ordered]@{ scriptBlockLogging = 1; moduleLogging = 1; transcription = 1; v2EngineVersion = '' }
    audit                = [ordered]@{ processCreationIncludeCmdLine = 1; securityLogMaxSizeBytes = 1073741824; subcategories = $fullAudit }
    securityPolicy       = [ordered]@{
        systemAccess = [ordered]@{ PasswordHistorySize = 24; MaximumPasswordAge = 365; MinimumPasswordAge = 1; MinimumPasswordLength = 14; PasswordComplexity = 1; ClearTextPassword = 0
            LockoutBadCount = 5; LockoutDuration = 15; ResetLockoutCount = 15; AllowAdministratorLockout = 1 }
        privilegeRights = $cleanRights
    }
    hardening            = [ordered]@{
        smbInsecureGuestAuth = 0; ldapClientIntegrity = 1; ntlmMinClientSec = 537395200; ntlmMinServerSec = 537395200
        allowNullSessionFallback = 0; allowOnlineId = 0; everyoneIncludesAnonymous = 0; limitBlankPasswordUse = 1; forceGuest = 0
        enablePlainTextPassword = 0; nullSessionPipesCount = 0; nullSessionSharesCount = 0; restrictNullSessAccess = 1
        netlogon = [ordered]@{ requireSignOrSeal = 1; sealSecureChannel = 1; signSecureChannel = 1; requireStrongKey = 1; disablePasswordChange = 0; maximumPasswordAge = 30 }
        winrm = [ordered]@{ clientAllowBasic = 0; clientAllowUnencryptedTraffic = 0; clientAllowDigest = 0; serviceAllowBasic = 0; serviceAllowUnencryptedTraffic = 0 }
        rdpPolicy = [ordered]@{ securityLayer = 2; minEncryptionLevel = 3; promptForPassword = 1; encryptRpcTraffic = 1; disableDriveRedirection = 1 }
        explorer = [ordered]@{ noDriveTypeAutoRun = 255; noAutorun = 1; noAutoplayForNonVolume = 1 }
        winlogon = [ordered]@{ autoAdminLogon = '0'; defaultPasswordPresent = $false }
        interactiveLogon = [ordered]@{ inactivityTimeoutSecs = 900; legalNoticeTextSet = $true; legalNoticeCaptionSet = $true; dontDisplayLastUserName = 1; disableCad = 0 }
        uacExtra = [ordered]@{ enableInstallerDetection = 1; enableSecureUiaPaths = 1; promptOnSecureDesktop = 1; enableVirtualization = 1 }
        noAutoUpdate = 0; enableSmartScreen = 1
        eventLogs = @([ordered]@{ name = 'Application'; maxSizeBytes = 33554432 }, [ordered]@{ name = 'System'; maxSizeBytes = 33554432 })
        mrxsmb10Start = 4; disableExceptionChainValidation = 0; safeDllSearchMode = 1
        ipStack = [ordered]@{ disableIpSourceRoutingV4 = 2; disableIpSourceRoutingV6 = 2; enableIcmpRedirect = 0 }
    }
    services             = $baseServices
    scheduledTasks       = @([ordered]@{ path = '\'; name = 'Backup'; state = 'Ready'; userId = 'SYSTEM'; groupId = ''; runLevel = 'Highest'; author = 'CORP\backupadm'
            actions = @([ordered]@{ execute = 'C:\Program Files\Backup\agent.exe'; arguments = '-p ***'; executable = 'C:\Program Files\Backup\agent.exe'; writableBy = @() }) })
    autoruns             = @([ordered]@{ location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; name = 'SecurityHealth'; command = '%windir%\system32\SecurityHealthSystray.exe'; executable = 'C:\Windows\system32\SecurityHealthSystray.exe'; writableBy = @() })
}

# ------------------------------------------------------------------ scenarios
switch ($Scenario) {
    'hardened' { }
    'laptop' {
        # Windows 11 23H2 Enterprise: support ends 2026-11-10, 40 days after
        # the default collection date.
        $s.host.os = [ordered]@{ caption = 'Microsoft Windows 11 Enterprise'; version = '10.0.22631'; build = 22631; ubr = 5909; displayVersion = '23H2'; editionId = 'Enterprise'; productType = 1; architecture = '64-bit'; installDateUtc = '2024-03-01T09:00:00Z'; lastBootUtc = '2026-09-29T07:00:00Z' }
        $s.credentialProtection.cachedLogonsCount = '4'
        $s.remoteAccess.rdpEnabled = $false
        $s.defender.exclusionPaths = @('C:\Program Files\Contoso CAD\Projects')
        $s.localAccounts.users[0].enabled = $false
        $s.localAccounts.administrators = @([ordered]@{ path = "$name/LocalAdm"; sid = "$machineSid-500"; class = 'User' }, [ordered]@{ path = 'CORP/Domain Admins'; sid = "$domainSid-512"; class = 'Group' }, [ordered]@{ path = 'AzureAD/Global Administrator'; sid = 'S-1-12-1-1111111111-2222222222-3333333333-4444444444'; class = 'Group' })
        $s.network.listening = @([ordered]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 445; process = 'System' })
        $s.services = @($baseServices)
    }
    'weak' {
        $s.host.os = [ordered]@{ caption = 'Microsoft Windows 10 Pro'; version = '10.0.19045'; build = 19045; ubr = 6093; displayVersion = '22H2'; editionId = 'Professional'; productType = 1; architecture = '64-bit'; installDateUtc = '2020-03-02T09:00:00Z'; lastBootUtc = '2026-06-01T07:00:00Z' }
        $s.patches = [ordered]@{ hotfixes = @([ordered]@{ id = 'KB5063709'; description = 'Security Update'; installedOnUtc = '2026-05-14T00:00:00Z' }); lastUpdateInstalledUtc = '2026-05-14T10:00:00Z' }
        $s.defender.realTimeProtectionEnabled = $false
        $s.defender.isTamperProtected = $false
        $s.defender.signatureUpdatedUtc = '2026-08-20T10:00:00Z'
        $s.defender.exclusionPaths = @('C:\Users\Public\Tools', 'C:\Program Files\Contoso ERP\Cache')
        $s.defender.exclusionExtensions = @('ps1')
        $s.defender.exclusionProcesses = @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        $s.defender.asrRules = @([ordered]@{ id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; action = 2 })
        $s.bitlocker.volumes = @(
            [ordered]@{ mountPoint = 'C:'; volumeType = 'OperatingSystem'; protectionStatus = 'Off'; volumeStatus = 'FullyDecrypted'; encryptionMethod = 'None'; keyProtectors = @() },
            [ordered]@{ mountPoint = 'D:'; volumeType = 'Data'; protectionStatus = 'Off'; volumeStatus = 'FullyDecrypted'; encryptionMethod = 'None'; keyProtectors = @() })
        $s.boot = [ordered]@{ secureBootEnabled = $null; firmware = 'BIOS' }
        $s.credentialProtection = [ordered]@{ runAsPPL = $null; lsaCfgFlags = $null; credentialGuardRunning = $false; hvciRunning = $false; vbsStatus = 0; wdigestUseLogonCredential = 1; cachedLogonsCount = '25'; lmCompatibilityLevel = 2; noLmHash = 0; restrictAnonymous = 0; restrictAnonymousSam = 0 }
        $s.network.smb1ServerEnabled = $true
        $s.network.smbServerSigningRequired = $false
        $s.network.smbClientSigningRequired = $false
        $s.network.llmnrPolicyEnableMulticast = $null
        $s.network.netbios = @([ordered]@{ adapter = 'Intel(R) Ethernet Connection I219-LM'; tcpipNetbiosOptions = 0 }, [ordered]@{ adapter = 'Intel(R) Wi-Fi 6 AX201'; tcpipNetbiosOptions = 1 })
        $s.network.firewallProfiles = @(
            [ordered]@{ name = 'Domain'; enabled = $true; defaultInboundAction = 'Allow'; logBlocked = 'False' },
            [ordered]@{ name = 'Private'; enabled = $true; defaultInboundAction = 'Block'; logBlocked = 'False' },
            [ordered]@{ name = 'Public'; enabled = $false; defaultInboundAction = 'Block'; logBlocked = 'False' })
        $s.network.listening = @(
            [ordered]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 5900; process = 'tvnserver' }, [ordered]@{ protocol = 'tcp'; address = '::'; port = 5900; process = 'tvnserver' },
            [ordered]@{ protocol = 'tcp'; address = '0.0.0.0'; port = 5985; process = 'System' }, [ordered]@{ protocol = 'tcp'; address = '127.0.0.1'; port = 3306; process = 'mysqld' },
            [ordered]@{ protocol = 'udp'; address = '0.0.0.0'; port = 161; process = 'snmp' })
        $s.remoteAccess = [ordered]@{ rdpEnabled = $true; rdpNlaRequired = $false }
        $s.localAccounts.users = @(
            [ordered]@{ name = 'Administrator'; sid = "$machineSid-500"; enabled = $true; passwordRequired = $true; passwordExpires = $false; lastLogonUtc = '2025-01-10T09:00:00Z'; passwordLastSetUtc = '2020-03-02T09:00:00Z' },
            [ordered]@{ name = 'Guest'; sid = "$machineSid-501"; enabled = $true; passwordRequired = $false; passwordExpires = $false; lastLogonUtc = $null; passwordLastSetUtc = $null },
            [ordered]@{ name = 'support'; sid = "$machineSid-1001"; enabled = $true; passwordRequired = $false; passwordExpires = $false; lastLogonUtc = '2026-09-01T09:00:00Z'; passwordLastSetUtc = '2021-06-01T09:00:00Z' })
        $s.localAccounts.administrators = @(
            [ordered]@{ path = "$name/Administrator"; sid = "$machineSid-500"; class = 'User' }, [ordered]@{ path = "$name/support"; sid = "$machineSid-1001"; class = 'User' },
            [ordered]@{ path = 'CORP/Domain Admins'; sid = "$domainSid-512"; class = 'Group' }, [ordered]@{ path = 'CORP/jsmith'; sid = "$domainSid-1342"; class = 'User' },
            [ordered]@{ path = 'CORP/Helpdesk'; sid = "$domainSid-1201"; class = 'Group' })
        $s.laps = [ordered]@{ windowsLapsBackupDirectory = $null; legacyLapsEnabled = $null; legacyLapsCseInstalled = $false }
        $s.uac = [ordered]@{ enableLua = 0; consentPromptBehaviorAdmin = 0; localAccountTokenFilterPolicy = 1; filterAdministratorToken = 0; alwaysInstallElevated = 1 }
        $s.powershell = [ordered]@{ scriptBlockLogging = $null; moduleLogging = $null; transcription = $null; v2EngineVersion = '2.0' }
        $s.audit = [ordered]@{ processCreationIncludeCmdLine = $null; securityLogMaxSizeBytes = 20971520
            subcategories = @($allAudit | ForEach-Object { $v = if ($_[1] -in @('Logon', 'Credential Validation')) { 1 } else { 0 }; Audit $_[0] $v $_[1] }) }
        $s.defender.puaProtection = 0
        $s.defender.networkProtection = 0
        $s.credentialProtection.restrictAnonymous = 0
        $s.powershell.transcription = $null
        $sa = $s.securityPolicy.systemAccess
        $sa.PasswordHistorySize = 0; $sa.MaximumPasswordAge = -1; $sa.MinimumPasswordAge = 0; $sa.MinimumPasswordLength = 0; $sa.PasswordComplexity = 0; $sa.ClearTextPassword = 1
        $sa.LockoutBadCount = 10; $sa.LockoutDuration = 5; $sa.ResetLockoutCount = 5
        $pr = $s.securityPolicy.privilegeRights
        $pr.SeDebugPrivilege = @($A, $USR); $pr.SeTcbPrivilege = @($A); $pr.SeNetworkLogonRight = @($A, $RDU, 'S-1-1-0', $USR); $pr.SeBackupPrivilege = @($A, 'S-1-5-32-551')
        $pr.SeDenyNetworkLogonRight = @(); $pr.SeDenyRemoteInteractiveLogonRight = @($GST)
        $hd = $s.hardening
        $hd.smbInsecureGuestAuth = 1; $hd.ldapClientIntegrity = 0; $hd.ntlmMinClientSec = 536870912; $hd.ntlmMinServerSec = 536870912
        $hd.allowNullSessionFallback = 1; $hd.allowOnlineId = 1; $hd.everyoneIncludesAnonymous = 1; $hd.limitBlankPasswordUse = 0; $hd.forceGuest = 1
        $hd.enablePlainTextPassword = 1; $hd.nullSessionPipesCount = 1; $hd.nullSessionSharesCount = 2; $hd.restrictNullSessAccess = 0
        $hd.netlogon = [ordered]@{ requireSignOrSeal = 0; sealSecureChannel = 0; signSecureChannel = 0; requireStrongKey = 0; disablePasswordChange = 1; maximumPasswordAge = 90 }
        $hd.winrm = [ordered]@{ clientAllowBasic = 1; clientAllowUnencryptedTraffic = 1; clientAllowDigest = 1; serviceAllowBasic = 1; serviceAllowUnencryptedTraffic = 1 }
        $hd.rdpPolicy = [ordered]@{ securityLayer = 0; minEncryptionLevel = 2; promptForPassword = 0; encryptRpcTraffic = 0; disableDriveRedirection = $null }
        $hd.explorer = [ordered]@{ noDriveTypeAutoRun = 145; noAutorun = $null; noAutoplayForNonVolume = $null }
        $hd.winlogon = [ordered]@{ autoAdminLogon = '1'; defaultPasswordPresent = $true }
        $hd.interactiveLogon = [ordered]@{ inactivityTimeoutSecs = $null; legalNoticeTextSet = $false; legalNoticeCaptionSet = $false; dontDisplayLastUserName = 0; disableCad = 1 }
        $hd.uacExtra = [ordered]@{ enableInstallerDetection = 0; enableSecureUiaPaths = 0; promptOnSecureDesktop = 0; enableVirtualization = 0 }
        $hd.noAutoUpdate = 1; $hd.enableSmartScreen = 0
        $hd.eventLogs = @([ordered]@{ name = 'Application'; maxSizeBytes = 20971520 }, [ordered]@{ name = 'System'; maxSizeBytes = 20971520 })
        $hd.mrxsmb10Start = 2; $hd.disableExceptionChainValidation = 1; $hd.safeDllSearchMode = 0
        $hd.ipStack = [ordered]@{ disableIpSourceRoutingV4 = 0; disableIpSourceRoutingV6 = 1; enableIcmpRedirect = 1 }
        # A neglected host with no EDR on it at all.
        $s.services = @($baseServices | Where-Object { $_.name -ne 'CSFalconService' }) + @(
            (Svc 'SSDPSRV' 'C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p' 'C:\Windows\system32\svchost.exe' 'NT AUTHORITY\LocalService'),
            (Svc 'XblAuthManager' 'C:\Windows\system32\svchost.exe -k netsvcs -p' 'C:\Windows\system32\svchost.exe'),
            (Svc 'LxssManager' 'C:\Windows\system32\svchost.exe -k LxssManagerUser -p' 'C:\Windows\system32\svchost.exe'),
            (Svc 'ContosoUpdater' 'C:\Program Files\Contoso Tools\Updater Service\updater.exe -service' 'C:\Program Files\Contoso Tools\Updater Service\updater.exe'),
            (Svc 'VendorAgent' '"C:\ProgramData\Vendor\agent.exe"' 'C:\ProgramData\Vendor\agent.exe' 'LocalSystem' 'Running' @((W 'file' 'S-1-5-11'), (W 'folder' 'S-1-5-32-545' 'Write'))),
            (Svc 'PrintHelper' '"C:\Tools\PrintHelper\helper.exe"' 'C:\Tools\PrintHelper\helper.exe' 'LocalSystem' 'Stopped' @((W 'folder' 'S-1-5-32-545' 'AppendData, Synchronize'))))
        $s.scheduledTasks = @(
            [ordered]@{ path = '\Contoso\'; name = 'Inventory'; state = 'Ready'; userId = 'SYSTEM'; groupId = ''; runLevel = 'Highest'; author = 'CORP\it'
                actions = @([ordered]@{ execute = 'C:\Users\Public\inventory.exe'; arguments = ''; executable = 'C:\Users\Public\inventory.exe'; writableBy = @((W 'file' 'S-1-1-0' 'FullControl')) }) },
            [ordered]@{ path = '\'; name = 'UserSync'; state = 'Ready'; userId = ''; groupId = 'Users'; runLevel = 'Limited'; author = 'CORP\it'
                actions = @([ordered]@{ execute = 'C:\Users\Public\sync.exe'; arguments = ''; executable = 'C:\Users\Public\sync.exe'; writableBy = @((W 'file' 'S-1-1-0' 'FullControl')) }) })
        $s.scheduledTasks += [ordered]@{ path = '\Microsoft\Windows\UpdateOrchestrator\'; name = 'Schedule Scan'; state = 'Ready'; userId = 'SYSTEM'; groupId = ''; runLevel = 'Highest'; author = 'Microsoft'
            actions = @([ordered]@{ execute = 'C:\Windows\system32\UsoClient.exe'; arguments = 'StartScan'; executable = 'C:\Windows\system32\UsoClient.exe'; writableBy = @() }) }
        $s.autoruns = @(
            [ordered]@{ location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; name = 'TrayHelper'; command = 'C:\ProgramData\TrayHelper\tray.exe'; executable = 'C:\ProgramData\TrayHelper\tray.exe'; writableBy = @((W 'file' 'S-1-5-32-545')) })
    }
    'dc' {
        $s.host.os.caption = 'Microsoft Windows Server 2016 Standard'
        $s.host.os.version = '10.0.14393'; $s.host.os.build = 14393; $s.host.os.ubr = 8422; $s.host.os.displayVersion = '1607'
        $s.credentialProtection.credentialGuardRunning = $false
        # The EDR agent is installed but its service is stopped.
        $s.services = @($baseServices | Where-Object { $_.name -ne 'CSFalconService' }) + @((Svc 'CSFalconService' '"C:\Program Files\CrowdStrike\CSFalconService.exe"' 'C:\Program Files\CrowdStrike\CSFalconService.exe' 'LocalSystem' 'Stopped'))
        $s.credentialProtection.cachedLogonsCount = '10'
        $s.network.smbServerSigningRequired = $false
        $s.localAccounts.users = @([ordered]@{ name = 'Administrator'; sid = "$domainSid-500"; enabled = $true; passwordRequired = $true; passwordExpires = $true; lastLogonUtc = '2026-09-30T09:00:00Z'; passwordLastSetUtc = '2026-08-01T09:00:00Z' })
        $s.localAccounts.administrators = @([ordered]@{ path = 'CORP/Administrator'; sid = "$domainSid-500"; class = 'User' }, [ordered]@{ path = 'CORP/Domain Admins'; sid = "$domainSid-512"; class = 'Group' })
        $s.audit.subcategories = @($allAudit | ForEach-Object { $v = if ($_[1] -like 'Kerberos*' -or $_[1] -eq 'Directory Service Changes') { 0 } else { 3 }; Audit $_[0] $v $_[1] })
    }
    'partial' {
        $s.meta.collectedBy = 'CORP\jdoe'; $s.meta.runningAsSystem = $false; $s.meta.runningAsAdmin = $false
        $s.meta.options.skipAcl = $true
        $s.meta.sectionsCollected = @('host', 'patches', 'defender', 'boot', 'credentialProtection', 'network', 'remoteAccess', 'localAccounts', 'laps', 'uac', 'powershell', 'hardening', 'services', 'scheduledTasks', 'autoruns')
        $s.meta.collectionErrors = @(
            [ordered]@{ section = 'defender.exclusions'; message = 'exclusions not readable (administrator or SYSTEM needed)' },
            [ordered]@{ section = 'bitlocker'; message = 'BitLocker status not readable: Access is denied' },
            [ordered]@{ section = 'audit'; message = 'auditpol failed (1314, administrator or SYSTEM needed)' },
            [ordered]@{ section = 'localAccounts.administrators'; message = 'Access is denied' },
            [ordered]@{ section = 'securityPolicy'; message = 'secedit failed (1, administrator or SYSTEM needed): Access is denied' })
        $s.host.os = [ordered]@{ caption = 'Microsoft Windows 11 Enterprise'; version = '10.0.26100'; build = 26100; ubr = 6584; displayVersion = '24H2'; editionId = 'Enterprise'; productType = 1; architecture = '64-bit'; installDateUtc = '2025-01-10T09:00:00Z'; lastBootUtc = '2026-09-28T07:00:00Z' }
        $s.defender = [ordered]@{ present = $true; amRunningMode = 'Passive Mode'; amServiceEnabled = $true; antivirusEnabled = $false; realTimeProtectionEnabled = $false; behaviorMonitorEnabled = $false; ioavProtectionEnabled = $false; isTamperProtected = $false; signatureUpdatedUtc = '2026-07-01T00:00:00Z'; exclusionsReadable = $false; exclusionPaths = @(); exclusionExtensions = @(); exclusionProcesses = @(); asrRules = @(); puaProtection = 0; networkProtection = 0 }
        $s.bitlocker = $null
        $s.audit = $null
        $s.securityPolicy = $null
        $s.credentialProtection.credentialGuardRunning = $null
        $s.credentialProtection.cachedLogonsCount = '4'
        $s.localAccounts.administrators = @()
        $s.localAccounts.administratorsReadable = $false
    }
}

$json = $s | ConvertTo-Json -Depth 10
$json = [regex]::Replace($json, '(?<=[^\\]"):\s*\{\s*\}', ': []')
$dir = Split-Path -Path $OutFile -Parent
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($OutFile), $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $Scenario snapshot ($name) to $OutFile"
