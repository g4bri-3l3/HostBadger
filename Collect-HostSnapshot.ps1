####################################################################################
# HostBadger collector: read-only snapshot of one Windows host's security posture
####################################################################################
<#
.SYNOPSIS
    Takes a read-only snapshot of the local Windows host's security settings
    and writes it as JSON (and a zip), for HostBadger.ps1 to analyze anywhere.

.DESCRIPTION
    One self-contained file, so it can be uploaded as a CrowdStrike Falcon
    cloud script (or to any EDR / SOAR that runs .ps1 files) and run on many
    endpoints through Real Time Response:

        runscript -CloudFile="Collect-HostSnapshot" -Timeout=600
        get C:\Windows\Temp\HostBadger\hostsnapshot_<host>_<time>.zip

    It only reads. That means registry values, CIM classes, the Defender,
    SMB, firewall, BitLocker, local account and scheduled task cmdlets, file
    ACLs, "auditpol /backup" and "secedit /export" (the last two write a
    temporary file that is deleted right away). It changes no setting, starts
    no process and opens no network connection. Test-HostBadgerSafety.ps1
    checks this claim against the code.

    It runs as SYSTEM under RTR, or as a local administrator. As a standard
    user it still runs, but some sections (Defender exclusions, BitLocker,
    the audit policy, the security policy, the security log) can't be read.
    Those failures are recorded in meta.collectionErrors, and the analyzer
    lists the checks that depend on them as "not evaluated", never as clean.

    Command lines of services, scheduled tasks and Run keys are kept, because
    the privilege escalation checks need them. Anything that looks like a
    password argument is masked first (-p, /password:, pwd=...).

.PARAMETER OutDir
    Where to write. Default C:\Windows\Temp\HostBadger when running elevated,
    otherwise %TEMP%\HostBadger.
.PARAMETER NoZip
    Keep only the JSON.
.PARAMETER SkipAcl
    Don't read file ACLs of service, task and Run key executables (faster on
    hosts with thousands of services; the "writable by users" checks are then
    not evaluated).
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [switch]$NoZip,
    [switch]$SkipAcl
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '1.0'
$script:SchemaVersion = 1
$script:Errors = New-Object System.Collections.Generic.List[object]
$script:Sections = New-Object System.Collections.Generic.List[string]

function Add-CollectionError {
    param([string]$Section, [string]$Message)
    $script:Errors.Add([ordered]@{ section = $Section; message = $Message })
    Write-Warning "[$Section] $Message"
}

function Invoke-Section {
    # Each section runs on its own, so one failure doesn't lose the whole snapshot.
    param([string]$Name, [scriptblock]$Body)
    try {
        $r = & $Body
        $script:Sections.Add($Name)
        return $r
    }
    catch {
        Add-CollectionError -Section $Name -Message $_.Exception.Message
        return $null
    }
}

function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try {
        $d = [datetime]$Value
        if ($d.Year -lt 1990) { return $null }
        return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    catch { return $null }
}

function Get-RegValue {
    # Returns $null when the key or the value isn't there.
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Get-RegSubkeyValues {
    # Every value of a key as name -> value (used for the Run keys).
    param([string]$Path)
    $out = @()
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($n in $item.GetValueNames()) {
            if ($n -eq '') { continue }
            $out += [ordered]@{ name = $n; value = "$($item.GetValue($n))" }
        }
    }
    catch { }
    return $out
}

function Protect-CommandLine {
    # Masks anything that looks like a password on a command line.
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?i)((?:^|\s)[-/](?:p|pw|pwd|pass|passwd|password|secret|token|key|apikey|api-key)(?:\s+|[:=]))("[^"]*"|''[^'']*''|\S+)', '$1***')
    $t = [regex]::Replace($t, '(?i)\b(password|passwd|pwd|secret|token|apikey|api_key)=("[^"]*"|[^\s;&]+)', '$1=***')
    return $t
}

function ConvertFrom-SecEditInf {
    # Turns the INF that "secedit /export" writes into data. The file is Unicode and its keys are in
    # English whatever the language of Windows. We keep only the account policy settings and the
    # user rights, and a right that nobody holds becomes an empty list.
    param([string[]]$Lines)
    $wanted = @('MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize',
        'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'ClearTextPassword', 'AllowAdministratorLockout')
    $access = [ordered]@{}
    $rights = [ordered]@{}
    $section = ''
    foreach ($raw in $Lines) {
        $line = "$raw".Trim().TrimStart([char]0xFEFF)
        if (-not $line -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($line -notmatch '^([^=]+?)\s*=\s*(.*)$') { continue }
        $key = $Matches[1].Trim(); $val = $Matches[2].Trim()
        if ($section -eq 'System Access' -and $wanted -contains $key) {
            $n = 0
            if ([int]::TryParse($val, [ref]$n)) { $access[$key] = $n }
        }
        elseif ($section -eq 'Privilege Rights' -and $key -match '^Se\w+$') {
            $list = @($val -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
            $rights[$key] = $list
        }
    }
    return [ordered]@{ systemAccess = $access; privilegeRights = $rights }
}

function Test-DefinitionUpdateTitle {
    # Defender definitions, the antimalware platform and the malware removal tool install every day
    # or every month, so they say nothing about whether Windows itself is patched.
    # Their titles are localized ("Aggiornamento dell'intelligence sulla sicurezza..."), but their
    # KB numbers are not: 2267602 for the Defender definitions, 4052623 for the platform and 890830
    # for the removal tool.
    param([string]$Title)
    return ("$Title" -match '(?<!\d)(2267602|4052623|890830)(?!\d)' -or "$Title" -match '(?i)security intelligence|definition update|antimalware platform|malicious software removal')
}

function Get-ExecutablePath {
    # Finds the program that a command line starts: the quoted path, or else everything up to ".exe"
    # (or the first space), with environment variables expanded.
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '(?i)^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|scr))(\s|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Principals that should never be able to write a program that SYSTEM or an administrator runs:
# Everyone, Users, Authenticated Users, Interactive, and the Domain Users and Domain Computers
# groups of any domain.
$script:LowPrivSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4', 'S-1-5-2', 'S-1-5-7')
function Test-LowPrivSid {
    param([string]$Sid)
    if ($script:LowPrivSids -contains $Sid) { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$')
}

# The permission bits that let someone change or replace a file, or add one to a folder: WriteData
# (add a file), AppendData (add a subfolder), Delete, ChangePermissions, TakeOwnership, and
# GENERIC_WRITE and GENERIC_ALL as they appear in inherit-only entries. We list the bits one by one
# because Modify and FullControl, used as masks, include the read bits, and then ReadAndExecute
# would match.
$script:WriteMask = [int64](0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
$script:AclCache = @{}

function Get-LowPrivWriters {
    # Who, among the low-privileged principals, can write the file or its folder. It only reads ACLs
    # (Get-Acl).
    param([string]$Path)
    # Return nothing rather than $null: @($null) would count as one empty writer.
    if ($SkipAcl -or -not $Path) { return }
    $key = $Path.ToLower()
    if ($script:AclCache.ContainsKey($key)) { return $script:AclCache[$key] }
    $result = @()
    foreach ($target in @(@{ Scope = 'file'; Path = $Path }, @{ Scope = 'folder'; Path = (Split-Path -Path $Path -Parent) })) {
        if (-not $target.Path -or -not (Test-Path -LiteralPath $target.Path)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $target.Path
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sid = $ace.IdentityReference.Value
                if (-not (Test-LowPrivSid $sid)) { continue }
                if (([int64]$ace.FileSystemRights -band $script:WriteMask) -eq 0) { continue }
                # On a folder, an entry that applies to subfolders only doesn't let anyone drop or
                # replace the file itself.
                if ($target.Scope -eq 'folder' -and ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -and
                    -not ($ace.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)) { continue }
                $result += [ordered]@{ scope = $target.Scope; sid = $sid; rights = "$($ace.FileSystemRights)" }
            }
        }
        catch { }
    }
    $script:AclCache[$key] = $result
    return $result
}

$isAdmin = $false
$isSystem = $false
try {
    $idn = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $idn.User.Value -eq 'S-1-5-18'
    $isAdmin = ([Security.Principal.WindowsPrincipal]$idn).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { }
if (-not $OutDir) { $OutDir = if ($isAdmin -or $isSystem) { 'C:\Windows\Temp\HostBadger' } else { Join-Path $env:TEMP 'HostBadger' } }

Write-Host "HostBadger collector $script:CollectorVersion on $env:COMPUTERNAME (admin: $isAdmin, SYSTEM: $isSystem)"

# ------------------------------------------------------------------ host
$cs = $null; $os = $null
$hostInfo = Invoke-Section 'host' {
    $script:cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $script:os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $role = switch ([int]$script:cs.DomainRole) { { $_ -in 0, 1 } { 'workstation' } { $_ -in 2, 3 } { 'server' } default { 'dc' } }
    # Machine SID: the SID of a local account without its last part (the RID).
    $machineSid = $null
    try {
        $la = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Select-Object -First 1
        if ($la) { $machineSid = $la.SID -replace '-\d+$', '' }
    }
    catch { }
    [ordered]@{
        name          = "$env:COMPUTERNAME"
        dnsDomain     = "$($script:cs.Domain)"
        partOfDomain  = [bool]$script:cs.PartOfDomain
        domainRole    = [int]$script:cs.DomainRole
        role          = $role
        machineSid    = $machineSid
        manufacturer  = "$($script:cs.Manufacturer)"
        model         = "$($script:cs.Model)"
        hypervisor    = [bool]$script:cs.HypervisorPresent
        os            = [ordered]@{
            caption        = "$($script:os.Caption)"
            version        = "$($script:os.Version)"
            build          = [int]$script:os.BuildNumber
            ubr            = Get-RegValue $cv 'UBR'
            displayVersion = "$(Get-RegValue $cv 'DisplayVersion')"
            editionId      = "$(Get-RegValue $cv 'EditionID')"
            productType    = [int]$script:os.ProductType
            architecture   = "$($script:os.OSArchitecture)"
            installDateUtc = ConvertTo-IsoUtc $script:os.InstallDate
            lastBootUtc    = ConvertTo-IsoUtc $script:os.LastBootUpTime
        }
    }
}

# ------------------------------------------------------------------ patches
$patches = Invoke-Section 'patches' {
    $hot = @()
    foreach ($q in @(Get-CimInstance -ClassName Win32_QuickFixEngineering)) {
        $hot += [ordered]@{ id = "$($q.HotFixID)"; description = "$($q.Description)"; installedOnUtc = ConvertTo-IsoUtc $q.InstalledOn }
    }
    # Windows Update history: the date of the last update that installed (definition updates don't count).
    $lastWu = $null
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $n = $searcher.GetTotalHistoryCount()
        if ($n -gt 0) {
            foreach ($h in @($searcher.QueryHistory(0, [Math]::Min($n, 200)))) {
                # Operation 1 = install, ResultCode 2 = succeeded.
                if ($h.Operation -eq 1 -and $h.ResultCode -eq 2 -and -not (Test-DefinitionUpdateTitle "$($h.Title)")) {
                    $d = ConvertTo-IsoUtc $h.Date
                    if ($d -and (-not $lastWu -or $d -gt $lastWu)) { $lastWu = $d }
                }
            }
        }
    }
    catch { }
    [ordered]@{ hotfixes = $hot; lastUpdateInstalledUtc = $lastWu }
}

# ------------------------------------------------------------------ defender
$defender = Invoke-Section 'defender' {
    $st = Get-MpComputerStatus
    $d = [ordered]@{
        present                   = $true
        amRunningMode             = "$($st.AMRunningMode)"
        amServiceEnabled          = [bool]$st.AMServiceEnabled
        antivirusEnabled          = [bool]$st.AntivirusEnabled
        realTimeProtectionEnabled = [bool]$st.RealTimeProtectionEnabled
        behaviorMonitorEnabled    = [bool]$st.BehaviorMonitorEnabled
        ioavProtectionEnabled     = [bool]$st.IoavProtectionEnabled
        isTamperProtected         = $(if ($null -ne $st.IsTamperProtected) { [bool]$st.IsTamperProtected } else { $null })
        signatureUpdatedUtc       = ConvertTo-IsoUtc $st.AntivirusSignatureLastUpdated
        exclusionsReadable        = $false
        exclusionPaths            = @()
        exclusionExtensions       = @()
        exclusionProcesses        = @()
        asrRules                  = @()
        puaProtection             = $null
        networkProtection         = $null
    }
    try {
        $p = Get-MpPreference
        # A standard user sees "N/A: Must be an administrator to view exclusions".
        $paths = @($p.ExclusionPath | Where-Object { $_ })
        if (@($paths | Where-Object { $_ -match '^N/A' }).Count -eq 0) {
            $d.exclusionsReadable = $true
            $d.exclusionPaths = $paths
            $d.exclusionExtensions = @($p.ExclusionExtension | Where-Object { $_ })
            $d.exclusionProcesses = @($p.ExclusionProcess | Where-Object { $_ })
        }
        $ids = @($p.AttackSurfaceReductionRules_Ids)
        $acts = @($p.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($ids[$i]) { $d.asrRules += [ordered]@{ id = "$($ids[$i])".ToLower(); action = $(if ($i -lt $acts.Count) { [int]$acts[$i] } else { $null }) } }
        }
        $d.puaProtection = $p.PUAProtection
        $d.networkProtection = $p.EnableNetworkProtection
    }
    catch { Add-CollectionError -Section 'defender.preferences' -Message $_.Exception.Message }
    if (-not $d.exclusionsReadable) { Add-CollectionError -Section 'defender.exclusions' -Message 'exclusions not readable (administrator or SYSTEM needed)' }
    $d
}

# ------------------------------------------------------------------ bitlocker / boot
$bitlocker = Invoke-Section 'bitlocker' {
    $vols = @()
    $featureInstalled = $true
    try {
        foreach ($v in @(Get-BitLockerVolume)) {
            $vols += [ordered]@{
                mountPoint       = "$($v.MountPoint)"
                volumeType       = "$($v.VolumeType)"
                protectionStatus = "$($v.ProtectionStatus)"
                volumeStatus     = "$($v.VolumeStatus)"
                encryptionMethod = "$($v.EncryptionMethod)"
                keyProtectors    = @($v.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
            }
        }
    }
    catch {
        # No BitLocker module (servers without the feature): the CIM class only exists when the
        # feature is installed.
        $msg = $_.Exception.Message
        try {
            foreach ($v in @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume)) {
                $vols += [ordered]@{
                    mountPoint       = "$($v.DriveLetter)"
                    volumeType       = $(if ($v.VolumeType -eq 0) { 'OperatingSystem' } elseif ($v.VolumeType -eq 1) { 'Data' } else { 'Removable' })
                    protectionStatus = $(if ($v.ProtectionStatus -eq 1) { 'On' } elseif ($v.ProtectionStatus -eq 0) { 'Off' } else { 'Unknown' })
                    volumeStatus     = ''
                    encryptionMethod = ''
                    keyProtectors    = @()
                }
            }
        }
        catch {
            if ($_.Exception.Message -match '(?i)invalid namespace|0x8004100e|namespace') { $featureInstalled = $false }
            else { throw "BitLocker status not readable: $msg" }
        }
    }
    [ordered]@{ featureInstalled = $featureInstalled; volumes = $vols }
}

$boot = Invoke-Section 'boot' {
    $sb = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    $fw = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType'
    [ordered]@{
        secureBootEnabled = $(if ($null -eq $sb) { $null } else { [int]$sb -eq 1 })
        firmware          = $(if ($fw -eq 2) { 'UEFI' } elseif ($fw -eq 1) { 'BIOS' } else { $null })
    }
}

# ------------------------------------------------------------------ credential protection
$credProt = Invoke-Section 'credentialProtection' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $dg = $null
    try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard } catch { }
    [ordered]@{
        runAsPPL                  = Get-RegValue $lsa 'RunAsPPL'
        lsaCfgFlags               = Get-RegValue $lsa 'LsaCfgFlags'
        credentialGuardRunning    = $(if ($dg) { @($dg.SecurityServicesRunning) -contains 1 } else { $null })
        hvciRunning               = $(if ($dg) { @($dg.SecurityServicesRunning) -contains 2 } else { $null })
        vbsStatus                 = $(if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { $null })
        wdigestUseLogonCredential = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        cachedLogonsCount         = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
        lmCompatibilityLevel      = Get-RegValue $lsa 'LmCompatibilityLevel'
        noLmHash                  = Get-RegValue $lsa 'NoLMHash'
        restrictAnonymous         = Get-RegValue $lsa 'RestrictAnonymous'
        restrictAnonymousSam      = Get-RegValue $lsa 'RestrictAnonymousSAM'
    }
}

# ------------------------------------------------------------------ network
$network = Invoke-Section 'network' {
    $n = [ordered]@{
        smb1ServerEnabled         = $null
        smbServerSigningRequired  = $null
        smbClientSigningRequired  = $null
        llmnrPolicyEnableMulticast = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        netbios                   = @()
        firewallProfiles          = @()
        listening                 = @()
    }
    try {
        $srv = Get-SmbServerConfiguration
        $n.smb1ServerEnabled = [bool]$srv.EnableSMB1Protocol
        $n.smbServerSigningRequired = [bool]$srv.RequireSecuritySignature
    }
    catch {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $s1 = Get-RegValue $p 'SMB1'
        $n.smb1ServerEnabled = $(if ($null -eq $s1) { $null } else { [int]$s1 -ne 0 })
        $rs = Get-RegValue $p 'RequireSecuritySignature'
        $n.smbServerSigningRequired = $(if ($null -eq $rs) { $null } else { [int]$rs -eq 1 })
    }
    try { $n.smbClientSigningRequired = [bool](Get-SmbClientConfiguration).RequireSecuritySignature }
    catch {
        $rs = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
        $n.smbClientSigningRequired = $(if ($null -eq $rs) { $null } else { [int]$rs -eq 1 })
    }
    foreach ($a in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
        $n.netbios += [ordered]@{ adapter = "$($a.Description)"; tcpipNetbiosOptions = $a.TcpipNetbiosOptions }
    }
    try {
        foreach ($fp in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
            $n.firewallProfiles += [ordered]@{
                name                 = "$($fp.Name)"
                enabled              = "$($fp.Enabled)" -eq 'True'
                defaultInboundAction = "$($fp.DefaultInboundAction)"
                logBlocked           = "$($fp.LogBlocked)"
            }
        }
    }
    catch { Add-CollectionError -Section 'network.firewall' -Message $_.Exception.Message }
    try {
        $procs = @{}
        foreach ($pr in @(Get-Process)) { $procs[[int]$pr.Id] = "$($pr.ProcessName)" }
        foreach ($c in @(Get-NetTCPConnection -State Listen)) {
            $n.listening += [ordered]@{ protocol = 'tcp'; address = "$($c.LocalAddress)"; port = [int]$c.LocalPort; process = $procs[[int]$c.OwningProcess] }
        }
        foreach ($u in @(Get-NetUDPEndpoint)) {
            $n.listening += [ordered]@{ protocol = 'udp'; address = "$($u.LocalAddress)"; port = [int]$u.LocalPort; process = $procs[[int]$u.OwningProcess] }
        }
    }
    catch { Add-CollectionError -Section 'network.listening' -Message $_.Exception.Message }
    $n
}

# ------------------------------------------------------------------ remote access
$remote = Invoke-Section 'remoteAccess' {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $deny = Get-RegValue $tsPol 'fDenyTSConnections'
    if ($null -eq $deny) { $deny = Get-RegValue $ts 'fDenyTSConnections' }
    $nla = Get-RegValue $tsPol 'UserAuthentication'
    if ($null -eq $nla) { $nla = Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication' }
    [ordered]@{
        rdpEnabled     = $(if ($null -eq $deny) { $null } else { [int]$deny -eq 0 })
        rdpNlaRequired = $(if ($null -eq $nla) { $null } else { [int]$nla -eq 1 })
    }
}

# ------------------------------------------------------------------ local accounts
$accounts = Invoke-Section 'localAccounts' {
    $users = @()
    $extra = @{}
    try { foreach ($lu in @(Get-LocalUser)) { $extra["$($lu.SID)"] = $lu } } catch { }
    foreach ($u in @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True')) {
        $lu = $extra["$($u.SID)"]
        $users += [ordered]@{
            name                 = "$($u.Name)"
            sid                  = "$($u.SID)"
            enabled              = -not [bool]$u.Disabled
            passwordRequired     = [bool]$u.PasswordRequired
            passwordExpires      = [bool]$u.PasswordExpires
            lastLogonUtc         = $(if ($lu) { ConvertTo-IsoUtc $lu.LastLogon } else { $null })
            passwordLastSetUtc   = $(if ($lu) { ConvertTo-IsoUtc $lu.PasswordLastSet } else { $null })
        }
    }
    # Administrators by SID through ADSI, because Get-LocalGroupMember fails on orphaned SIDs and on
    # some Entra members.
    $admins = @()
    $adminsReadable = $true
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $grpName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]"WinNT://./$grpName,group"
        foreach ($m in @($grp.psbase.Invoke('Members'))) {
            $path = "$($m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null))"
            $sidBytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
            $sid = $null
            try { $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value } catch { }
            $cls = "$($m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null))"
            $admins += [ordered]@{ path = ($path -replace '^WinNT://', ''); sid = $sid; class = $cls }
        }
    }
    catch {
        $adminsReadable = $false
        Add-CollectionError -Section 'localAccounts.administrators' -Message $_.Exception.Message
    }
    [ordered]@{ users = $users; administrators = $admins; administratorsReadable = $adminsReadable }
}

# ------------------------------------------------------------------ LAPS / UAC
$laps = Invoke-Section 'laps' {
    $wl = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
    $wlGpo = 'HKLM:\SOFTWARE\Policies\Microsoft Windows\LAPS'
    $backup = Get-RegValue $wlGpo 'BackupDirectory'
    if ($null -eq $backup) { $backup = Get-RegValue $wl 'BackupDirectory' }
    $legacyEnabled = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    [ordered]@{
        windowsLapsBackupDirectory = $backup
        legacyLapsEnabled          = $(if ($null -eq $legacyEnabled) { $null } else { [int]$legacyEnabled -eq 1 })
        legacyLapsCseInstalled     = (Test-Path -LiteralPath 'C:\Program Files\LAPS\CSE\AdmPwd.dll')
    }
}

$uac = Invoke-Section 'uac' {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    [ordered]@{
        enableLua                    = Get-RegValue $p 'EnableLUA'
        consentPromptBehaviorAdmin   = Get-RegValue $p 'ConsentPromptBehaviorAdmin'
        localAccountTokenFilterPolicy = Get-RegValue $p 'LocalAccountTokenFilterPolicy'
        filterAdministratorToken     = Get-RegValue $p 'FilterAdministratorToken'
        alwaysInstallElevated        = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    }
}

# ------------------------------------------------------------------ logging
$psLogging = Invoke-Section 'powershell' {
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    [ordered]@{
        scriptBlockLogging = Get-RegValue "$base\ScriptBlockLogging" 'EnableScriptBlockLogging'
        moduleLogging      = Get-RegValue "$base\ModuleLogging" 'EnableModuleLogging'
        transcription      = Get-RegValue "$base\Transcription" 'EnableTranscripting'
        # The v2 engine registers itself here for as long as the optional feature is on.
        v2EngineVersion    = "$(Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion')"
    }
}

$audit = Invoke-Section 'audit' {
    $a = [ordered]@{
        processCreationIncludeCmdLine = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
        securityLogMaxSizeBytes       = $null
        subcategories                 = @()
    }
    try { $a.securityLogMaxSizeBytes = [int64](Get-WinEvent -ListLog 'Security').MaximumSizeInBytes }
    catch {
        $ms = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize'
        if ($null -ne $ms) { $a.securityLogMaxSizeBytes = [int64]$ms }
    }
    # "auditpol /backup" writes the effective policy as a CSV with a numeric Setting Value (0 none,
    # 1 success, 2 failure, 3 both). That is the same in every language, unlike the text that "/get"
    # prints. We read the file and delete it right away. The backup changes no setting.
    # With ErrorActionPreference set to Stop, Windows PowerShell 5.1 turns the first stderr line of
    # a native command into an exception, so we read the exit code instead.
    $tmpCsv = Join-Path $OutDir ("auditpol_{0}.csv" -f [guid]::NewGuid().ToString('N'))
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    # auditpol can leave an empty file behind when it fails, so the finally block always removes it.
    try {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $raw = & auditpol.exe /backup "/file:$tmpCsv" 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        if ($code -ne 0 -or -not (Test-Path -LiteralPath $tmpCsv)) {
            $text = @($raw | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } } |
                ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'System.Management.Automation.RemoteException' })
            throw "auditpol failed ($code, administrator or SYSTEM needed): $(($text | Select-Object -First 2) -join ' ')"
        }
        $rows = @(Import-Csv -LiteralPath $tmpCsv)
    }
    finally { Remove-Item -LiteralPath $tmpCsv -Force -ErrorAction SilentlyContinue }
    foreach ($r in $rows) {
        $props = @($r.PSObject.Properties)
        # The columns are Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion
        # Setting, Exclusion Setting and Setting Value. We take them by position because the header
        # can be localized too. Rows without a GUID are global options (CrashOnAuditFail and
        # similar).
        $guid = "$($props[3].Value)".Trim().Trim('{', '}').ToLower()
        if ($guid -notmatch '^[0-9a-f]{8}-') { continue }
        $a.subcategories += [ordered]@{
            name      = "$($props[2].Value)"
            guid      = $guid
            inclusion = "$($props[4].Value)"
            value     = $(if ($props.Count -ge 7 -and "$($props[6].Value)" -match '^\d+$') { [int]$props[6].Value } else { $null })
        }
    }
    $a
}

# ------------------------------------------------------------------ services, tasks, autoruns
$services = Invoke-Section 'services' {
    $out = @()
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service)) {
        $exe = Get-ExecutablePath "$($s.PathName)"
        $out += [ordered]@{
            name        = "$($s.Name)"
            displayName = "$($s.DisplayName)"
            startMode   = "$($s.StartMode)"
            state       = "$($s.State)"
            account     = "$($s.StartName)"
            pathName    = Protect-CommandLine "$($s.PathName)"
            executable  = $exe
            writableBy  = $(if ($exe -and $exe -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\') { @(Get-LowPrivWriters $exe) } else { @() })
        }
    }
    $out
}

$tasks = Invoke-Section 'scheduledTasks' {
    $out = @()
    foreach ($t in @(Get-ScheduledTask)) {
        $acts = @()
        foreach ($a in @($t.Actions)) {
            if (-not $a.Execute) { continue }
            $exe = Get-ExecutablePath "$($a.Execute)"
            $acts += [ordered]@{
                execute    = Protect-CommandLine "$($a.Execute)"
                arguments  = Protect-CommandLine "$($a.Arguments)"
                executable = $exe
                writableBy = $(if ($exe -and $exe -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\') { @(Get-LowPrivWriters $exe) } else { @() })
            }
        }
        $out += [ordered]@{
            path     = "$($t.TaskPath)"
            name     = "$($t.TaskName)"
            state    = "$($t.State)"
            userId   = "$($t.Principal.UserId)"
            groupId  = "$($t.Principal.GroupId)"
            runLevel = "$($t.Principal.RunLevel)"
            author   = "$($t.Author)"
            actions  = $acts
        }
    }
    $out
}

$autoruns = Invoke-Section 'autoruns' {
    $out = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')) {
        foreach ($v in @(Get-RegSubkeyValues $k)) {
            $exe = Get-ExecutablePath $v.value
            $out += [ordered]@{ location = ($k -replace '^HKLM:\\', 'HKLM\'); name = $v.name; command = Protect-CommandLine $v.value; executable = $exe; writableBy = @(Get-LowPrivWriters $exe) }
        }
    }
    $startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
    if (Test-Path -LiteralPath $startup) {
        foreach ($f in @(Get-ChildItem -LiteralPath $startup -File -Force | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $out += [ordered]@{ location = 'Common Startup folder'; name = $f.Name; command = $f.FullName; executable = $f.FullName; writableBy = @(Get-LowPrivWriters $f.FullName) }
        }
    }
    $out
}

# ------------------------------------------------------------------ local security policy
# "secedit /export" only writes the policy to a temporary file, and its log to another one; we
# delete both right away. It never changes the policy: we don't use /configure or /import, and the
# safety review refuses them.
$secPolicy = Invoke-Section 'securityPolicy' {
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $id = [guid]::NewGuid().ToString('N')
    $tmpInf = Join-Path $OutDir "secpol_$id.inf"
    $tmpLog = Join-Path $OutDir "secpol_$id.log"
    try {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $raw = & secedit.exe /export /cfg $tmpInf /areas SECURITYPOLICY USER_RIGHTS /log $tmpLog 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        if ($code -ne 0 -or -not (Test-Path -LiteralPath $tmpInf)) {
            $text = @($raw | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } } |
                ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'System.Management.Automation.RemoteException' })
            throw "secedit failed ($code, administrator or SYSTEM needed): $(($text | Select-Object -First 2) -join ' ')"
        }
        $lines = [System.IO.File]::ReadAllLines($tmpInf, [System.Text.Encoding]::Unicode)
    }
    finally {
        Remove-Item -LiteralPath $tmpInf -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tmpLog -Force -ErrorAction SilentlyContinue
    }
    ConvertFrom-SecEditInf $lines
}

# ------------------------------------------------------------------ baseline settings
# Registry values that the CIS-based checks compare (read only). A value that isn't there stays
# $null, and the checks only judge a value that is set, unless the Windows default is itself the
# problem.
$hardening = Invoke-Section 'hardening' {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lanSrv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $wrmC = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    $wrmS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $expPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $insecureGuest = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth'
    if ($null -eq $insecureGuest) { $insecureGuest = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' }
    # Log sizes: the policy (KB) wins over the log's own setting.
    $logs = @()
    foreach ($ln in @('Application', 'System')) {
        $bytes = $null
        $pol = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$ln" 'MaxSize'
        if ($null -ne $pol) { $bytes = [int64]$pol * 1KB }
        else {
            try { $bytes = [int64](Get-WinEvent -ListLog $ln).MaximumSizeInBytes }
            catch {
                $ms = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$ln" 'MaxSize'
                if ($null -ne $ms) { $bytes = [int64]$ms }
            }
        }
        $logs += [ordered]@{ name = $ln; maxSizeBytes = $bytes }
    }
    [ordered]@{
        smbInsecureGuestAuth     = $insecureGuest
        ldapClientIntegrity      = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity'
        ntlmMinClientSec         = Get-RegValue "$lsa\MSV1_0" 'NTLMMinClientSec'
        ntlmMinServerSec         = Get-RegValue "$lsa\MSV1_0" 'NTLMMinServerSec'
        allowNullSessionFallback = Get-RegValue "$lsa\MSV1_0" 'AllowNullSessionFallback'
        allowOnlineId            = Get-RegValue "$lsa\pku2u" 'AllowOnlineID'
        everyoneIncludesAnonymous = Get-RegValue $lsa 'EveryoneIncludesAnonymous'
        limitBlankPasswordUse    = Get-RegValue $lsa 'LimitBlankPasswordUse'
        forceGuest               = Get-RegValue $lsa 'ForceGuest'
        enablePlainTextPassword  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnablePlainTextPassword'
        # Names of pipes and shares are not stored, only how many.
        nullSessionPipesCount    = @((Get-RegValue $lanSrv 'NullSessionPipes') | Where-Object { $_ }).Count
        nullSessionSharesCount   = @((Get-RegValue $lanSrv 'NullSessionShares') | Where-Object { $_ }).Count
        restrictNullSessAccess   = Get-RegValue $lanSrv 'RestrictNullSessAccess'
        netlogon                 = [ordered]@{
            requireSignOrSeal    = Get-RegValue $nl 'RequireSignOrSeal'
            sealSecureChannel    = Get-RegValue $nl 'SealSecureChannel'
            signSecureChannel    = Get-RegValue $nl 'SignSecureChannel'
            requireStrongKey     = Get-RegValue $nl 'RequireStrongKey'
            disablePasswordChange = Get-RegValue $nl 'DisablePasswordChange'
            maximumPasswordAge   = Get-RegValue $nl 'MaximumPasswordAge'
        }
        winrm                    = [ordered]@{
            clientAllowBasic              = Get-RegValue $wrmC 'AllowBasic'
            clientAllowUnencryptedTraffic = Get-RegValue $wrmC 'AllowUnencryptedTraffic'
            clientAllowDigest             = Get-RegValue $wrmC 'AllowDigest'
            serviceAllowBasic             = Get-RegValue $wrmS 'AllowBasic'
            serviceAllowUnencryptedTraffic = Get-RegValue $wrmS 'AllowUnencryptedTraffic'
        }
        rdpPolicy                = [ordered]@{
            securityLayer         = Get-RegValue $tsPol 'SecurityLayer'
            minEncryptionLevel    = Get-RegValue $tsPol 'MinEncryptionLevel'
            promptForPassword     = Get-RegValue $tsPol 'fPromptForPassword'
            encryptRpcTraffic     = Get-RegValue $tsPol 'fEncryptRPCTraffic'
            disableDriveRedirection = Get-RegValue $tsPol 'fDisableCdm'
        }
        explorer                 = [ordered]@{
            noDriveTypeAutoRun    = Get-RegValue $expPol 'NoDriveTypeAutoRun'
            noAutorun             = Get-RegValue $expPol 'NoAutorun'
            noAutoplayForNonVolume = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume'
        }
        winlogon                 = [ordered]@{
            autoAdminLogon        = "$(Get-RegValue $wl 'AutoAdminLogon')"
            # Only whether a password is stored there, never the password.
            defaultPasswordPresent = ($null -ne (Get-RegValue $wl 'DefaultPassword'))
        }
        interactiveLogon         = [ordered]@{
            inactivityTimeoutSecs = Get-RegValue $sysPol 'InactivityTimeoutSecs'
            legalNoticeTextSet    = -not [string]::IsNullOrWhiteSpace("$(Get-RegValue $sysPol 'LegalNoticeText')")
            legalNoticeCaptionSet = -not [string]::IsNullOrWhiteSpace("$(Get-RegValue $sysPol 'LegalNoticeCaption')")
            dontDisplayLastUserName = Get-RegValue $sysPol 'DontDisplayLastUserName'
            disableCad            = Get-RegValue $sysPol 'DisableCAD'
        }
        uacExtra                 = [ordered]@{
            enableInstallerDetection = Get-RegValue $sysPol 'EnableInstallerDetection'
            enableSecureUiaPaths  = Get-RegValue $sysPol 'EnableSecureUIAPaths'
            promptOnSecureDesktop = Get-RegValue $sysPol 'PromptOnSecureDesktop'
            enableVirtualization  = Get-RegValue $sysPol 'EnableVirtualization'
        }
        noAutoUpdate             = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
        enableSmartScreen        = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        eventLogs                = $logs
        mrxsmb10Start            = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
        disableExceptionChainValidation = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation'
        safeDllSearchMode        = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode'
        ipStack                  = [ordered]@{
            disableIpSourceRoutingV4 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting'
            disableIpSourceRoutingV6 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting'
            enableIcmpRedirect       = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect'
        }
    }
}
# ------------------------------------------------------------------ write
$hostName = if ($hostInfo) { $hostInfo.name } else { "$env:COMPUTERNAME" }
$now = (Get-Date).ToUniversalTime()
$snapshot = [ordered]@{
    meta                 = [ordered]@{
        tool             = 'HostBadger'
        kind             = 'host'
        computerName     = "$env:COMPUTERNAME"
        schemaVersion    = $script:SchemaVersion
        collectorVersion = $script:CollectorVersion
        collectedAtUtc   = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        collectedBy      = "$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        runningAsSystem  = $isSystem
        runningAsAdmin   = $isAdmin
        psVersion        = "$($PSVersionTable.PSVersion)"
        options          = [ordered]@{ skipAcl = [bool]$SkipAcl }
        # ToArray(): @() over a List inside a hashtable throws "Argument types do not match".
        sectionsCollected = $script:Sections.ToArray()
        collectionErrors = $script:Errors.ToArray()
    }
    host                 = $hostInfo
    patches              = $patches
    defender             = $defender
    bitlocker            = $bitlocker
    boot                 = $boot
    credentialProtection = $credProt
    network              = $network
    remoteAccess         = $remote
    localAccounts        = $accounts
    laps                 = $laps
    uac                  = $uac
    powershell           = $psLogging
    audit                = $audit
    securityPolicy       = $secPolicy
    hardening            = $hardening
    # A section that returns an empty list hands back $null, and @($null) would be one empty entry.
    services             = @($services | Where-Object { $_ })
    scheduledTasks       = @($tasks | Where-Object { $_ })
    autoruns             = @($autoruns | Where-Object { $_ })
}

if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$base = Join-Path $OutDir ("hostsnapshot_{0}_{1}" -f ($hostName -replace '[^\w\-]', '_'), $now.ToString('yyyyMMddHHmmss'))
$json = $snapshot | ConvertTo-Json -Depth 10
# Windows PowerShell 5.1 writes an empty array inside a hashtable as {}. Every empty object in this
# snapshot is really an empty list, so we put the brackets back.
$json = [regex]::Replace($json, '(?<=[^\\]"):\s*\{\s*\}', ': []')
[System.IO.File]::WriteAllText("$base.json", $json, (New-Object System.Text.UTF8Encoding($false)))
$outPath = "$base.json"
if (-not $NoZip) {
    try {
        Compress-Archive -LiteralPath "$base.json" -DestinationPath "$base.zip" -Force
        Remove-Item -LiteralPath "$base.json"
        $outPath = "$base.zip"
    }
    catch { Write-Warning "Compression failed ($($_.Exception.Message)); the JSON is kept." }
}
Write-Host "Sections: $($script:Sections.Count) collected, $($script:Errors.Count) error(s)."
Write-Host "Snapshot: $outPath"
