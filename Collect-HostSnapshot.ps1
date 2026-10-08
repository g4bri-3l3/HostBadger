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
    no process and opens no network connection of its own. The one exception
    is the opt-in -CheckUpdates, where the Windows Update Agent contacts its
    update server. Test-HostBadgerSafety.ps1 checks this claim against the code.

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
.PARAMETER CheckUpdates
    Ask the Windows Update Agent which updates are still missing. This is the
    only option that causes network traffic: the agent contacts the WSUS server
    set by policy (WUServer) or, without one, Microsoft Update (HTTPS to
    *.update.microsoft.com). Off by default; without it the pending updates are
    simply not part of the snapshot.
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [switch]$NoZip,
    [switch]$SkipAcl,
    [switch]$CheckUpdates
)

$ErrorActionPreference = 'Stop'
$script:CollectorVersion = '1.0'
$script:SchemaVersion = 1
$script:Errors = New-Object System.Collections.Generic.List[object]
$script:Sections = New-Object System.Collections.Generic.List[string]
$script:SectionSeconds = [ordered]@{}

# Progress cursor. PowerShell cannot draw while it is busy, so the cursor moves each time the script
# reports a step (a section, a service, a registry batch). It is drawn only on an interactive console;
# redirected output (an EDR session, a log file) gets nothing.
$script:SpinFrames = @('|', '/', '-', '\')
$script:SpinIndex = 0
$script:SpinLast = 0
$script:SpinWidth = 0
$script:SpinEnabled = $null
function Step-Spinner {
    param([string]$Message)
    if ($null -eq $script:SpinEnabled) {
        $script:SpinEnabled = $false
        try { $script:SpinEnabled = [bool]([Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) } catch { }
    }
    if (-not $script:SpinEnabled) { return }
    $now = [Environment]::TickCount
    if (($now - $script:SpinLast) -lt 90 -and $script:SpinWidth -gt 0) { return }
    $script:SpinLast = $now
    $text = "$Message $($script:SpinFrames[$script:SpinIndex % 4])"
    $script:SpinIndex++
    $pad = [Math]::Max(0, $script:SpinWidth - $text.Length)
    Write-Host -NoNewline "`r$text$(' ' * $pad)"
    $script:SpinWidth = $text.Length
}
function Stop-Spinner {
    if ($script:SpinEnabled -and $script:SpinWidth -gt 0) { Write-Host -NoNewline "`r$(' ' * $script:SpinWidth)`r" }
    $script:SpinWidth = 0
}

function Add-CollectionError {
    param([string]$Section, [string]$Message)
    $script:Errors.Add([ordered]@{ section = $Section; message = $Message })
    Stop-Spinner
    Write-Warning "[$Section] $Message"
}

function Invoke-Section {
    # Each section runs on its own, so one failure doesn't lose the whole snapshot.
    param([string]$Name, [scriptblock]$Body)
    $script:SpinSection = $Name
    Step-Spinner "Collecting $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Body
        $script:Sections.Add($Name)
        return $r
    }
    catch {
        Add-CollectionError -Section $Name -Message $_.Exception.Message
        return $null
    }
    finally { $script:SectionSeconds[$Name] = [Math]::Round($sw.Elapsed.TotalSeconds, 1) }
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

function ConvertTo-ReadableFileRights {
    # FileSystemRights.ToString() falls back to a bare (sometimes negative) number when the mask uses
    # the raw GENERIC_READ/WRITE/EXECUTE/ALL bits instead of the specific rights .NET's enum names --
    # seen in practice on inherit-only template ACEs some installers write (confirmed on a real
    # Authenticated Users entry: -536805376, i.e. 0xE0010000 = GENERIC_READ|WRITE|EXECUTE + Delete).
    # Those bits are decomposed into readable names here; a mask that already has a name is unchanged.
    # [System.Security.AccessControl.FileSystemRights]$Value (PowerShell's type-cast operator) throws
    # on a value with undefined bits, even though it is a [Flags] enum; [Enum]::ToObject does not
    # validate and matches plain .NET Enum.ToString() behavior (a name when one matches, otherwise the
    # bare number), which is what we actually want here.
    param([int64]$Value)
    $fsr = [System.Security.AccessControl.FileSystemRights]
    $text = "$([Enum]::ToObject($fsr, $Value))"
    if ($text -match '^-?\d+$') {
        $names = @(); $generic = 0
        if (($Value -band 0x10000000) -ne 0) { $names += 'GenericAll'; $generic = $generic -bor 0x10000000 }
        else {
            if (($Value -band [int]0x80000000) -ne 0) { $names += 'GenericRead'; $generic = $generic -bor [int]0x80000000 }
            if (($Value -band 0x40000000) -ne 0) { $names += 'GenericWrite'; $generic = $generic -bor 0x40000000 }
            if (($Value -band 0x20000000) -ne 0) { $names += 'GenericExecute'; $generic = $generic -bor 0x20000000 }
        }
        $rest = $Value -band (-bnot $generic)
        if ($rest -ne 0) { $names += "$([Enum]::ToObject($fsr, $rest))" }
        if ($names.Count -gt 0) { return ($names -join ', ') }
    }
    return $text
}

function Get-LowPrivWriters {
    # Who, among the low-privileged principals, can write the file or its folder. It only reads ACLs
    # (Get-Acl).
    param([string]$Path)
    # Return nothing rather than $null: @($null) would count as one empty writer.
    if ($SkipAcl -or -not $Path) { return }
    Step-Spinner "Collecting $script:SpinSection (file permissions)"
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
                $result += [ordered]@{ scope = $target.Scope; sid = $sid; rights = (ConvertTo-ReadableFileRights ([int64]$ace.FileSystemRights)) }
            }
        }
        catch { }
    }
    $script:AclCache[$key] = $result
    return $result
}

function Get-ServiceLowPrivStart {
    # Who, among the low-privileged principals, may start the service: the SERVICE_START right in the
    # service's security descriptor (the "Security" value in the "Security" subkey of its registry key,
    # readable by administrators and SYSTEM). Read only. A service without that subkey has the default
    # descriptor, which lets only administrators start it. Returns $null when it can't be read, which is
    # not the same as nobody.
    param([string]$Name)
    $out = @()
    try {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name\Security"
        if (-not (Test-Path -LiteralPath $key)) { return @() }
        $bytes = (Get-ItemProperty -LiteralPath $key -Name 'Security' -ErrorAction Stop).Security
        if ($null -eq $bytes) { return $null }
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([byte[]]$bytes), 0
        foreach ($ace in @($sd.DiscretionaryAcl)) {
            if ("$($ace.AceType)" -ne 'AccessAllowed') { continue }
            $sid = $ace.SecurityIdentifier.Value
            if (-not (Test-LowPrivSid $sid)) { continue }
            if (([int64]$ace.AccessMask -band (0x10 -bor 0x10000000)) -eq 0) { continue }
            $out += $sid
        }
    }
    catch { return $null }
    # A bare array return (no unary comma): PowerShell streams its elements out one by one, which is
    # exactly what the caller's @(... | Where-Object { $_ }) expects. A leading comma here would wrap
    # the whole array as a single element instead, and the caller would read .kind/.sid/.rights off
    # that wrapper (or off an inner empty array), getting blank values instead of the real ones.
    return @($out | Select-Object -Unique)
}

# Who controls a folder: its owner, and every non-administrator entry that lets someone change the
# permissions, take ownership or delete what is inside (not mere write access, which the checks above
# already report). Read only (Get-Acl), cached per folder.
$script:FolderControlCache = @{}
function Get-FolderControl {
    param([string]$Path)
    $key = $Path.ToLower()
    if ($script:FolderControlCache.ContainsKey($key)) { return $script:FolderControlCache[$key] }
    $res = @()
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $trusted = { param($s) $s -eq 'S-1-5-18' -or $s -eq 'S-1-5-32-544' -or $s -eq 'S-1-3-0' -or $s -match '^S-1-5-80-' -or $s -match '^S-1-5-21-\d+-\d+-\d+-(500|512|518|519)$' }
        if ($owner -and -not (& $trusted $owner)) { $res += [ordered]@{ kind = 'owner'; sid = $owner; rights = 'Owner' } }
        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            if (& $trusted $sid) { continue }
            # DELETE, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership
            if (([int64]$ace.FileSystemRights -band (0x10000 -bor 0x40 -bor 0x40000 -bor 0x80000)) -eq 0) { continue }
            if (($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            $res += [ordered]@{ kind = 'acl'; sid = $sid; rights = "$($ace.FileSystemRights)" }
        }
    }
    catch { }
    $script:FolderControlCache[$key] = $res
    # Bare return, same reason as Get-ServiceLowPrivStart above: no unary comma.
    return $res
}

function Get-AncestorControl {
    # The folders above a service program, from its own folder up to (not including) the drive root.
    # Level 1 is the program's folder. Folders under the Windows directory are left out.
    param([string]$Exe)
    $out = @()
    if ($SkipAcl -or -not $Exe) { return $out }
    $dir = Split-Path -Path $Exe -Parent
    $level = 1
    while ($dir -and $dir.Length -gt 3 -and $level -le 8) {
        if ($dir -match '(?i)^[a-z]:\\windows(\\|$)') { break }
        if (Test-Path -LiteralPath $dir) {
            foreach ($c in @(Get-FolderControl $dir | Where-Object { $_ })) { $out += [ordered]@{ level = $level; kind = $c.kind; sid = $c.sid; rights = $c.rights } }
        }
        $parent = Split-Path -Path $dir -Parent
        if ($parent -eq $dir) { break }
        $dir = $parent; $level++
    }
    return $out
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
        mapsReporting             = $null
        disableBlockAtFirstSeen   = $null
        disableScriptScanning     = $null
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
        $d.mapsReporting = $p.MAPSReporting
        $d.disableBlockAtFirstSeen = $(if ($null -ne $p.DisableBlockAtFirstSeen) { [bool]$p.DisableBlockAtFirstSeen } else { $null })
        $d.disableScriptScanning = $(if ($null -ne $p.DisableScriptScanning) { [bool]$p.DisableScriptScanning } else { $null })
    }
    catch { Add-CollectionError -Section 'defender.preferences' -Message $_.Exception.Message }
    if (-not $d.exclusionsReadable) { Add-CollectionError -Section 'defender.exclusions' -Message 'exclusions not readable (administrator or SYSTEM needed)' }
    $d
}

# ------------------------------------------------------------------ bitlocker / boot
$bitlocker = Invoke-Section 'bitlocker' {
    # Without administrator rights both reads below fail after about 5 seconds each, so do not try.
    if (-not $isAdmin -and -not $isSystem) { throw 'BitLocker status needs administrator or SYSTEM (not attempted)' }
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
        $underSystem32 = $exe -and $exe -match '(?i)\\Windows\\(System32|SysWOW64)\\'
        $writers = $(if ($exe -and -not $underSystem32) { @(Get-LowPrivWriters $exe) } else { @() })
        # Captured into a variable first, not inlined into the hashtable literal: a function call
        # inside $(...) that can return $null, one object or many doesn't reliably collapse to the
        # right array shape when assigned directly as a hashtable value.
        $lps = if (@($writers).Count -gt 0) { Get-ServiceLowPrivStart "$($s.Name)" } else { @() }
        $out += [ordered]@{
            name        = "$($s.Name)"
            displayName = "$($s.DisplayName)"
            startMode   = "$($s.StartMode)"
            state       = "$($s.State)"
            account     = "$($s.StartName)"
            pathName    = Protect-CommandLine "$($s.PathName)"
            executable  = $exe
            writableBy  = $writers
            ancestorControl = $(if ($exe -and -not $underSystem32) { @(Get-AncestorControl $exe) } else { @() })
            # $null here means "could not determine" (no Security registry value readable), not "nobody".
            startableBy = $(if ($null -eq $lps) { $null } else { @($lps) })
        }
    }
    $out
}

$tasks = Invoke-Section 'scheduledTasks' {
    $out = @()
    foreach ($t in @(Get-ScheduledTask)) {
        Step-Spinner 'Collecting scheduled tasks'
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
    # SCHANNEL: only values somebody set. Enabled is stored as a DWORD (0xFFFFFFFF reads as -1).
    $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    $schProtocols = @()
    foreach ($pn in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        foreach ($side in @('Server', 'Client')) {
            $schProtocols += [ordered]@{ name = $pn; side = $side; enabled = Get-RegValue "$sch\Protocols\$pn\$side" 'Enabled' }
        }
    }
    $schCiphers = @()
    foreach ($cn in @('NULL', 'DES 56/56', 'RC2 40/128', 'RC2 56/128', 'RC2 128/128', 'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168')) {
        $schCiphers += [ordered]@{ name = $cn; enabled = Get-RegValue "$sch\Ciphers\$cn" 'Enabled' }
    }
    $ntdsP = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $pnpP = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    [ordered]@{
        schannel                 = [ordered]@{ protocols = $schProtocols; ciphers = $schCiphers }
        ldapServer               = [ordered]@{ integrity = Get-RegValue $ntdsP 'LDAPServerIntegrity'; channelBinding = Get-RegValue $ntdsP 'LdapEnforceChannelBinding' }
        pointAndPrint           = [ordered]@{
            restrictDriverInstallToAdmins = Get-RegValue $pnpP 'RestrictDriverInstallationToAdministrators'
            noWarningNoElevationOnInstall = Get-RegValue $pnpP 'NoWarningNoElevationOnInstall'
            noWarningNoElevationOnUpdate  = Get-RegValue $pnpP 'NoWarningNoElevationOnUpdate'
        }
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
# ------------------------------------------------------------------ installed software
# What the Programs and Features list shows (the Uninstall keys, 64 and 32 bit), read only. Updates and
# system components are left out. Per-user installs are not listed.
$software = Invoke-Section 'software' {
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            Step-Spinner 'Collecting installed software'
            try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            $n = "$($p.DisplayName)".Trim()
            if (-not $n -or $p.SystemComponent -eq 1 -or $p.ParentKeyName -or $n -match '^(Security Update|Update|Hotfix) for ' -or $n -match '\(KB\d{6,}\)') { continue }
            $id = ("$n|$($p.DisplayVersion)|$($p.Publisher)").ToLower()
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $out.Add([ordered]@{ name = $n; version = "$($p.DisplayVersion)".Trim(); publisher = "$($p.Publisher)".Trim() })
            if ($out.Count -ge 5000) { break }
        }
    }
    $out.ToArray()
}

# ------------------------------------------------------------------ pending Windows updates (only with -CheckUpdates)
# Asks the Windows Update Agent on this machine what is missing. This is the one place where the
# collector causes network traffic: the agent contacts the WSUS server set by policy (WUServer) or, if
# there is none, Microsoft Update (HTTPS to *.update.microsoft.com). The collector sends nothing itself.
$updatesPending = $null
if ($CheckUpdates) {
    $updatesPending = Invoke-Section 'updatesPending' {
        Step-Spinner 'Searching Windows Update (network)'
        $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $useWsus = ((Get-RegValue "$wuPol\AU" 'UseWUServer') -eq 1) -and [bool](Get-RegValue $wuPol 'WUServer')
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $pending = @()
        foreach ($u in @($res.Updates)) {
            Step-Spinner 'Reading the pending updates'
            $cats = @(); foreach ($c in @($u.Categories)) { $cats += "$($c.Name)" }
            $kbs = @(); foreach ($kb in @($u.KBArticleIDs)) { $kbs += "KB$kb" }
            $t = "$($u.Title)"; if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
            $pending += [ordered]@{ kb = ($kbs -join ','); title = $t; severity = "$($u.MsrcSeverity)"; categories = ($cats -join ', '); downloaded = [bool]$u.IsDownloaded; rebootRequired = [bool]$u.RebootRequired }
            if ($pending.Count -ge 200) { break }
        }
        [ordered]@{ searched = $true; source = $(if ($useWsus) { 'WSUS' } else { 'Microsoft Update' }); pending = $pending }
    }
}

# ------------------------------------------------------------------ DISA STIG registry values
# The values that the registry rules of the DISA STIGs (Windows 11, Defender, Firewall, Edge, Chrome,
# Firefox, Office 365) look at, read only. Only values that exist are written; a value that is not
# there is a value that is not configured. M = machine (HKLM), U = per user (the HKU hives that are
# loaded, which is what a SYSTEM run can see). The list is generated from the STIG data.
# BEGIN STIG-REGISTRY (generated by tools\Convert-PowerStigData.ps1; do not edit)
$stigRegistryList = @(
    'M|Software\Policies\Google\Chrome|RemoteAccessHostFirewallTraversal'
    'M|Software\Policies\Google\Chrome|DefaultGeolocationSetting'
    'M|Software\Policies\Google\Chrome|DefaultPopupsSetting'
    'M|Software\Policies\Google\Chrome|DefaultSearchProviderEnabled'
    'M|Software\Policies\Google\Chrome|PasswordManagerEnabled'
    'M|Software\Policies\Google\Chrome|BackgroundModeEnabled'
    'M|Software\Policies\Google\Chrome|SyncDisabled'
    'M|Software\Policies\Google\Chrome\URLBlocklist|1'
    'M|Software\Policies\Google\Chrome|CloudPrintProxyEnabled'
    'M|Software\Policies\Google\Chrome|NetworkPredictionOptions'
    'M|Software\Policies\Google\Chrome|MetricsReportingEnabled'
    'M|Software\Policies\Google\Chrome|SearchSuggestEnabled'
    'M|Software\Policies\Google\Chrome|ImportSavedPasswords'
    'M|Software\Policies\Google\Chrome|IncognitoModeAvailability'
    'M|Software\Policies\Google\Chrome|EnableOnlineRevocationChecks'
    'M|Software\Policies\Google\Chrome|SafeBrowsingProtectionLevel'
    'M|Software\Policies\Google\Chrome|SavingBrowserHistoryDisabled'
    'M|Software\Policies\Google\Chrome|AllowDeletingBrowserHistory'
    'M|Software\Policies\Google\Chrome|PromptForDownloadLocation'
    'M|Software\Policies\Google\Chrome|DownloadRestrictions'
    'M|Software\Policies\Google\Chrome|SafeBrowsingExtendedReportingEnabled'
    'M|Software\Policies\Google\Chrome|DefaultWebUsbGuardSetting'
    'M|Software\Policies\Google\Chrome|EnableMediaRouter'
    'M|Software\Policies\Google\Chrome|AutoplayAllowed'
    'M|Software\Policies\Google\Chrome|UrlKeyedAnonymizedDataCollectionEnabled'
    'M|Software\Policies\Google\Chrome|WebRtcEventLogCollectionAllowed'
    'M|Software\Policies\Google\Chrome|DeveloperToolsAvailability'
    'M|Software\Policies\Google\Chrome|BrowserGuestModeEnabled'
    'M|Software\Policies\Google\Chrome|AutofillCreditCardEnabled'
    'M|Software\Policies\Google\Chrome|AutofillAddressEnabled'
    'M|Software\Policies\Google\Chrome|ImportAutofillFormData'
    'M|Software\Policies\Google\Chrome|DefaultWebBluetoothGuardSetting'
    'M|Software\Policies\Google\Chrome|QuicAllowed'
    'M|Software\Policies\Google\Chrome|CookiesSessionOnlyForUrls'
    'M|Software\Policies\Google\Chrome\"|CreateThemesSettings'
    'M|Software\Policies\Google\Chrome\"|DevToolsGenAiSettings'
    'M|Software\Policies\Google\Chrome\"|GenAILocalFoundationalModelSettings'
    'M|Software\Policies\Google\Chrome\"|HelpMeWriteSettings'
    'M|Software\Policies\Google\Chrome\"|HistorySearchSettings'
    'M|Software\Policies\Google\Chrome\"|TabCompareSettings'
    'M|Software\Policies\Microsoft\Windows Defender|PUAProtection'
    'M|Software\Policies\Microsoft\Windows Defender|DisableRoutinelyTakingAction'
    'M|Software\Policies\Microsoft\Windows Defender|DisableAntiSpyware'
    'M|Software\Policies\Microsoft\Windows Defender\Exclusions|Exclusions_Paths'
    'M|Software\Policies\Microsoft\Windows Defender\Exclusions|Exclusions_Processes'
    'M|Software\Policies\Microsoft\Windows Defender\Exclusions|DisableAutoExclusions'
    'M|Software\Policies\Microsoft\Windows Defender\Spynet|LocalSettingOverrideSpynetReporting'
    'M|Software\Policies\Microsoft\Windows Defender\Spynet|DisableBlockAtFirstSeen'
    'M|Software\Policies\Microsoft\Windows Defender\Spynet|SpynetReporting'
    'M|Software\Policies\Microsoft\Windows Defender\Spynet|SubmitSamplesConsent'
    'M|Software\Policies\Microsoft\Windows Defender\NIS|DisableProtocolRecognition'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|LocalSettingOverrideDisableOnAccessProtection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|LocalSettingOverrideRealtimeScanDirection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|LocalSettingOverrideDisableIOAVProtection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|LocalSettingOverrideDisableBehaviorMonitoring'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|LocalSettingOverrideDisableRealtimeMonitoring'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|RealtimeScanDirection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableOnAccessProtection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableIOAVProtection'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableRealtimeMonitoring'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableBehaviorMonitoring'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableScanOnRealtimeEnable'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|DisableArchiveScanning'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|DisableRemovableDriveScanning'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|ScheduleDay'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|DisableEmailScanning'
    'M|Software\Policies\Microsoft\Windows Defender\Signature Updates|ASSignatureDue'
    'M|Software\Policies\Microsoft\Windows Defender\Signature Updates|AVSignatureDue'
    'M|Software\Policies\Microsoft\Windows Defender\Signature Updates|ScheduleDay'
    'M|Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction|5'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|3B576869-A4EC-4529-8536-B80A7769E899'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|D3E037E1-3EB8-44C8-A917-57927947596D'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection|EnableNetworkProtection'
    'M|Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction|4'
    'M|Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction|2'
    'M|Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction|1'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|c1db55ab-c21a-4637-bb3f-a12568109d35'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|d1e49aac-8f56-4280-b9ba-993a6d77406c'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|e6db77e5-3df2-4cf1-b95a-636979351e5b'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|01443614-cd74-433a-b99e-2ecdc07bfc25'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|26190899-1602-49e8-8b27-eb1d0a1ce869'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules|56a863a9-875e-4185-98a7-b882c64b5ce5'
    'M|Software\Policies\Microsoft\Windows Defender|DisableLocalAdminMerge'
    'M|Software\Policies\Microsoft\Windows Defender|HideExclusionsFromLocalAdmins'
    'M|Software\Policies\Microsoft\Windows Defender|RandomizeScheduleTaskTimes'
    'M|SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options|UILockdown'
    'M|Software\Policies\Microsoft\Windows Defender\MpEngine|EnableFileHashComputation'
    'M|Software\Policies\Microsoft\Windows Defender\MpEngine|MpBafsExtendedTimeout'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableScriptScanning'
    'M|Software\Policies\Microsoft\Windows Defender\Real-Time Protection|OobeEnableRtpAndSigUpdate'
    'M|Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection|AllowNetworkProtectionOnWinServer'
    'M|Software\Policies\Microsoft\Windows Defender\Features|PassiveRemediation'
    'M|Software\Policies\Microsoft\Windows Defender\Reporting|EnableDynamicSignatureDroppedEventReporting'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|QuickScanIncludeExclusions'
    'M|Software\Policies\Microsoft\Windows Defender\NIS|EnableConvertWarnToBlock'
    'M|Software\Policies\Microsoft\Windows Defender\NIS|AllowSwitchToAsyncInspection'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|DisablePackedExeScanning'
    'M|Software\Policies\Microsoft\Windows Defender\Scan|DisableHeuristics'
    'M|Software\Policies\Microsoft\Windows Defender\MpEngine|MpCloudBlockLevel'
    'M|SOFTWARE\Policies\Microsoft\Edge|PreventSmartScreenPromptOverride'
    'M|SOFTWARE\Policies\Microsoft\Edge|PreventSmartScreenPromptOverrideForFiles'
    'M|SOFTWARE\Policies\Microsoft\Edge|InPrivateModeAvailability'
    'M|SOFTWARE\Policies\Microsoft\Edge|BackgroundModeEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|DefaultPopupsSetting'
    'M|SOFTWARE\Policies\Microsoft\Edge|SyncDisabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|NetworkPredictionOptions'
    'M|SOFTWARE\Policies\Microsoft\Edge|SearchSuggestEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportAutofillFormData'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportBrowserSettings'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportCookies'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportExtensions'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportHistory'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportHomepage'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportOpenTabs'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportPaymentInfo'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportSavedPasswords'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportSearchEngine'
    'M|SOFTWARE\Policies\Microsoft\Edge|ImportShortcuts'
    'M|SOFTWARE\Policies\Microsoft\Edge|AutoplayAllowed'
    'M|SOFTWARE\Policies\Microsoft\Edge|DefaultWebUsbGuardSetting'
    'M|SOFTWARE\Policies\Microsoft\Edge|EnableMediaRouter'
    'M|SOFTWARE\Policies\Microsoft\Edge|DefaultWebBluetoothGuardSetting'
    'M|SOFTWARE\Policies\Microsoft\Edge|AutofillCreditCardEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|AutofillAddressEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|EnableOnlineRevocationChecks'
    'M|SOFTWARE\Policies\Microsoft\Edge|PersonalizationReportingEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|DefaultGeolocationSetting'
    'M|SOFTWARE\Policies\Microsoft\Edge|AllowDeletingBrowserHistory'
    'M|SOFTWARE\Policies\Microsoft\Edge|DeveloperToolsAvailability'
    'M|SOFTWARE\Policies\Microsoft\Edge|DownloadRestrictions'
    'M|SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist|1'
    'M|SOFTWARE\Policies\Microsoft\Edge|PasswordManagerEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|SitePerProcess'
    'M|SOFTWARE\Policies\Microsoft\Edge|AuthSchemes'
    'M|SOFTWARE\Policies\Microsoft\Edge|SmartScreenEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|SmartScreenPuaEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|PromptForDownloadLocation'
    'M|SOFTWARE\Policies\Microsoft\Edge|TrackingPrevention'
    'M|SOFTWARE\Policies\Microsoft\Edge|PaymentMethodQueryEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|AlternateErrorPagesEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|UserFeedbackAllowed'
    'M|SOFTWARE\Policies\Microsoft\Edge|EdgeCollectionsEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|ConfigureShare'
    'M|SOFTWARE\Policies\Microsoft\Edge|BrowserGuestModeEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|RelaunchNotification'
    'M|SOFTWARE\Policies\Microsoft\Edge|BuiltInDnsClientEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|QuicAllowed'
    'M|SOFTWARE\Policies\Microsoft\Edge|VisualSearchEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|HubsSidebarEnabled'
    'M|SOFTWARE\Policies\Microsoft\Edge|DefaultCookieSetting'
    'M|SOFTWARE\Policies\Microsoft\Edge|ConfigureFriendlyURLFormat'
    'M|SOFTWARE\Policies\Microsoft\Edge|ComposeInlineEnabled'
    'M|SOFTWARE\Policies\Mozilla\Firefox|SSLVersionMin'
    'M|SOFTWARE\Policies\Mozilla\Firefox|ExtensionUpdate'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableFormHistory'
    'M|SOFTWARE\Policies\Mozilla\Firefox|PasswordManagerEnabled'
    'M|SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking|Default'
    'M|SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking|Locked'
    'M|SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission|Default'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableTelemetry'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableDeveloperTools'
    'M|SOFTWARE\Policies\Mozilla\Firefox\Certificates|ImportEnterpriseRoots'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableForgetButton'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisablePrivateBrowsing'
    'M|SOFTWARE\Policies\Mozilla\Firefox|SearchSuggestEnabled'
    'M|SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay|Default'
    'M|SOFTWARE\Policies\Mozilla\Firefox|NetworkPrediction'
    'M|SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection|Fingerprinting'
    'M|SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection|Cryptomining'
    'M|SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers|TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    'M|SOFTWARE\Policies\Mozilla\Firefox\UserMessaging|ExtensionRecommendations'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|Highlights'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|Locked'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|Pocket'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|Search'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|Snippets'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|SponsoredPocket'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|SponsoredTopSites'
    'M|SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome|TopSites'
    'M|SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS|Enabled'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableFirefoxAccounts'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableFeedbackCommands'
    'M|SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions|Enabled'
    'M|SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions|Locked'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|Cache'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|Cookies'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|Downloads'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|FormData'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|History'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|Locked'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|OfflineApps'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|Sessions'
    'M|SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown|SiteSettings'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisablePocket'
    'M|SOFTWARE\Policies\Mozilla\Firefox|DisableFirefoxStudies'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile|EnableFirewall'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile|EnableFirewall'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile|EnableFirewall'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile|EnableFirewall'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile|EnableFirewall'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile|EnableFirewall'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile|DefaultInboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile|DefaultInboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile|DefaultOutboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile|DefaultOutboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging|LogFileSize'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging|LogFileSize'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging|LogDroppedPackets'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging|LogDroppedPackets'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging|LogSuccessfulConnections'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging|LogSuccessfulConnections'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile|DefaultInboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile|DefaultInboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile|DefaultOutboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile|DefaultOutboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging|LogFileSize'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging|LogFileSize'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging|LogDroppedPackets'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging|LogDroppedPackets'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging|LogSuccessfulConnections'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging|LogSuccessfulConnections'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile|DefaultInboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile|DefaultInboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile|DefaultOutboundAction'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile|DefaultOutboundAction'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile|AllowLocalPolicyMerge'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile|AllowLocalIPsecPolicyMerge'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging|LogFileSize'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging|LogFileSize'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging|LogDroppedPackets'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging|LogDroppedPackets'
    'M|SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging|LogSuccessfulConnections'
    'M|SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging|LogSuccessfulConnections'
    'U|Software\Policies\Microsoft\Office\16.0\access\security|blockcontentexecutionfrominternet'
    'U|Software\Policies\Microsoft\Office\16.0\access\security|NoTBPromptUnsignedAddin'
    'U|Software\Policies\Microsoft\Office\16.0\Access\Security|vbawarnings'
    'U|software\policies\microsoft\office\16.0\common\security|macroruntimescanscope'
    'U|Software\Policies\Microsoft\Office\16.0\common\security|DRMEncryptProperty'
    'U|software\policies\microsoft\office\16.0\common\portal|linkpublishingdisabled'
    'U|software\policies\microsoft\office\16.0\common\toolbars|noextensibilitycustomizationfromdocument'
    'U|Software\Policies\Microsoft\Office\16.0\Common\Security|UFIControls'
    'U|Software\Policies\Microsoft\Office\Common\Security|AutomationSecurity'
    'U|software\policies\microsoft\office\16.0\common\trustcenter|trustbar'
    'U|Software\Policies\Microsoft\Office\16.0\Common\Security|defaultencryption12'
    'U|Software\Policies\Microsoft\Office\16.0\Common\Security|OpenXMLEncryption'
    'U|software\policies\microsoft\office\16.0\common\security\trusted locations|allow user locations'
    'U|software\policies\microsoft\office\common\smart tag|neverloadmanifests'
    'U|SOFTWARE\Policies\Microsoft\vba\security|LoadControlsInForms'
    'M|SOFTWARE\Microsoft\Office\Common\COM Compatibility|COMMENT'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations|AllowNetworkLocations'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security|vbawarnings'
    'U|software\policies\microsoft\office\16.0\excel\security\external content|disableddeserverlaunch'
    'U|software\policies\microsoft\office\16.0\excel\security\external content|disableddeserverlookup'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|DBaseFiles'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|DifandSylkFiles'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL2Macros'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL2Worksheets'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL3Macros'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL3Worksheets'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL4Macros'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL4Workbooks'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|XL4Worksheets'
    'U|software\policies\microsoft\office\16.0\excel\security\fileblock|xl95workbooks'
    'U|Software\Policies\Microsoft\office\16.0\excel\security\fileblock|XL9597WorkbooksandTemplates'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\fileblock|OpenInProtectedView'
    'U|software\policies\microsoft\office\16.0\excel\security\fileblock|htmlandxmlssfiles'
    'U|software\policies\microsoft\office\16.0\excel\options|extractdatadisableui'
    'U|software\policies\microsoft\office\16.0\excel\options\binaryoptions|fupdateext_78_1'
    'U|software\policies\microsoft\office\16.0\excel\internet|donotloadpictures'
    'U|software\policies\microsoft\office\16.0\excel\options|disableautorepublish'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Options|disableautorepublishwarning'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security|extensionhardening'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security|excelbypassencryptiedmacrosscan'
    'U|software\policies\microsoft\office\16.0\excel\security\filevalidation|enableonload'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security|webservicefunctionwarnings'
    'U|software\policies\microsoft\office\16.0\excel\security|blockcontentexecutionfrominternet'
    'U|software\policies\microsoft\office\16.0\excel\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\excel\security\external content|enableblockunsecurequeryfiles'
    'U|software\policies\microsoft\office\16.0\excel\security\protectedview|enabledatabasefileprotectedview'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security\ProtectedView|DisableInternetFilesInPV'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security\ProtectedView|DisableUnsafeLocationsInPV'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security\FileValidation|openinprotectedview'
    'U|Software\Policies\Microsoft\Office\16.0\Excel\Security\FileValidation|DisableEditFromPV'
    'U|software\policies\microsoft\office\16.0\excel\security\protectedview|DisableAttachmentsInPV'
    'M|Software\Policies\Microsoft\office\16.0\lync|enablesiphighsecuritymode'
    'M|Software\Policies\Microsoft\office\16.0\lync|disablehttpconnect'
    'U|software\policies\microsoft\office\16.0\outlook\rpc|enablerpcencryption'
    'U|software\policies\microsoft\office\16.0\outlook\security|publicfolderscript'
    'U|software\policies\microsoft\office\16.0\outlook\security|sharedfolderscript'
    'U|software\policies\microsoft\office\16.0\outlook\options\general|msgformat'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\Options\Mail|junkmailprotection'
    'U|software\policies\microsoft\office\16.0\outlook\security|allowactivexoneoffforms'
    'U|software\policies\microsoft\office\16.0\outlook|disallowattachmentcustomization'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\options\mail|Internet'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\security|publishtogaldisabled'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\Security|minenckey'
    'U|software\policies\microsoft\office\16.0\outlook\security|warnaboutinvalid'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\security|usecrlchasing'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\security|adminsecuritymode'
    'U|software\policies\microsoft\office\16.0\outlook\security|allowuserstolowerattachments'
    'U|Software\Policies\Microsoft\Office\16.0\outlook\security|ShowLevel1Attach'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\Security|FileExtensionsRemoveLevel1'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\Security|FileExtensionsRemoveLevel2'
    'U|Software\Policies\Microsoft\Office\16.0\outlook\security|EnableOneOffFormScripts'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoomcustomaction'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoomaddressbookaccess'
    'U|Software\Policies\Microsoft\Office\16.0\outlook\security|PromptOOMFormulaAccess'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoomsaveas'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoomaddressinformationaccess'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoommeetingtaskrequestresponse'
    'U|software\policies\microsoft\office\16.0\outlook\security|promptoomsend'
    'U|Software\Policies\Microsoft\Office\16.0\outlook\options\mail|JunkMailEnableLinks'
    'U|software\policies\microsoft\office\16.0\outlook\security|level'
    'U|software\policies\microsoft\office\16.0\ms project\security\trusted locations|allownetworklocations'
    'U|software\policies\Microsoft\office\16.0\ms project\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\Project\Security|vbawarnings'
    'U|software\policies\microsoft\office\16.0\powerpoint\security|vbawarnings'
    'U|Software\Policies\Microsoft\Office\16.0\Outlook\Security|runprograms'
    'U|software\policies\microsoft\office\16.0\powerpoint\security\fileblock|binaryfiles'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\fileblock|OpenInProtectedView'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\Security|PowerPointBypassEncryptedMacroScan'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation|EnableOnLoad'
    'U|Software\Policies\Microsoft\Office\16.0\powerpoint\security|blockcontentexecutionfrominternet'
    'U|software\policies\Microsoft\office\16.0\powerpoint\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview|DisableInternetFilesInPV'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview|DisableAttachmentsInPV'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview|DisableUnsafeLocationsInPV'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\Security\FileValidation|openinprotectedview'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\Security\FileValidation|DisableEditFromPV'
    'U|Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations|AllowNetworkLocations'
    'U|software\policies\microsoft\office\common\security|automationsecuritypublisher'
    'U|software\policies\microsoft\office\16.0\publisher\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\Publisher\Security|vbawarnings'
    'U|Software\Policies\Microsoft\Office\16.0\Visio\Security|vbawarnings'
    'U|software\policies\microsoft\office\16.0\visio\security\trusted locations|allownetworklocations'
    'U|software\policies\microsoft\office\16.0\visio\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\visio\security\fileblock|visio2000files'
    'U|Software\Policies\Microsoft\Office\16.0\visio\security\fileblock|visio2003files'
    'U|Software\Policies\Microsoft\Office\16.0\visio\security\fileblock|visio50andearlierfiles'
    'U|software\policies\microsoft\office\16.0\visio\security|blockcontentexecutionfrominternet'
    'U|software\policies\microsoft\office\16.0\word\security|notbpromptunsignedaddin'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security|WordBypassEncryptedMacroScan'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView|DisableInternetFilesInPV'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView|DisableUnsafeLocationsInPV'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security\FileValidation|openinprotectedview'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security\FileValidation|DisableEditFromPV'
    'U|software\policies\microsoft\office\16.0\word\security\protectedview|disableattachmentsinpv'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|OpenInProtectedView'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|Word2Files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|Word2000Files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|word2003files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|word2007files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|word60files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|word95files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|word97files'
    'U|Software\Policies\Microsoft\Office\16.0\word\security\fileblock|wordxpfiles'
    'U|Software\Policies\Microsoft\Office\16.0\word\security|blockcontentexecutionfrominternet'
    'U|software\policies\microsoft\office\16.0\word\security\trusted locations|allownetworklocations'
    'U|Software\Policies\Microsoft\Office\16.0\Word\Security|vbawarnings'
    'U|software\policies\microsoft\office\16.0\word\security\filevalidation|enableonload'
    'M|SOFTWARE\Policies\Microsoft\FVE|UseAdvancedStartup'
    'M|SOFTWARE\Policies\Microsoft\FVE|UseTPMPIN'
    'M|Software\Policies\Microsoft\FVE|MinimumPIN'
    'M|SYSTEM\CurrentControlSet\Control\Session Manager\kernel|DisableExceptionChainValidation'
    'M|SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1'
    'M|SYSTEM\CurrentControlSet\Services\mrxsmb10|Start'
    'M|SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity|AllowBluetooth'
    'M|SOFTWARE\Policies\Microsoft\Windows\EventLog\Application|MaxSize'
    'M|SOFTWARE\Policies\Microsoft\Windows\EventLog\Security|MaxSize'
    'M|SOFTWARE\Policies\Microsoft\Windows\EventLog\System|MaxSize'
    'M|SOFTWARE\Policies\Microsoft\Windows\Personalization|NoLockScreenCamera'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam|Value'
    'M|SOFTWARE\Policies\Microsoft\Windows\Personalization|NoLockScreenSlideshow'
    'M|SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIpSourceRouting'
    'M|SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|DisableIPSourceRouting'
    'M|SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|EnableICMPRedirect'
    'M|SYSTEM\CurrentControlSet\Services\Netbt\Parameters|NoNameReleaseOnDemand'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|LocalAccountTokenFilterPolicy'
    'M|SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest|UseLogonCredential'
    'M|SOFTWARE\Classes\batfile\shell\runasuser|SuppressionPolicy'
    'M|SOFTWARE\Classes\cmdfile\shell\runasuser|SuppressionPolicy'
    'M|SOFTWARE\Classes\exefile\shell\runasuser|SuppressionPolicy'
    'M|SOFTWARE\Classes\mscfile\shell\runasuser|SuppressionPolicy'
    'M|SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation|AllowInsecureGuestAuth'
    'M|SOFTWARE\Policies\Microsoft\Windows\Network Connections|NC_ShowSharedAccessUI'
    'M|SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fMinimizeConnections'
    'M|SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fBlockNonDomain'
    'M|SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config|AutoConnectAllowedOEM'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit|ProcessCreationIncludeCmdLine_Enabled'
    'M|SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation|AllowProtectedCreds'
    'M|SOFTWARE\Policies\Microsoft\Windows\DeviceGuard|EnableVirtualizationBasedSecurity'
    'M|SOFTWARE\Policies\Microsoft\Windows\DeviceGuard|RequirePlatformSecurityFeatures'
    'M|SOFTWARE\Policies\Microsoft\Windows\DeviceGuard|LsaCfgFlags'
    'M|SYSTEM\CurrentControlSet\Policies\EarlyLaunch|DriverLoadPolicy'
    'M|SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoGPOListChanges'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Printers|DisableWebPnPDownload'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoWebServices'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Printers|DisableHTTPPrinting'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|DevicePKInitEnabled'
    'M|SOFTWARE\Policies\Microsoft\Windows\System|DontDisplayNetworkSelectionUI'
    'M|SOFTWARE\Policies\Microsoft\Windows\System|EnumerateLocalUsers'
    'M|SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|DCSettingIndex'
    'M|SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|ACSettingIndex'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fAllowToGetHelp'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Rpc|RestrictRemoteClients'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|MSAOptional'
    'M|SOFTWARE\Policies\Microsoft\Windows\AppCompat|DisableInventory'
    'M|SOFTWARE\Policies\Microsoft\Windows\Explorer|NoAutoplayfornonVolume'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer|NoDriveTypeAutoRun'
    'M|SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures|EnhancedAntiSpoofing'
    'M|SOFTWARE\Policies\Microsoft\Windows\CloudContent|DisableWindowsConsumerFeatures'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI|EnumerateAdministrators'
    'M|SOFTWARE\Policies\Microsoft\Windows\DataCollection|LimitEnhancedDiagnosticDataWindowsAnalytics'
    'M|SOFTWARE\Policies\Microsoft\Windows\DataCollection|AllowTelemetry'
    'M|SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization|DODownloadMode'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config|DODownloadMode'
    'M|SOFTWARE\Policies\Microsoft\Windows\System|ShellSmartScreenLevel'
    'M|SOFTWARE\Policies\Microsoft\Windows\Explorer|NoDataExecutionPrevention'
    'M|SOFTWARE\Policies\Microsoft\Windows\Explorer|NoHeapTerminationOnCorruption'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|PreXPSP2ShellProtocolBehavior'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter|PreventOverride'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter|PreventOverrideAppRepUnknown'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings|PreventCertErrorOverrides'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main|FormSuggest Passwords'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter|EnabledV9'
    'M|SOFTWARE\Policies\Microsoft\Windows\GameDVR|AllowGameDVR'
    'M|SOFTWARE\Policies\Microsoft\PassportForWork|RequireSecurityDevice'
    'M|SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity|MinimumPINLength'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|DisablePasswordSaving'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fDisableCdm'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fPromptForPassword'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fEncryptRPCTraffic'
    'M|SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|MinEncryptionLevel'
    'M|SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds|DisableEnclosureDownload'
    'M|SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds|AllowBasicAuthInClear'
    'M|SOFTWARE\Policies\Microsoft\Windows\Windows Search|AllowIndexingEncryptedStoresOrItems'
    'M|SOFTWARE\Policies\Microsoft\Windows\Installer|EnableUserControl'
    'M|SOFTWARE\Policies\Microsoft\Windows\Installer|AlwaysInstallElevated'
    'M|SOFTWARE\Policies\Microsoft\Windows\Installer|SafeForScripting'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|DisableAutomaticRestartSignOn'
    'M|SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowBasic'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowUnencryptedTraffic'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|AllowBasic'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|AllowUnencryptedTraffic'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|DisableRunAs'
    'M|SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowDigest'
    'M|SOFTWARE\Policies\Microsoft\Windows\AppPrivacy|LetAppsActivateWithVoiceAboveLock'
    'M|SOFTWARE\Policies\Microsoft\Windows\AppPrivacy|LetAppsActivateWithVoice'
    'M|Software\Policies\Microsoft\Windows\System|AllowDomainPINLogon'
    'M|Software\Policies\Microsoft\WindowsInkWorkspace|AllowWindowsInkWorkspace'
    'U|SOFTWARE\Policies\Microsoft\Windows\CloudContent|DisableThirdPartySuggestions'
    'M|Software\Policies\Microsoft\Windows\Kernel DMA Protection|DeviceEnumerationPolicy'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|LimitBlankPasswordUse'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|SCENoApplyLegacyAuditPolicy'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|RequireSignOrSeal'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SealSecureChannel'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SignSecureChannel'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|DisablePasswordChange'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|MaximumPasswordAge'
    'M|SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|RequireStrongKey'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs'
    'M|SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|CachedLogonsCount'
    'M|SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|SCRemoveOption'
    'M|SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature'
    'M|SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|EnablePlainTextPassword'
    'M|SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RequireSecuritySignature'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|EveryoneIncludesAnonymous'
    'M|SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RestrictNullSessAccess'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|RestrictRemoteSAM'
    'M|SYSTEM\CurrentControlSet\Control\LSA\MSV1_0|allownullsessionfallback'
    'M|SYSTEM\CurrentControlSet\Control\LSA\pku2u|AllowOnlineID'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|SupportedEncryptionTypes'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|NoLMHash'
    'M|SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel'
    'M|SYSTEM\CurrentControlSet\Services\LDAP|LDAPClientIntegrity'
    'M|SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec'
    'M|SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec'
    'M|SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy|Enabled'
    'M|SYSTEM\CurrentControlSet\Control\Session Manager|ProtectionMode'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|FilterAdministratorToken'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorAdmin'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorUser'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableInstallerDetection'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableSecureUIAPaths'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA'
    'M|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableVirtualization'
    'U|SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications|NoToastApplicationNotificationOnLockScreen'
    'U|SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments|SaveZoneInformation'
    'M|SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths|\\*\NETLOGON'
    'M|SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths|\\*\SYSVOL'
    'M|SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription|EnableTranscripting'
    'M|SOFTWARE\Policies\Microsoft\Windows\DeviceGuard|HypervisorEnforcedCodeIntegrity'
    'M|SOFTWARE\Policies\Microsoft\MicrosoftAccount|DisableUserAuth'
    'M|SOFTWARE\Policies\Microsoft\Windows\System|EnableSmartScreen'
)
# END STIG-REGISTRY
$stig = Invoke-Section 'stig' {
    $machine = @(); $userPaths = @()
    foreach ($line in $stigRegistryList) {
        Step-Spinner 'Collecting DISA STIG registry values'
        $parts = $line.Split('|')
        if ($parts[0] -eq 'U') { $userPaths += , $parts; continue }
        $v = Get-RegValue ('HKLM:\' + $parts[1]) $parts[2]
        if ($null -ne $v) { $machine += [ordered]@{ k = $parts[1]; n = $parts[2]; v = $(if ($v -is [array]) { ($v -join ',') } else { $v }) } }
    }
    $users = @()
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $vals = @()
        foreach ($parts in $userPaths) {
            $v = Get-RegValue ("Registry::HKEY_USERS\$($hive.PSChildName)\" + $parts[1]) $parts[2]
            if ($null -ne $v) { $vals += [ordered]@{ k = $parts[1]; n = $parts[2]; v = $(if ($v -is [array]) { ($v -join ',') } else { $v }) } }
        }
        $users += [ordered]@{ sid = $hive.PSChildName; values = $vals }
    }
    [ordered]@{
        products = [ordered]@{
            edge    = [bool]((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') -or (Test-Path -LiteralPath "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"))
            chrome  = [bool]((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Google\Chrome'))
            firefox = [bool]((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'))
            office  = [bool]((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot'))
        }
        machine  = $machine
        users    = $users
    }
}
# ------------------------------------------------------------------ write
$hostName =if ($hostInfo) { $hostInfo.name } else { "$env:COMPUTERNAME" }
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
        options          = [ordered]@{ skipAcl = [bool]$SkipAcl; checkUpdates = [bool]$CheckUpdates }
        # ToArray(): @() over a List inside a hashtable throws "Argument types do not match".
        sectionsCollected = $script:Sections.ToArray()
        collectionErrors = $script:Errors.ToArray()
        sectionSeconds   = $script:SectionSeconds
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
    stig                 = $stig
    software             = @($software | Where-Object { $_ })
    updatesPending       = $updatesPending
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
# A conditional that can produce an empty array in one branch (…$(if (cond) { @(...) } else { @() })…)
# can come out of ConvertTo-Json as a bare null instead of [], even on PowerShell 7, once it sits deep
# enough inside a large nested structure. Harmless for the analyzer (every reader of these two fields
# wraps with @(... | Where-Object { $_ })), but it should read as an empty array like every other list
# field in the schema, not as null. Scoped by field name: other fields use null on purpose (for
# example startableBy, where null means "could not be determined", not "nobody").
foreach ($arrayField in 'writableBy', 'ancestorControl') {
    $json = [regex]::Replace($json, "`"$arrayField`":\s*null", "`"$arrayField`": []")
}
[System.IO.File]::WriteAllText("$base.json", $json, (New-Object System.Text.UTF8Encoding($false)))
$outPath = "$base.json"
if (-not $NoZip) {
    try {
        Step-Spinner 'Compressing the snapshot'
        Compress-Archive -LiteralPath "$base.json" -DestinationPath "$base.zip" -Force
        Remove-Item -LiteralPath "$base.json"
        $outPath = "$base.zip"
    }
    catch { Stop-Spinner; Write-Warning "Compression failed ($($_.Exception.Message)); the JSON is kept." }
}
Stop-Spinner
$slowest = @($script:SectionSeconds.GetEnumerator() | Where-Object { $_.Value -ge 2 } | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Key) $($_.Value) s" })
if ($slowest.Count -gt 0) { Write-Host "Slowest sections: $($slowest -join ', ')" }
Write-Host "Sections: $($script:Sections.Count) collected, $($script:Errors.Count) error(s)."
Write-Host "Snapshot: $outPath"
