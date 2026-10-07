# Optional Gemini step. The ground rules: Findings are computed locally, and the report is saved
# before anything is sent. The model writes on top of them and never decides what a finding is.
# Nothing leaves without consent: with no flag there is no call, and HostBadger never prompts on its
# own. -SendToAI is the consent, and -AiConfirm adds a y/N question. Host names, domains, accounts,
# groups, SIDs, paths, the names of services, tasks, autoruns and adapters, and addresses are
# swapped for tokens first. The map never leaves this machine, and the collector's error messages
# are never sent. -AiDryRun writes the exact prompt to a file and sends nothing. Every real send
# leaves the prompt and the reply next to the report (<report>_ai_prompt.txt and _ai_response.json),
# still pseudonymized. The API key comes from -ApiKey or $env:GEMINI_API_KEY.

# Names that are the same on every Windows machine. They help the model and give nothing away.
$script:AiKeepNames = @(
    'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount', 'Everyone', 'Authenticated Users',
    'SYSTEM', 'LocalSystem', 'LocalService', 'NetworkService', 'TrustedInstaller', 'Spooler',
    'Domain Admins', 'Domain Users', 'Domain Computers', 'Domain Controllers', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Users', 'Guests', 'Power Users', 'Remote Desktop Users', 'Remote Management Users',
    'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'Network Configuration Operators',
    'Performance Log Users', 'Performance Monitor Users', 'Distributed COM Users', 'Event Log Readers',
    'Hyper-V Administrators', 'IIS_IUSRS', 'Replicator', 'Cryptographic Operators'
)
# Listener and excluded processes that are stock Windows or well-known server engines.
$script:AiKeepProcesses = @('svchost', 'system', 'lsass', 'services', 'wininit', 'spoolsv', 'dns', 'sqlservr', 'mysqld', 'postgres',
    'redis-server', 'mongod', 'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32',
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')
# Stock Windows tools under System32 and SysWOW64 look the same everywhere, and the model needs to
# see that a scripting host is excluded from scanning.
$script:AiKeepPathPattern = '(?i)^[a-z]:\\windows\\(?:system32|syswow64)\\(?:windowspowershell\\v1\.0\\)?(?:powershell|powershell_ise|cmd|wscript|cscript|mshta|rundll32|regsvr32|svchost|msiexec|certutil|bitsadmin|wmic|schtasks|net|reg|sc)\.exe$'
# Account prefixes that are not a domain.
$script:AiKeepAccountPrefixes = @('NT AUTHORITY', 'NT SERVICE', 'BUILTIN', 'Window Manager', 'Font Driver Host', 'NT VIRTUAL MACHINE')
$script:AiTokenPattern = '\b(?:HOSTFQDN|HOST|DOMAIN|NETBIOS|USER|GROUP|SID|PATH|UNC|SERVICE|TASK|AUTORUN|ADAPTER|PROC|IP)-\d+\b'
$script:AiSidPattern = 'S-1-(?:5-21|12-1|5-80|5-82|5-83)(?:-\d+)+'
# Not inside a longer dotted number, and not a CIS rule number ("CIS 18.10.7.3"), because those are
# not addresses.
$script:AiIpPattern = '(?<!CIS )(?<![\d.])(?!0\.0\.0\.0(?!\d)|127\.0\.0\.1(?!\d))(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)'

# --------------------------------------------------------------------------
# Pseudonymizer
# --------------------------------------------------------------------------
function New-HostPseudonymizer {
    # $Snapshots holds every host's snapshot and $Findings the findings that will be sent.
    # $HostOrder is the order in which hosts will be listed, so that HOST-1 is the first one.
    param($Snapshots, $Findings, [string[]]$HostOrder = @())
    $pz = [PSCustomObject]@{
        Candidates     = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        Forward        = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        Reverse        = @{}
        Counters       = @{}
        Hints          = @{}
        Ordered        = $null
        DomainSuffixes = @()
    }
    $keep = @{}; foreach ($k in $script:AiKeepNames) { $keep[$k.ToLower()] = $true }
    $keepProc = @{}; foreach ($k in $script:AiKeepProcesses) { $keepProc[$k.ToLower()] = $true }
    $keepPrefix = @{}; foreach ($k in $script:AiKeepAccountPrefixes) { $keepPrefix[$k.ToLower()] = $true }

    $add = {
        param($Value, [string]$Prefix)
        $v = "$Value".Trim()
        if (-not $v -or $v.Length -lt 3) { return }
        if ($keep.ContainsKey($v.ToLower())) { return }
        if ($Prefix -eq 'PATH' -and $v -match $script:AiKeepPathPattern) { return }
        if ($Prefix -eq 'PROC' -and $keepProc.ContainsKey($v.ToLower())) { return }
        if (-not $pz.Candidates.ContainsKey($v)) { $pz.Candidates[$v] = $Prefix }
    }
    # DOMAIN\name, DOMAIN/name, name@domain.tld or a bare name.
    $addAccount = {
        param($Value, [string]$Kind = 'USER')
        $v = "$Value".Trim()
        if (-not $v) { return }
        if ($v -match '^([^\\/]+)[\\/](.+)$') {
            if ($keepPrefix.ContainsKey($Matches[1].ToLower())) { return }
            $left = $Matches[1]; $right = $Matches[2]
            & $add $left 'NETBIOS'; & $add $right $Kind
        }
        elseif ($v -match '^([^@]+)@(.+)$') { & $add $Matches[1] $Kind }
        else { & $add $v $Kind }
    }

    $suffixes = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Snapshots | Where-Object { $_ })) {
        $hn = Get-SnapshotHostName $s
        & $add $hn 'HOST'; & $add $s.host.name 'HOST'; & $add $s.meta.computerName 'HOST'
        $dns = "$($s.host.dnsDomain)"
        if ($dns) { & $add $dns 'DOMAIN'; $suffixes.Add($dns); & $add "$hn.$dns" 'HOSTFQDN' }
        foreach ($u in @($s.localAccounts.users | Where-Object { $_ })) { & $add $u.name 'USER' }
        foreach ($m in @($s.localAccounts.administrators | Where-Object { $_ })) {
            $kind = if ("$($m.class)" -match '(?i)group') { 'GROUP' } else { 'USER' }
            $p = "$($m.path)"
            if ($p -match '^([^\\/]+)[\\/](.+)$' -and $Matches[1] -ieq $hn) { & $add $Matches[2] $kind }
            else { & $addAccount $p $kind }
        }
        # Rights held by an account that could not be turned into a SID are listed by name.
        if ($s.securityPolicy -and $s.securityPolicy.privilegeRights) {
            foreach ($pn in @($s.securityPolicy.privilegeRights.PSObject.Properties)) {
                foreach ($member in @($pn.Value)) { if ("$member" -and "$member" -notmatch '^S-1-') { & $addAccount "$member" } }
            }
        }
        foreach ($svc in @($s.services | Where-Object { $_ })) {
            & $addAccount $svc.account
            & $add $svc.pathName 'PATH'; & $add $svc.executable 'PATH'
        }
        foreach ($t in @($s.scheduledTasks | Where-Object { $_ })) {
            # The author is a vendor or a person and is never printed in a finding. Masking it would
            # only damage words like "Microsoft".
            & $addAccount $t.userId; & $addAccount $t.groupId
            foreach ($a in @($t.actions | Where-Object { $_ })) { & $add $a.execute 'PATH'; & $add $a.executable 'PATH' }
        }
        foreach ($r in @($s.autoruns | Where-Object { $_ })) { & $add $r.command 'PATH'; & $add $r.executable 'PATH' }
        foreach ($p in @($s.defender.exclusionPaths | Where-Object { $_ })) { & $add $p 'PATH' }
        foreach ($p in @($s.defender.exclusionProcesses | Where-Object { $_ })) { & $add $p $(if ("$p" -match '[\\/]') { 'PATH' } else { 'PROC' }) }
    }

    # Names that only a finding mentions (the Objects of the findings follow a fixed pattern).
    foreach ($f in @($Findings | Where-Object { $_ })) {
        $o = "$($f.Object)"
        # Stock service names from the CIS list say what the finding is: keep them.
        if ($o -match '^service: (.+)$' -and "$($f.Type)" -ne 'service_should_be_disabled') { & $add $Matches[1] 'SERVICE' }
        elseif ($o -match '^task: (.+?) -> ') { & $add $Matches[1] 'TASK' }
        elseif ($o -match '^autorun: \S+ (.+)$') { & $add $Matches[1] 'AUTORUN' }
        elseif ($o -match '^adapter: (.+)$') { & $add $Matches[1] 'ADAPTER' }
        elseif ($o -match '^account: (.+)$') { & $add $Matches[1] 'USER' }
        elseif ($o -match '^member: (.+)$') { & $addAccount $Matches[1] }
        if ("$($f.Type)" -eq 'risky_listener' -and "$($f.Detail)" -match '^Listening on (\S+?)(?: by (.+?))?\.$') {
            if (@('0.0.0.0', '::', '127.0.0.1', '::1') -notcontains $Matches[1]) { & $add $Matches[1] 'IP' }
            if ($Matches[2]) { & $add $Matches[2] 'PROC' }
        }
    }

    # Longest first, so that "WKS-ACCT-017.corp.example" is replaced before "WKS-ACCT-017".
    $pz.Ordered = @($pz.Candidates.Keys | Sort-Object { $_.Length } -Descending)
    $pz.DomainSuffixes = @($suffixes | Select-Object -Unique)
    # Hosts first, in the order of the listing, so the tokens read HOST-1, HOST-2... in the order of
    # the table.
    foreach ($h in $HostOrder) { if ($pz.Candidates.ContainsKey($h)) { [void](Get-AiToken $pz $h 'HOST') } }
    foreach ($d in $pz.DomainSuffixes) { if ($pz.Candidates.ContainsKey($d)) { [void](Get-AiToken $pz $d 'DOMAIN') } }
    return $pz
}

function Get-AiToken {
    param($Pz, [string]$Value, [string]$Prefix)
    if ($Pz.Forward.ContainsKey($Value)) { return $Pz.Forward[$Value] }
    if (-not $Pz.Counters.ContainsKey($Prefix)) { $Pz.Counters[$Prefix] = 0 }
    $Pz.Counters[$Prefix]++
    $token = "$Prefix-$($Pz.Counters[$Prefix])"
    $Pz.Forward[$Value] = $token
    $Pz.Reverse[$token] = $Value
    if ($Prefix -eq 'PATH' -and (Test-CommandInUserWritablePlace $Value)) { $Pz.Hints[$token] = 'user-writable location' }
    return $token
}

# Finding text copies identifiers from the snapshot exactly as they are. Names that can also be an
# ordinary word (an account called "support", a task called "Update") are therefore matched with
# their exact case. Otherwise "Support ended" would turn into "USER-2 ended". Hosts, domains and
# paths are never prose, so those ignore case.
function Get-AiMatchOptions {
    param([string]$Prefix)
    if (@('HOST', 'HOSTFQDN', 'DOMAIN', 'NETBIOS', 'PATH', 'IP') -contains $Prefix) { return [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    return [System.Text.RegularExpressions.RegexOptions]::None
}

# "CIS 2.3.7.5, 2.3.7.6" is a list of rule numbers, and four dotted numbers look like an address.
# The references are set aside while we look for addresses.
$script:AiCisRefPattern = 'CIS \d+(?:\.\d+)*(?:(?:, and |, | - | and )\d+(?:\.\d+)*)*'

function Protect-AiText {
    param($Pz, [string]$Text)
    if (-not $Text) { return $Text }
    $out = $Text
    # Structural identifiers go first, and whatever they contain is replaced as a whole.
    $out = [regex]::Replace($out, $script:AiSidPattern, { param($m) Get-AiToken $Pz $m.Value 'SID' })
    $out = [regex]::Replace($out, '\\\\[^\s]+', { param($m) Get-AiToken $Pz $m.Value 'UNC' })
    foreach ($suffix in $Pz.DomainSuffixes) {
        $fq = '(?i)(?<![\w.\-])(?:[a-z0-9\-_]+\.)+' + [regex]::Escape($suffix) + '(?![\w\-])'
        $out = [regex]::Replace($out, $fq, { param($m) Get-AiToken $Pz $m.Value 'HOSTFQDN' })
    }
    foreach ($k in $Pz.Ordered) {
        $prefix = $Pz.Candidates[$k]
        $pattern = '(?<![\w.\-$])' + [regex]::Escape($k) + '(?![\w\-$]|\.[\w])'
        $out = [regex]::Replace($out, $pattern, { param($m) Get-AiToken $Pz $k $prefix }, (Get-AiMatchOptions $prefix))
    }
    $refs = New-Object System.Collections.Generic.List[string]
    $out = [regex]::Replace($out, $script:AiCisRefPattern, { param($m) $refs.Add($m.Value); "$([char]1)$($refs.Count - 1)$([char]1)" })
    $out = [regex]::Replace($out, $script:AiIpPattern, { param($m) Get-AiToken $Pz $m.Value 'IP' })
    $out = [regex]::Replace($out, "$([char]1)(\d+)$([char]1)", { param($m) $refs[[int]$m.Groups[1].Value] })
    return $out
}

function Unprotect-AiText {
    param($Pz, [string]$Text)
    if (-not $Text) { return $Text }
    return [regex]::Replace($Text, $script:AiTokenPattern, {
            param($m)
            if ($Pz.Reverse.ContainsKey($m.Value)) { return $Pz.Reverse[$m.Value] }
            return $m.Value
        })
}

# The last check before sending: if any real identifier is still there, we refuse.
function Test-AiLeak {
    param($Pz, [string]$Text)
    $leaks = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Pz.Ordered) {
        if ($k.Length -lt 4) { continue }
        if ([regex]::IsMatch($Text, '(?<![\w.\-@$])' + [regex]::Escape($k) + '(?![\w\-$]|\.[\w])', (Get-AiMatchOptions $Pz.Candidates[$k]))) { $leaks.Add($k) }
        if ($leaks.Count -ge 10) { break }
    }
    if ($Text -match $script:AiSidPattern) { $leaks.Add('(a domain, Entra or service SID)') }
    if ($Text -match '\\\\[^\s]+') { $leaks.Add('(a UNC path)') }
    if ([regex]::Replace($Text, $script:AiCisRefPattern, '') -match $script:AiIpPattern) { $leaks.Add('(an IP address)') }
    foreach ($suffix in $Pz.DomainSuffixes) { if ($Text.IndexOf($suffix, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add($suffix) } }
    # Any drive path left over, other than the stock Windows tools, is a path that wasn't masked.
    foreach ($m in [regex]::Matches($Text, '(?i)[a-z]:\\[^\s\\]\S*')) {
        if ($m.Value -notmatch $script:AiKeepPathPattern) { $leaks.Add('(a file path: ' + $m.Value.Substring(0, [Math]::Min(3, $m.Value.Length)) + '...)'); break }
    }
    return $leaks
}

# --------------------------------------------------------------------------
# Prompt
# --------------------------------------------------------------------------
$script:AiSystemPrompt = @"
You are a Windows endpoint security assistant helping the defenders who own
these hosts plan remediation. You receive deterministic hardening findings
that were already computed by a local tool from read-only host snapshots.
Treat them as established facts: do not recompute, dispute or add findings
that are not in the input.

Identifiers were replaced by placeholder tokens (HOST-3, DOMAIN-1, USER-2,
GROUP-1, SID-4, PATH-7, SERVICE-2, TASK-1, AUTORUN-1, ADAPTER-1, PROC-2,
IP-1...). Always refer to objects by their token exactly as written; never
guess the real name. Names that are the same on every Windows machine
(Administrator, Guest, Users, Everyone...) are left as is. A PATH token
listed under "Path tokens" is in a location low-privileged users can write.

A section "Coverage gaps" lists checks that could NOT be evaluated on some
hosts. Their state is unknown: never describe those hosts as clean for those
checks, and mention the gap where it matters.

Your output is for defenders only. Describe risk in terms of impact and
business consequence; do not write attack procedures, commands or
exploitation steps.

Produce:
1. executive_summary: 4-6 sentences for management. Overall posture of the
   fleet, the two or three exposures that matter most and why, in plain
   language. Say if coverage gaps limit the picture.
2. remediation_plan: an ordered list of work packages. Group related checks
   that share an owner or a change window (for example all Defender items,
   or all SMB and NetBIOS items). Order by risk reduction per unit of effort:
   exposures that let an attacker run code as SYSTEM or steal credentials
   first, then protection gaps, then hygiene. Each item: title, the check
   ids it covers, affected host tokens (at most 8), why this position in the
   order, effort (low | medium | high), and operational caveats (what can
   break, what to test first). Do NOT number the items yourself.
3. quick_wins: up to 5 changes that are low effort and low disruption.
4. monitoring: for exposures that cannot be fixed immediately, what to
   monitor meanwhile: relevant Windows event IDs and a short description of
   the detection logic for a SIEM. Only reference event IDs you are confident
   exist and apply.
5. comparison_narrative: only if a "Comparison" section is present, 2-4
   sentences on the trend (real progress vs churn). Omit otherwise.
6. host_priorities: the hosts to work on first, with a rank (1 = first), the
   host tokens, and a one sentence rationale (what exposure, what role).
7. remediation_scripts: for the check ids where a safe, standard fix can be
   expressed as PowerShell, give a snippet. Each: the check id, a short
   PowerShell block using native cmdlets (Set-MpPreference,
   Set-SmbServerConfiguration, registry or policy settings; use the tokens
   as placeholders the operator will substitute), and caveats. Only for
   changes that are routine and reversible; for anything destructive or
   environment-specific, return guidance in caveats and keep the script
   minimal or empty. Never include credential theft or offensive code.
8. triage: re-rank the fired checks by real exploitability in THIS fleet
   (reachability, privilege, how many hosts, host role), not by static
   severity alone. Each: a rank (1 = fix first), the check ids, the key
   tokens, and a one sentence rationale.

If no findings are provided, say so plainly and return empty lists.

Respond with one JSON object only, no markdown fences:
{ "executive_summary": "...",
  "remediation_plan": [ { "title": "...", "checks": ["..."], "objects": ["..."],
      "rationale": "...", "effort": "low|medium|high", "caveats": "..." } ],
  "quick_wins": ["..."],
  "monitoring": [ { "checks": ["..."], "event_ids": ["4688"], "guidance": "..." } ],
  "comparison_narrative": "...",
  "host_priorities": [ { "rank": 1, "hosts": ["HOST-1"], "rationale": "..." } ],
  "remediation_scripts": [ { "check": "...", "powershell": "...", "caveats": "..." } ],
  "triage": [ { "rank": 1, "checks": ["..."], "objects": ["..."], "rationale": "..." } ] }
"@

# The raw prompt, with real names. The whole of it goes through Protect-AiText, so nothing reaches
# the model unmasked, whatever text a check wrote.
function New-AiPromptRaw {
    param($Findings, $Hosts, $Comparison, [int]$MaxLinesPerCheck = 12)
    $sevOrder = @('Critical', 'High', 'Medium', 'Low')
    $lines = New-Object System.Collections.Generic.List[string]
    $hostList = @($Hosts | Sort-Object { $_.Score.Score }, Name)
    $avg = [int][Math]::Round((@($hostList | ForEach-Object { $_.Score.Score }) | Measure-Object -Average).Average)
    $sevText = ($sevOrder | ForEach-Object { $s = $_; "{0} {1}" -f @($Findings | Where-Object { $_.Severity -eq $s }).Count, $s.ToLower() }) -join ', '
    $roles = ($hostList | Group-Object Role | Sort-Object Name | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    $lines.Add("Fleet: $($hostList.Count) host(s) ($roles). Average hardening score $avg/100. Findings: $sevText.")
    $lines.Add('')
    $lines.Add('Hosts (name, role, operating system, score, findings, checks not evaluated):')
    foreach ($h in $hostList) {
        $n = @($Findings | Where-Object { $_.Host -eq $h.Name }).Count
        $lines.Add("- $($h.Name): $($h.Role), $($h.Os), score $($h.Score.Grade) $($h.Score.Score)/100, $n finding(s), $(@($h.NotEvaluated).Count) not evaluated.")
    }
    $gaps = @($hostList | ForEach-Object { $_.NotEvaluated } | Where-Object { $_ })
    if ($gaps.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Coverage gaps (checks NOT evaluated: state unknown, not clean):')
        foreach ($g in ($gaps | Group-Object Type | Sort-Object Name)) {
            # The collector's error text never leaves. The model only learns that the data was
            # missing.
            $why = (@($g.Group | ForEach-Object { ("$($_.Reason)" -replace "(failed): [^;]*", '$1') } | Select-Object -Unique) -join ' / ')
            $lines.Add("- $($g.Name) ($($script:CheckCatalog[$g.Name].Title)): $(@($g.Group | ForEach-Object { $_.Host } | Select-Object -Unique) -join ', '). $why")
        }
    }
    $lines.Add('')
    $lines.Add('Findings grouped by check (severity, host, object, detail):')
    $groups = $Findings | Group-Object Type | Sort-Object { - ($_.Group | ForEach-Object { $script:SeverityRank[$_.Severity] } | Measure-Object -Maximum).Maximum }, @{ Expression = 'Count'; Descending = $true }
    foreach ($g in $groups) {
        $meta = $script:CheckCatalog[$g.Name]
        $ordered = @($g.Group | Sort-Object { - $script:SeverityRank[$_.Severity] }, Host, Object)
        $worst = $ordered[0].Severity
        $nHosts = @($ordered | ForEach-Object { $_.Host } | Select-Object -Unique).Count
        $lines.Add("## [$worst] $($g.Name): $($meta.Title) ($($ordered.Count) finding(s) on $nHosts host(s))")
        foreach ($f in ($ordered | Select-Object -First $MaxLinesPerCheck)) { $lines.Add("- [$($f.Severity)] $($f.Host) | $($f.Object) | $($f.Detail)") }
        if ($ordered.Count -gt $MaxLinesPerCheck) {
            $shown = @($ordered | Select-Object -First $MaxLinesPerCheck | ForEach-Object { $_.Host } | Select-Object -Unique).Count
            $lines.Add("- ... and $($ordered.Count - $MaxLinesPerCheck) more finding(s) with the same issue ($($nHosts - $shown) more host(s))")
        }
    }
    if ($Comparison -and (@($Comparison.New).Count + @($Comparison.Resolved).Count) -gt 0) {
        $lines.Add('')
        $lines.Add('Comparison with the previous run (already computed):')
        foreach ($f in @($Comparison.New | Select-Object -First 30)) { $lines.Add("- NEW [$($f.Severity)] $($f.Type): $($f.Host) | $($f.Object)") }
        foreach ($f in @($Comparison.Resolved | Select-Object -First 30)) { $lines.Add("- RESOLVED [$($f.Severity)] $($f.Type): $($f.Host) | $($f.Object)") }
        $lines.Add("- Still present: $(@($Comparison.Persisting).Count)")
    }
    return ($lines -join "`n")
}

function New-AiPrompt {
    param($Findings, $Hosts, $Pz, $Comparison, [int]$MaxLinesPerCheck = 12)
    $text = Protect-AiText $Pz (New-AiPromptRaw -Findings $Findings -Hosts $Hosts -Comparison $Comparison -MaxLinesPerCheck $MaxLinesPerCheck)
    # Which path tokens are in a place where low-privileged users can write. That is a class, not a
    # name.
    $writable = @($Pz.Hints.Keys | Where-Object { $text -match ('\b' + [regex]::Escape($_) + '\b') } | Sort-Object { [int]($_ -replace '\D', '') })
    if ($writable.Count -gt 0) { $text += "`n`nPath tokens (in a location low-privileged users can write: profile, Temp, ProgramData, Downloads, drive root):`n- $($writable -join ', ')" }
    return $text
}

# The same text that goes into the request: the system instruction, then the user prompt. The dry
# run and the copy kept before a real send both use it.
function Write-AiPromptFile {
    param([string]$Path, [string]$UserPrompt)
    $text = "=== SYSTEM ===`n$script:AiSystemPrompt`n`n=== USER ===`n$UserPrompt`n"
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# report_x.html -> report_x_ai_prompt.txt, in the same folder.
function Get-AiSidecarPath {
    param([string]$ReportPath, [string]$Suffix)
    $dir = [System.IO.Path]::GetDirectoryName($ReportPath)
    Join-Path $dir ([System.IO.Path]::GetFileNameWithoutExtension($ReportPath) + $Suffix)
}

# What came back, before the tokens are swapped back to real names.
function Write-AiResponseFile {
    param([string]$Path, $Raw)
    [System.IO.File]::WriteAllText($Path, ($Raw | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
}

# --------------------------------------------------------------------------
# Talking to Gemini: HttpClient, a spinner, and retries with a growing wait.
# --------------------------------------------------------------------------
function Invoke-HttpPostWithSpinner {
    param([string]$Uri, [string]$JsonBody, [string]$Message = "Contacting Gemini", [int]$TimeoutSeconds = 180, [hashtable]$Headers = @{})
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    # Windows PowerShell 5.1 can default to TLS 1.0.
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    foreach ($hdr in $Headers.Keys) { [void]$client.DefaultRequestHeaders.Add($hdr, $Headers[$hdr]) }
    $content = New-Object System.Net.Http.StringContent($JsonBody, [System.Text.Encoding]::UTF8, 'application/json')
    try {
        $task = $client.PostAsync($Uri, $content)
        $spin = @('|', '/', '-', '\'); $i = 0
        while (-not $task.IsCompleted) { Write-Host -NoNewline "`r$Message $($spin[$i % 4])  "; Start-Sleep -Milliseconds 120; $i++ }
        Write-Host "`r$Message... done.          "
        $resp = $task.GetAwaiter().GetResult()
        return [PSCustomObject]@{ StatusCode = [int]$resp.StatusCode; IsSuccess = $resp.IsSuccessStatusCode; Body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
    }
    finally { $client.Dispose() }
}

# MaxAttempts 0 keeps trying until it works (Ctrl+C to stop). Only timeouts, 429 and 5xx are
# retried, because a 400, 401 or 403 won't fix itself.
function Invoke-GeminiAnalysis {
    param([string]$UserPrompt, [string]$ApiKey, [string]$Model, [int]$MaxAttempts = 3, [int]$TimeoutSeconds = 180)
    $unlimited = $MaxAttempts -le 0
    $ofText = if ($unlimited) { '' } else { "/$MaxAttempts" }
    $canRetry = { param($n) $unlimited -or $n -lt $MaxAttempts }
    # Wait 2, 4, 8... seconds, at most a minute.
    $backoff = { param($n) [int][Math]::Min(60, [Math]::Pow(2, [Math]::Min($n, 6))) }
    $body = @{
        system_instruction = @{ parts = @(@{ text = $script:AiSystemPrompt }) }
        contents           = @(@{ role = 'user'; parts = @(@{ text = $UserPrompt }) })
        generationConfig   = @{ temperature = 0.2; responseMimeType = 'application/json' }
    } | ConvertTo-Json -Depth 10
    # The key goes in a header, not in the URL, so it stays out of proxy logs.
    # HOSTBADGER_GEMINI_BASEURL points at an internal gateway (or at the test endpoint).
    $base = if ($env:HOSTBADGER_GEMINI_BASEURL) { $env:HOSTBADGER_GEMINI_BASEURL.TrimEnd('/') } else { 'https://generativelanguage.googleapis.com' }
    $uri = "$base/v1beta/models/${Model}:generateContent"
    $transient = @(429, 500, 502, 503, 504)
    $result = $null
    for ($attempt = 1; $unlimited -or $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = Invoke-HttpPostWithSpinner -Uri $uri -JsonBody $body -Headers @{ 'x-goog-api-key' = $ApiKey } -Message "Contacting Gemini (attempt $attempt$ofText)" -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            $inner = $_.Exception; $isTimeout = $false
            while ($inner) { if ($inner -is [System.Threading.Tasks.TaskCanceledException] -or $inner -is [TimeoutException]) { $isTimeout = $true; break }; $inner = $inner.InnerException }
            if ($isTimeout -and (& $canRetry $attempt)) {
                $wait = & $backoff $attempt
                Write-Host "Gemini timed out after $TimeoutSeconds s, retrying in $wait s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $wait; continue
            }
            Write-Host "ERROR: Gemini call failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
        if ($result.IsSuccess) { break }
        if ($transient -contains $result.StatusCode -and (& $canRetry $attempt)) {
            $wait = & $backoff $attempt
            Write-Host "Gemini HTTP $($result.StatusCode), retrying in $wait s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $wait; $result = $null; continue
        }
        Write-Host "ERROR: Gemini call failed: HTTP $($result.StatusCode). $($result.Body)" -ForegroundColor Red
        return $null
    }
    if (-not $result) { return $null }
    try { $resp = $result.Body | ConvertFrom-Json } catch { Write-Host 'ERROR: Gemini response is not valid JSON.' -ForegroundColor Red; return $null }
    $raw = $resp.candidates[0].content.parts[0].text
    $raw = ($raw -replace '^\s*```(?:json)?', '') -replace '```\s*$', ''
    try { return ($raw | ConvertFrom-Json) } catch { Write-Host "ERROR: model did not return clean JSON:`n$raw" -ForegroundColor Red; return $null }
}

# --------------------------------------------------------------------------
# Put the real names back, and drop anything about a check that didn't fire, because the model can't
# invent findings.
# --------------------------------------------------------------------------
function ConvertFrom-AiResponse {
    param($Raw, $Pz, $Findings, [string]$Model)
    $valid = @{}; foreach ($f in $Findings) { $valid[$f.Type] = $true }
    $u = { param($t) Unprotect-AiText $Pz "$t" }
    $plan = @()
    foreach ($item in @($Raw.remediation_plan | Where-Object { $_ })) {
        $checks = @($item.checks | Where-Object { $valid.ContainsKey("$_") })
        if ($checks.Count -eq 0) { continue }
        $effort = "$($item.effort)".ToLower(); if (@('low', 'medium', 'high') -notcontains $effort) { $effort = '' }
        $plan += [PSCustomObject]@{
            Title     = & $u ($item.title -replace '^\s*\d+[\.\)]\s*', '')
            Checks    = $checks
            Objects   = @($item.objects | Where-Object { $_ } | Select-Object -First 8 | ForEach-Object { & $u $_ })
            Rationale = & $u $item.rationale
            Effort    = $effort
            Caveats   = & $u $item.caveats
        }
    }
    $monitoring = @()
    foreach ($m in @($Raw.monitoring | Where-Object { $_ })) {
        $monitoring += [PSCustomObject]@{
            Checks   = @($m.checks | Where-Object { $valid.ContainsKey("$_") })
            EventIds = @($m.event_ids | Where-Object { "$_" -match '^\d{3,5}$' } | ForEach-Object { "$_" })
            Guidance = & $u $m.guidance
        }
    }
    # Only hosts that exist: a token the map doesn't know is dropped.
    $hostPrio = @()
    foreach ($hp in @($Raw.host_priorities | Where-Object { $_ })) {
        $hosts = @($hp.hosts | Where-Object { $_ -and $Pz.Reverse.ContainsKey("$_") } | Select-Object -First 8 | ForEach-Object { & $u $_ })
        if ($hosts.Count -eq 0) { continue }
        $rank = 0; try { $rank = [int]$hp.rank } catch { $rank = 0 }
        $hostPrio += [PSCustomObject]@{ Rank = $rank; Hosts = $hosts; Rationale = & $u $hp.rationale }
    }
    $hostPrio = @($hostPrio | Sort-Object { if ($_.Rank -gt 0) { $_.Rank } else { 9999 } })
    $remScripts = @()
    foreach ($rs in @($Raw.remediation_scripts | Where-Object { $_ })) {
        $chk = "$($rs.check)"
        if (-not $valid.ContainsKey($chk)) { continue }
        $ps = & $u $rs.powershell
        if (-not $ps -and -not $rs.caveats) { continue }
        $remScripts += [PSCustomObject]@{ Check = $chk; PowerShell = $ps; Caveats = & $u $rs.caveats }
    }
    $triage = @()
    foreach ($tr in @($Raw.triage | Where-Object { $_ })) {
        $checks = @($tr.checks | Where-Object { $valid.ContainsKey("$_") })
        if ($checks.Count -eq 0) { continue }
        $rank = 0; try { $rank = [int]$tr.rank } catch { $rank = 0 }
        $triage += [PSCustomObject]@{
            Rank      = $rank
            Checks    = $checks
            Objects   = @($tr.objects | Where-Object { $_ } | Select-Object -First 8 | ForEach-Object { & $u $_ })
            Rationale = & $u $tr.rationale
        }
    }
    $triage = @($triage | Sort-Object { if ($_.Rank -gt 0) { $_.Rank } else { 9999 } })

    return [PSCustomObject]@{
        Model               = $Model
        ExecutiveSummary    = & $u $Raw.executive_summary
        RemediationPlan     = $plan
        QuickWins           = @($Raw.quick_wins | Where-Object { $_ } | Select-Object -First 5 | ForEach-Object { & $u $_ })
        Monitoring          = $monitoring
        ComparisonNarrative = if ($Raw.comparison_narrative) { & $u $Raw.comparison_narrative } else { '' }
        HostPriorities      = $hostPrio
        RemediationScripts  = $remScripts
        Triage              = $triage
        MaskedIdentifiers   = $Pz.Reverse.Count
    }
}

function ConvertTo-AiSectionHtml {
    param($AiResult)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    & $w "<div class='ai-section'><div class='ai-badge'>AI-assisted &middot; $(& $H $AiResult.Model) &middot; $($AiResult.MaskedIdentifiers) identifiers pseudonymized before sending</div>"
    # An HTML entity instead of a literal emoji, because PS 5.1 reads these BOM-less files as ANSI.
    & $w "<h2><span class='ai-robot' role='img' aria-label='AI' style='margin-right:8px'>&#x1F916;</span>AI summary and remediation plan</h2>"
    & $w "<p>$(& $H $AiResult.ExecutiveSummary)</p>"
    if ($AiResult.ComparisonNarrative) { & $w "<h3>Trend since previous run</h3><p>$(& $H $AiResult.ComparisonNarrative)</p>" }
    if (@($AiResult.QuickWins).Count -gt 0) {
        & $w '<h3>Quick wins</h3><ul>'
        foreach ($q in $AiResult.QuickWins) { & $w "<li>$(& $H $q)</li>" }
        & $w '</ul>'
    }
    if (@($AiResult.HostPriorities).Count -gt 0) {
        & $w "<h3>Hosts to work on first</h3><div class='table-wrap'><table><tr><th>#</th><th>Hosts</th><th>Why</th></tr>"
        $i = 0
        foreach ($p in $AiResult.HostPriorities) {
            $i++
            $rank = if ($p.Rank -gt 0) { $p.Rank } else { $i }
            & $w "<tr class='data-row'><td>$rank</td><td>$(& $H ($p.Hosts -join ', '))</td><td>$(& $H $p.Rationale)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.RemediationPlan).Count -gt 0) {
        & $w '<h3>Suggested remediation order</h3><ol>'
        foreach ($p in $AiResult.RemediationPlan) {
            $effort = if ($p.Effort) { " <span class='check-id'>effort: $($p.Effort)</span>" } else { '' }
            $objs = if (@($p.Objects).Count -gt 0) { "<br><span class='meta'>Objects: $(& $H ($p.Objects -join ', '))</span>" } else { '' }
            $cav = if ($p.Caveats) { "<br><span class='meta'>Caveats: $(& $H $p.Caveats)</span>" } else { '' }
            & $w "<li><b>$(& $H $p.Title)</b>$effort<br>$(& $H $p.Rationale)<br><span class='meta'>Checks: $(($p.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</span>$objs$cav</li>"
        }
        & $w '</ol>'
    }
    if (@($AiResult.Monitoring).Count -gt 0) {
        & $w "<h3>Monitoring until fixed</h3><div class='table-wrap'><table><tr><th>Checks</th><th>Event IDs</th><th>Guidance</th></tr>"
        foreach ($m in $AiResult.Monitoring) {
            & $w "<tr class='data-row'><td>$(($m.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</td><td>$(& $H ($m.EventIds -join ', '))</td><td>$(& $H $m.Guidance)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.Triage).Count -gt 0) {
        & $w "<h3>Exploitability triage (fix order for this fleet)</h3><div class='table-wrap'><table class='ai-triage'><tr><th>#</th><th>Checks</th><th>Objects</th><th>Why</th></tr>"
        $i = 0
        foreach ($t in $AiResult.Triage) {
            $i++
            $rank = if ($t.Rank -gt 0) { $t.Rank } else { $i }
            & $w "<tr class='data-row'><td>$rank</td><td>$(($t.Checks | ForEach-Object { "<code>$_</code>" }) -join ' ')</td><td>$(& $H ($t.Objects -join ', '))</td><td>$(& $H $t.Rationale)</td></tr>"
        }
        & $w '</table></div>'
    }
    if (@($AiResult.RemediationScripts).Count -gt 0) {
        & $w '<h3>Remediation scripts (review before running)</h3>'
        & $w "<p class='meta'>Generated PowerShell using native cmdlets, with names as placeholders. HostBadger never runs it. Treat it as a starting point: read it, substitute the real values, and test on a pilot host first.</p>"
        foreach ($s in $AiResult.RemediationScripts) {
            & $w "<div style='margin:10px 0'><span class='check-id'>Fix for <code>$(& $H $s.Check)</code></span>"
            if ($s.PowerShell) { & $w "<div class='ai-script'>$(& $H $s.PowerShell)</div>" }
            if ($s.Caveats) { & $w "<div class='meta'>Caveats: $(& $H $s.Caveats)</div>" }
            & $w '</div>'
        }
    }
    & $w "<p class='meta'>Generated by a language model from findings computed locally. Verify every recommendation before acting; the deterministic sections of this report are authoritative.</p></div>"
    return $sb.ToString()
}
