<#
.SYNOPSIS
    Builds data\cis-map.json: for every rule of the CIS Windows 11 Enterprise
    benchmark, the number of the same setting in the CIS Windows 10 Enterprise
    and Windows Server 2022, 2019 and 2016 benchmarks.

.DESCRIPTION
    Developer tool, not part of a HostBadger run: it only reads local files, it
    does not download anything. Clone (or download) the MIT-licensed
    ansible-lockdown roles yourself and point the parameters at them:
      https://github.com/ansible-lockdown/Windows-11-CIS
      https://github.com/ansible-lockdown/Windows-10-CIS
      https://github.com/ansible-lockdown/Windows-2022-CIS
      https://github.com/ansible-lockdown/Windows-2019-CIS
      https://github.com/ansible-lockdown/Windows-2016-CIS
    Every *.yml under the folder (its tasks folder when there is one) is read
    as text: a rule starts at a top-level task named "<number> | <kind> |
    <title>". The gpo_creation tasks of the 2019 and 2016 roles repeat the
    same rules and are skipped.

    Two rules are the same setting when they write the same registry value
    (key and value name). Rules without a registry value (user rights, audit
    policy, password policy) are matched on their title, without the expected
    value. A Windows 11 rule can map to two server rules: the domain controller
    and the member server variants (user rights, mostly). HostBadger's checks
    and expected values stay the Windows 11 ones; the map only changes which
    rule number a finding quotes on a server. A rule with no server counterpart
    is quoted with its Windows 11 number and says so.
.PARAMETER Win11Dir
    Folder of the Windows-11-CIS role.
.PARAMETER Server2022Dir
    Folder of the Windows-2022-CIS role.
.PARAMETER Server2019Dir
    Folder of the Windows-2019-CIS role.
.PARAMETER Win10Dir
    Folder of the Windows-10-CIS role.
.PARAMETER Server2016Dir
    Folder of the Windows-2016-CIS role.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Win11Dir,
    [Parameter(Mandatory)][string]$Server2022Dir,
    [Parameter(Mandatory)][string]$Server2019Dir,
    [Parameter(Mandatory)][string]$Win10Dir,
    [Parameter(Mandatory)][string]$Server2016Dir,
    [string]$OutMap = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\cis-map.json')
)
$ErrorActionPreference = 'Stop'

function Read-CisRules {
    # One row per top-level rule: number, title, level (L1/L2), applies (both/DC/MS), first registry value.
    param([string]$Dir)
    $tasks = Join-Path $Dir 'tasks'
    $base = if (Test-Path -LiteralPath $tasks) { $tasks } else { $Dir }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $base -Recurse -File -Filter *.yml | Where-Object { $_.FullName -notmatch 'gpo_creation' })) {
        $cur = $null
        foreach ($l in [System.IO.File]::ReadAllLines($f.FullName)) {
            if ($l -match '^- name: "(\d+(?:\.\d+)+)\s*\|\s*\w+\s*\|\s*(.*?)"?\s*$') {
                if ($cur) { $rows.Add([pscustomobject]$cur) }
                $cur = [ordered]@{ Rule = $Matches[1]; Title = $Matches[2]; Tags = ''; Path = ''; Name = '' }
                continue
            }
            if (-not $cur) { continue }
            if ($l -match '^\s+- ((?:level[12]|ngws)-[\w-]+)\s*$') { $cur.Tags += " $($Matches[1])" }
            elseif (-not $cur.Path -and $l -match '^\s+(?:path|key):\s*(.+?)\s*$') {
                $p = ($Matches[1] -replace '\s+#.*$', '').Trim('"', "'")
                # win_security_policy "Registry Values": key MACHINE\...\ValueName, the name is the last part.
                if ($p -match '^MACHINE\\(.+)\\([^\\]+)$') { $cur.Path = "HKLM\$($Matches[1])"; $cur.Name = $Matches[2] }
                else { $cur.Path = $p }
            }
            elseif ($cur.Path -and -not $cur.Name -and $l -match '^\s+(?:name|value):\s*(.+?)\s*$') { $cur.Name = ($Matches[1] -replace '\s+#.*$', '').Trim('"', "'") }
        }
        if ($cur) { $rows.Add([pscustomobject]$cur) }
    }
    foreach ($r in $rows) {
        $dc = $r.Tags -match 'domaincontroller'; $ms = $r.Tags -match 'memberserver|domainmember'
        $title = "$($r.Title)" -replace '\s*\((DC|MS) only\)', ''
        [pscustomobject]@{
            Rule    = $r.Rule
            # L1/L2 of the main profiles first; NG (next generation Windows security) and BL
            # (BitLocker) are the optional profiles.
            Level   = $(if ($r.Tags -match 'level2-(high|memberserver|domaincontroller|domainmember|corporate)') { 'L2' }
                elseif ($r.Tags -match 'level1-(corporate|memberserver|domaincontroller|domainmember)') { 'L1' }
                elseif ($r.Tags -match 'next-generation|ngws') { 'NG' } elseif ($r.Tags -match 'bitlocker') { 'BL' } else { 'L1' })
            Applies = $(if ("$($r.Title)" -match '\(DC only\)' -or ($dc -and -not $ms)) { 'DC' } elseif ("$($r.Title)" -match '\(MS only\)' -or ($ms -and -not $dc)) { 'MS' } else { 'both' })
            RegKey  = $(if ($r.Path -and $r.Name -and $r.Path -notmatch '\{\{' -and $r.Name -notmatch '\{\{') { ("$($r.Path)|$($r.Name)" -replace '^HKLM:?\\', 'HKLM\').ToLower() } else { '' })
            # "Configure Create symbolic links" (Windows 11) is "Create symbolic links" elsewhere.
            TitleKey = (($title -replace "(?i)^ensure\s+", '' -replace "(?i)^configure\s+", '' -replace "(?i)'?\s+(is\s+(set|configured)|to\s+include)\b.*$", '' -replace '[^A-Za-z0-9]+', ' ').Trim().ToLower())
        }
    }
}

$win11 = @(Read-CisRules $Win11Dir)
$servers = [ordered]@{ srv2022 = @(Read-CisRules $Server2022Dir); srv2019 = @(Read-CisRules $Server2019Dir); srv2016 = @(Read-CisRules $Server2016Dir); win10 = @(Read-CisRules $Win10Dir) }
$map = [ordered]@{}
$stats = [ordered]@{}
foreach ($b in $servers.Keys) {
    $byReg = @{}; $byTitle = @{}
    foreach ($r in $servers[$b]) {
        if ($r.RegKey) { if (-not $byReg[$r.RegKey]) { $byReg[$r.RegKey] = New-Object System.Collections.Generic.List[object] }; $byReg[$r.RegKey].Add($r) }
        if ($r.TitleKey) { if (-not $byTitle[$r.TitleKey]) { $byTitle[$r.TitleKey] = New-Object System.Collections.Generic.List[object] }; $byTitle[$r.TitleKey].Add($r) }
    }
    $n = 0
    $used = @{}
    foreach ($w in $win11) {
        # Same registry value first; the title when the value differs or is missing (a role can write a
        # setting under another key: Server 2022 writes RunAsPPL under a policy key).
        $hits = if ($w.RegKey -and $byReg[$w.RegKey]) { $byReg[$w.RegKey] } else {
            # A title can name a computer and a user setting (18.x and 19.x): keep the same section.
            $sec = ($w.Rule -split '\.')[0]
            @($byTitle[$w.TitleKey] | Where-Object { $_ -and ($_.Rule -split '\.')[0] -eq $sec })
        }
        $hits = @($hits | Where-Object { $_ })
        if (-not $hits) { continue }
        if (-not $map.Contains($w.Rule)) { $map[$w.Rule] = [ordered]@{} }
        # r rule, l level, a applies (both, DC, MS).
        $map[$w.Rule][$b] = @($hits | Sort-Object Rule -Unique | ForEach-Object { [ordered]@{ r = $_.Rule; l = $_.Level; a = $_.Applies } })
        foreach ($x in $hits) { $used[$x.Rule] = $true }
        $n++
    }
    $stats[$b] = $n
    foreach ($r in $servers[$b]) { $r | Add-Member -NotePropertyName Used -NotePropertyValue ([bool]$used[$r.Rule]) -Force }
}
# Rules that Windows 11 does not have (server and Windows 10 only): one entry per setting, with its
# number in each benchmark that has it. Same setting: same registry value, or same title within the
# same section. The key is the Server 2022 number, or "<benchmark>:<number>" for a rule Server 2022
# lacks; a check quotes it with Add-Finding -ServerCis.
$groups = New-Object System.Collections.Generic.List[object]
$byKey = @{}
foreach ($b in $servers.Keys) {
    foreach ($r in @($servers[$b] | Where-Object { -not $_.Used })) {
        $keys = @(if ($r.RegKey) { "r:$($r.RegKey)" }; if ($r.TitleKey) { "t:$(($r.Rule -split '\.')[0]):$($r.TitleKey)" })
        $g = $null
        foreach ($k in $keys) { if ($byKey.ContainsKey($k)) { $g = $byKey[$k]; break } }
        if (-not $g) { $g = [ordered]@{}; $groups.Add($g) }
        foreach ($k in $keys) { $byKey[$k] = $g }
        if (-not $g.Contains($b)) { $g[$b] = New-Object System.Collections.Generic.List[object] }
        if (-not @($g[$b] | Where-Object { $_.r -eq $r.Rule })) { $g[$b].Add([ordered]@{ r = $r.Rule; l = $r.Level; a = $r.Applies }) }
    }
}
$extra = [ordered]@{}
foreach ($g in $groups) {
    $first = @($servers.Keys | Where-Object { $g.Contains($_) })[0]
    $anchor = @($g[$first].ToArray() | Sort-Object { (($_.r -split '\.') | ForEach-Object { '{0:D4}' -f [int]$_ }) -join '.' })[0].r
    $key = if ($first -eq 'srv2022') { $anchor } else { "${first}:$anchor" }
    $e = [ordered]@{}
    foreach ($b in $servers.Keys) { if ($g.Contains($b)) { $e[$b] = $g[$b].ToArray() } }
    $extra[$key] = $e
}
$out = [ordered]@{
    source     = 'ansible-lockdown Windows-11-CIS, Windows-10-CIS, Windows-2022-CIS, Windows-2019-CIS, Windows-2016-CIS (MIT); built by tools\Convert-CisMapping.ps1'
    benchmarks = [ordered]@{
        win11   = 'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0'
        win10   = 'CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0'
        srv2022 = 'CIS Microsoft Windows Server 2022 Benchmark v4.0.0'
        srv2019 = 'CIS Microsoft Windows Server 2019 Benchmark v4.0.0'
        srv2016 = 'CIS Microsoft Windows Server 2016 Benchmark v3.0.0'
    }
    # The name a finding uses: "CIS Server 2022 2.3.5.2".
    short      = [ordered]@{ win11 = 'Windows 11'; win10 = 'Windows 10'; srv2022 = 'Server 2022'; srv2019 = 'Server 2019'; srv2016 = 'Server 2016' }
    rules      = $map
    # Rules without a Windows 11 counterpart, by Server 2022 number (or "win10:5.8"): see above.
    extra      = $extra
}
$json = $out | ConvertTo-Json -Depth 6 -Compress
[System.IO.File]::WriteAllText($OutMap, $json, (New-Object System.Text.UTF8Encoding $false))
"Windows 11 rules read: $($win11.Count); mapped: " + (($stats.Keys | ForEach-Object { "$_ $($stats[$_])" }) -join ', ') + "; rules without a Windows 11 counterpart: $($extra.Count)"
"Wrote $OutMap"
