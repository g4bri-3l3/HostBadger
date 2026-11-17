<#
.SYNOPSIS
    Writes COVERAGE.md from the check catalog (lib\Checks.ps1), the remediation
    list (lib\Remediation.ps1) and the STIG catalog (data\stig-catalog.json).
    Developer tool: run it after adding or changing a check.
#>
[CmdletBinding()]
param([string]$OutFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'COVERAGE.md'))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'lib\Checks.ps1')
. (Join-Path $root 'lib\AI.ps1')
. (Join-Path $root 'lib\Remediation.ps1')

$order = @('Credential Protection', 'Antivirus', 'Disk and Boot', 'Network Exposure', 'Remote Access', 'Local Accounts', 'Privilege Escalation', 'Persistence', 'Logging', 'Patching', 'System Hardening', 'Software', 'DISA STIG')
$roleShort = @{ workstation = 'W'; server = 'S'; dc = 'DC' }
$stig = @(Get-StigCatalog)
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('# HostBadger coverage')
$null = $sb.AppendLine()
$null = $sb.AppendLine("Every check in ``lib\Checks.ps1``, generated from the catalog ($($script:CheckCatalog.Count) checks, of which $(@($script:CheckCatalog.Keys | Where-Object { $_ -like 'stig_*' }).Count) cover the $($stig.Count) registry rules of the DISA STIGs listed at the end). Severity is the default; a few findings raise or lower it (the check's description in the report says when). Roles: W workstation, S server, DC domain controller.")
$null = $sb.AppendLine()
# The benchmark names come from data\cis-map.json, so this document cannot name a version the mapping
# was not built from.
$cisB = (Get-CisMap).benchmarks
$cisOthers = @(@('win10', 'srv2022', 'srv2019', 'srv2016') | ForEach-Object { "$($cisB.$_)" } | Where-Object { $_ })
$null = $sb.AppendLine("The CIS column gives the rule number in the *$($cisB.win11)* and its profile level (L1 corporate, L2 high security); the descriptions are HostBadger's own. A check is a read-only comparison of the host's setting with the rule; it is not a certification of conformity, and the benchmark covers many more settings (most of the administrative templates, for instance) than HostBadger reads. On Windows 10 and on Windows Server 2022, 2019 and 2016 the findings quote the same setting in that version's CIS benchmark instead ($($cisOthers -join '; ')). Checks marked *Server* follow a rule that only the server benchmarks have.")
$null = $sb.AppendLine()
$null = $sb.AppendLine('The last column says whether HostBadger can write a remediation script for the check (`-OutRemediation`): one setting, the expected value, reversible, previewed by default and with a rollback file. `no` means the fix needs a decision, carries a risk, or is an upgrade: follow the remediation text in the report.')
foreach ($cat in $order) {
    $rows = @($script:CheckCatalog.Keys | Where-Object { $script:CheckCatalog[$_].Category -eq $cat })
    if ($rows.Count -eq 0) { continue }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## $cat")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| ID | Severity | MITRE | CIS | Roles | Fix script | Title |')
    $null = $sb.AppendLine('|---|---|---|---|---|---|---|')
    foreach ($id in $rows) {
        $m = $script:CheckCatalog[$id]
        $roles = (@($m.Roles | ForEach-Object { $roleShort[$_] }) -join ', ')
        $fix = if ($script:FixTypes.ContainsKey($id)) { 'yes' } else { 'no' }
        $null = $sb.AppendLine("| ``$id`` | $($m.Severity) | $($m.Mitre) | $(if ($m.Cis) { $m.Cis } elseif ($m.CisServer) { "Server $($m.CisServer)" }) | $roles | $fix | $($m.Title) |")
    }
}
$null = $sb.AppendLine()
# Recent attacks: the mapping lives in data\recent-attacks.json, so this document cannot name a check
# that is not in the catalog (the regression checks every name).
$ra = Get-RecentAttacks
if ($ra) {
    $null = $sb.AppendLine('## Recent attacks 2022-2026')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('The vectors behind the attacks and research most reported between 2022 and 2026, the condition each one needs on a Windows host, and the checks that look for that condition. A check in this table does not detect the attack: it reports the setting or the leftover the attack needs, before or after the fact. Only the checks in the Checks column decide whether a host is exposed; the Context column holds checks that make the vector easier or worse but are not the condition itself, so they are reported next to it and never mark a host exposed on their own.')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Attack or vector | Years | What it needs on the host | Checks | Context |')
    $null = $sb.AppendLine('|---|---|---|---|---|')
    foreach ($a in @($ra.attacks)) {
        $checks = (@($a.checks) | ForEach-Object { '`' + $_ + '`' }) -join ', '
        $rel = (@($a.related) | Where-Object { $_ } | ForEach-Object { '`' + $_ + '`' }) -join ', '
        $null = $sb.AppendLine("| $($a.name) | $($a.years) | $($a.needs) | $checks | $rel |")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('### What these checks do not cover')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('A host snapshot is a configuration, not a stream of events. These are the vectors of the same years that HostBadger deliberately says nothing about, and why.')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Not covered | Why |')
    $null = $sb.AppendLine('|---|---|')
    foreach ($a in @($ra.notCovered)) { $null = $sb.AppendLine("| $($a.name) | $($a.why) |") }
    $null = $sb.AppendLine()
}
# Attack paths: the chains of data\attack-paths.json, stage by stage. Same rule as the table above,
# every check named here is in the catalog (the regression checks it).
$apDoc = Get-AttackPaths
if ($apDoc) {
    $stageDoc = @{}
    foreach ($st in @($apDoc.stages)) { $stageDoc["$($st.id)"] = "$($st.name)" }
    $null = $sb.AppendLine('## Attack paths')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('The chains in `data\attack-paths.json`, stage by stage, with the checks that look for the condition each stage needs. The report draws one chain per path, for a single host: a stage is filled when a check of it reports that condition there, grey when nothing about it could be judged, plain when every judged check of it is clean. A complete chain means every stage has an enabling condition on that one host; it is evidence, not proof that anyone walked it, and the chains are documentation of what the checks mean together, not a new kind of detection.')
    foreach ($p in @($apDoc.paths)) {
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("### $($p.name)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("$($p.why) Judged on: $((@($p.roles) -join ', ')).")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Stage | What it needs on the host | Checks |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($s in @($p.steps)) {
            $checks = (@($s.checks) | ForEach-Object { '`' + $_ + '`' }) -join ', '
            $null = $sb.AppendLine("| $($stageDoc["$($s.stage)"]) | $($s.needs) | $checks |")
        }
    }
    $null = $sb.AppendLine()
}
$null = $sb.AppendLine('## DISA STIG rules read by the stig_* checks')
$null = $sb.AppendLine()
$null = $sb.AppendLine('The registry rules of the DISA STIGs (STIG content published by DISA). Each rule is one finding when the host differs; the collector reads exactly those values and nothing else. Rules that need an organization decision (a banner text, an approved URL list) are left out. Browser and Office rules are judged only when the product is installed; Office rules are per-user policies and are judged on the user profiles that were loaded when the snapshot was taken.')
$null = $sb.AppendLine()
if ($script:StigBuilt) { $null = $sb.AppendLine("The catalog (``data\stig-catalog.json``) was built on $($script:StigBuilt) from the PowerSTIG releases below; every release in this table comes from the catalog itself, not from this document.") }
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Product | STIG release | Rules | CAT I | CAT II | CAT III |')
$null = $sb.AppendLine('|---|---|---|---|---|---|')
# The product names; the release comes from the catalog, so this document cannot promise one the shipped
# rules do not come from.
$prodRel = { param($p) "$($script:StigReleases.$p.release)" }
$rel = [ordered]@{ adobereader = 'Adobe Acrobat Reader DC Continuous'; adobepro = 'Adobe Acrobat Pro DC Continuous'; win10 = 'Windows 10'; win11 = 'Windows 11'; defender = 'Microsoft Defender Antivirus'; firewall = 'Windows Defender Firewall'; edge = 'Microsoft Edge'; chrome = 'Google Chrome'; firefox = 'Mozilla Firefox'; office = 'Microsoft Office 365 ProPlus' }
foreach ($p in $rel.Keys) {
    $e = @($stig | Where-Object { $_.p -eq $p })
    $null = $sb.AppendLine("| ``$($script:StigProductType[$p])`` | $("$($rel[$p]) $(& $prodRel $p)".Trim()) | $($e.Count) | $(@($e | Where-Object { $_.s -eq 'H' }).Count) | $(@($e | Where-Object { $_.s -eq 'M' }).Count) | $(@($e | Where-Object { $_.s -eq 'L' }).Count) |")
}
# The Windows Server STIGs each have a domain-controller and a member-server variant behind one
# check type; the Rules column counts both (a host is judged by its role).
$srvRel = [ordered]@{ stig_server2016 = @('Windows Server 2016', 'srv2016dc', 'srv2016ms'); stig_server2019 = @('Windows Server 2019', 'srv2019dc', 'srv2019ms'); stig_server2022 = @('Windows Server 2022', 'srv2022dc', 'srv2022ms'); stig_server2025 = @('Windows Server 2025', 'srv2025dc', 'srv2025ms') }
foreach ($type in $srvRel.Keys) {
    $e = @($stig | Where-Object { $_.p -in $srvRel[$type][1], $srvRel[$type][2] })
    $null = $sb.AppendLine("| ``$type`` | $("$($srvRel[$type][0]) $(Get-StigRelease $type)".Trim()) (DC + member) | $($e.Count) | $(@($e | Where-Object { $_.s -eq 'H' }).Count) | $(@($e | Where-Object { $_.s -eq 'M' }).Count) | $(@($e | Where-Object { $_.s -eq 'L' }).Count) |")
}
$null = $sb.AppendLine()
$null = $sb.AppendLine('## ACSC Essential Eight requirements judged from a host')
$null = $sb.AppendLine()
$null = $sb.AppendLine("The requirements of the ASD Essential Eight Maturity Model ($($script:E8ModelVersion)) that a host shows, in the ASD wording, with the checks that judge them. The dashboard gives each strategy the highest maturity level whose requirements here, and those of the levels below, are all met. The other requirements (vulnerability scanning cadence, central logging, multi-factor authentication, backups, processes) need evidence a host does not hold, so the level is an upper bound. Multi-factor authentication and regular backups have no requirement a host shows.")
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Strategy | ML | Requirement | Checks | Notes |')
$null = $sb.AppendLine('|---|---|---|---|---|')
foreach ($r in $script:E8Requirements) {
    $scope = @(); if ($r.Roles) { $scope += "roles: $(@($r.Roles | ForEach-Object { $roleShort[$_] }) -join ', ')" }; if ($r.Product) { $scope += 'with Microsoft Office' }; if ($r.Match) { $scope += "finding matching ``$($r.Match)``" }; if ($r.Note) { $scope += $r.Note }
    $checks = (@($r.Checks) | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $null = $sb.AppendLine("| $($script:E8Strategies[$r.S].Label) | $($r.L) | $($r.Req) | $checks | $($scope -join '; ') |")
}
$null = $sb.AppendLine()
$null = $sb.AppendLine('## NIS2: ACN basic measures judged from a host')
$null = $sb.AppendLine()
$null = $sb.AppendLine("The requirements of the basic security measures of the Italian National Cybersecurity Agency (ACN Determinazione 379907/2025, D.Lgs. 138/2024: Allegato 1 for soggetti importanti, Allegato 2 for soggetti essenziali) that a host shows, in ACN's wording (``data\acn-nis2-measures.json``), with the checks that give evidence about them. The dashboard lists those with a finding against them. The other requirements (governance, risk and vulnerability plans, inventories, backups, multi-factor authentication, training, incident handling, documented procedures) need evidence a host does not hold: no contrary evidence on a host is not compliance.")
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Measure | Point | Requirement (ACN) | Checks | Notes |')
$null = $sb.AppendLine('|---|---|---|---|---|')
foreach ($r in $script:AcnRequirements) {
    $scope = @(); if ($r.E) { $scope += 'Allegato 2 only (soggetti essenziali)' }; if ($r.Roles) { $scope += "roles: $(@($r.Roles | ForEach-Object { $roleShort[$_] }) -join ', ')" }; if ($r.List) { $scope += "judged only with -$($r.List)" }; if ($r.Match) { $scope += "finding matching ``$($r.Match)``" }; if ($r.Note) { $scope += $r.Note }
    $checks = (@($r.Checks) | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $null = $sb.AppendLine("| $($r.Code) | $($r.P) | $(Get-AcnMeasureText $r.Code $r.P) | $checks | $($scope -join '; ') |")
}
$null = $sb.AppendLine()
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
"Wrote $OutFile ($($script:CheckCatalog.Count) checks, $($stig.Count) STIG rules)."
