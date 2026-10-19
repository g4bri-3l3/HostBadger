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

$order = @('Credential Protection', 'Antivirus', 'Disk and Boot', 'Network Exposure', 'Remote Access', 'Local Accounts', 'Privilege Escalation', 'Logging', 'Patching', 'System Hardening', 'Software', 'DISA STIG')
$roleShort = @{ workstation = 'W'; server = 'S'; dc = 'DC' }
$stig = @(Get-StigCatalog)
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('# HostBadger coverage')
$null = $sb.AppendLine()
$null = $sb.AppendLine("Every check in ``lib\Checks.ps1``, generated from the catalog ($($script:CheckCatalog.Count) checks, of which $(@($script:CheckCatalog.Keys | Where-Object { $_ -like 'stig_*' }).Count) cover the $($stig.Count) registry rules of the DISA STIGs listed at the end). Severity is the default; a few findings raise or lower it (the check's description in the report says when). Roles: W workstation, S server, DC domain controller.")
$null = $sb.AppendLine()
$null = $sb.AppendLine("The CIS column gives the rule number in the *CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0* and its profile level (L1 corporate, L2 high security); the descriptions are HostBadger's own. A check is a read-only comparison of the host's setting with the rule; it is not a certification of conformity, and the benchmark covers many more settings (most of the administrative templates, for instance) than HostBadger reads. On Windows 10 and on Windows Server 2022, 2019 and 2016 the findings quote the same setting in that version's CIS benchmark instead (Windows 10 Enterprise v3.0.0, Server 2022 and 2019 v4.0.0, Server 2016 v3.0.0). Checks marked *Server* follow a rule that only the server benchmarks have.")
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
$null = $sb.AppendLine('## DISA STIG rules read by the stig_* checks')
$null = $sb.AppendLine()
$null = $sb.AppendLine('The registry rules of the DISA STIGs (STIG content published by DISA). Each rule is one finding when the host differs; the collector reads exactly those values and nothing else. Rules that need an organization decision (a banner text, an approved URL list) are left out. Browser and Office rules are judged only when the product is installed; Office rules are per-user policies and are judged on the user profiles that were loaded when the snapshot was taken.')
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Product | STIG release | Rules | CAT I | CAT II | CAT III |')
$null = $sb.AppendLine('|---|---|---|---|---|---|')
$rel = [ordered]@{ adobereader = 'Adobe Acrobat Reader DC Continuous V2R1'; adobepro = 'Adobe Acrobat Pro DC Continuous V2R1'; win10 = 'Windows 10 V3R6'; win11 = 'Windows 11 V2R7'; defender = 'Microsoft Defender Antivirus V2R8'; firewall = 'Windows Defender Firewall V2R2'; edge = 'Microsoft Edge V2R5'; chrome = 'Google Chrome V2R11'; firefox = 'Mozilla Firefox V6R7'; office = 'Microsoft Office 365 ProPlus V3R5' }
foreach ($p in $rel.Keys) {
    $e = @($stig | Where-Object { $_.p -eq $p })
    $null = $sb.AppendLine("| ``$($script:StigProductType[$p])`` | $($rel[$p]) | $($e.Count) | $(@($e | Where-Object { $_.s -eq 'H' }).Count) | $(@($e | Where-Object { $_.s -eq 'M' }).Count) | $(@($e | Where-Object { $_.s -eq 'L' }).Count) |")
}
# The Windows Server STIGs each have a domain-controller and a member-server variant behind one
# check type; the Rules column counts both (a host is judged by its role).
$srvRel = [ordered]@{ stig_server2016 = @('Windows Server 2016 V2R10', 'srv2016dc', 'srv2016ms'); stig_server2019 = @('Windows Server 2019 V3R8', 'srv2019dc', 'srv2019ms'); stig_server2022 = @('Windows Server 2022 V2R8', 'srv2022dc', 'srv2022ms'); stig_server2025 = @('Windows Server 2025 V1R1', 'srv2025dc', 'srv2025ms') }
foreach ($type in $srvRel.Keys) {
    $e = @($stig | Where-Object { $_.p -in $srvRel[$type][1], $srvRel[$type][2] })
    $null = $sb.AppendLine("| ``$type`` | $($srvRel[$type][0]) (DC + member) | $($e.Count) | $(@($e | Where-Object { $_.s -eq 'H' }).Count) | $(@($e | Where-Object { $_.s -eq 'M' }).Count) | $(@($e | Where-Object { $_.s -eq 'L' }).Count) |")
}
$null = $sb.AppendLine()
$null = $sb.AppendLine('## ACSC Essential Eight requirements judged from a host')
$null = $sb.AppendLine()
$null = $sb.AppendLine("The requirements of the ASD Essential Eight Maturity Model (November 2023) that a host shows, in the ASD wording, with the checks that judge them. The dashboard gives each strategy the highest maturity level whose requirements here, and those of the levels below, are all met. The other requirements (vulnerability scanning cadence, central logging, multi-factor authentication, backups, processes) need evidence a host does not hold, so the level is an upper bound. Multi-factor authentication and regular backups have no requirement a host shows.")
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Strategy | ML | Requirement | Checks | Notes |')
$null = $sb.AppendLine('|---|---|---|---|---|')
foreach ($r in $script:E8Requirements) {
    $scope = @(); if ($r.Roles) { $scope += "roles: $(@($r.Roles | ForEach-Object { $roleShort[$_] }) -join ', ')" }; if ($r.Product) { $scope += 'with Microsoft Office' }; if ($r.Match) { $scope += "finding matching ``$($r.Match)``" }; if ($r.Note) { $scope += $r.Note }
    $checks = (@($r.Checks) | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $null = $sb.AppendLine("| $($script:E8Strategies[$r.S].Label) | $($r.L) | $($r.Req) | $checks | $($scope -join '; ') |")
}
$null = $sb.AppendLine()
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
"Wrote $OutFile ($($script:CheckCatalog.Count) checks, $($stig.Count) STIG rules)."
