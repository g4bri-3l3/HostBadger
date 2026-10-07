<#
.SYNOPSIS
    HostBadger regression: builds the synthetic fleet, analyzes it and checks
    exact finding counts, the "not evaluated" rule, roles, exceptions,
    comparison, JSON Lines, zip input and the safety review. Exit 1 on any
    failure. Run it on Windows PowerShell 5.1 and PowerShell 7.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'lib\Checks.ps1')
. (Join-Path $root 'lib\AI.ps1')
. (Join-Path $root 'lib\Remediation.ps1')
. (Join-Path $root 'lib\Reporting.ps1')

$script:pass = 0; $script:fail = 0
function Assert-True([bool]$Cond, [string]$What) {
    if ($Cond) { $script:pass++ } else { $script:fail++; Write-Host "FAIL $What" -ForegroundColor Red }
}
function Assert-Equal($Actual, $Expected, [string]$What) {
    if ("$Actual" -ceq "$Expected") { $script:pass++ } else { $script:fail++; Write-Host "FAIL $What`n   expected: $Expected`n   actual  : $Actual" -ForegroundColor Red }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("hostbadger_regression_{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$fleet = Join-Path $work 'fleet'
foreach ($sc in 'weak', 'hardened', 'laptop', 'dc', 'partial') {
    & (Join-Path $PSScriptRoot 'New-SyntheticHostSnapshot.ps1') -Scenario $sc -OutFile (Join-Path $fleet "hostsnapshot_$sc.json") 6>$null | Out-Null
}
$config = @{ AllowedAdmins = @(); MaxPatchAgeDays = 45; MaxSignatureAgeDays = 7; SupportWarningDays = 90; MaxCachedLogonsWorkstation = 4; MaxCachedLogonsServer = 1; MinSecurityLogKB = 196608 }

function Invoke-One([string]$File, [hashtable]$Cfg = $config) { return Invoke-HostChecks -Snapshot (Import-HostSnapshot $File) -Config $Cfg }
function Has($Result, [string]$Type, [string]$Object = '', [string]$Severity = '') {
    return @($Result.Findings | Where-Object { $_.Type -eq $Type -and (-not $Object -or $_.Object -eq $Object) -and (-not $Severity -or $_.Severity -eq $Severity) }).Count -gt 0
}

# ------------------------------------------------------------------ per host
$weak = Invoke-One (Join-Path $fleet 'hostsnapshot_weak.json')
$hard = Invoke-One (Join-Path $fleet 'hostsnapshot_hardened.json')
$lap = Invoke-One (Join-Path $fleet 'hostsnapshot_laptop.json')
$dc = Invoke-One (Join-Path $fleet 'hostsnapshot_dc.json')
$part = Invoke-One (Join-Path $fleet 'hostsnapshot_partial.json')

Assert-Equal @($weak.Findings).Count 132 'weak: total findings'
Assert-Equal @($hard.Findings).Count 2 'hardened: total findings'
Assert-Equal @($lap.Findings).Count 3 'laptop: total findings'
Assert-Equal @($dc.Findings).Count 3 'dc: total findings'
Assert-Equal @($part.Findings).Count 2 'partial: total findings'
$all = @($weak.Findings) + @($hard.Findings) + @($lap.Findings) + @($dc.Findings) + @($part.Findings)
Assert-Equal ((@('Critical', 'High', 'Medium', 'Low') | ForEach-Object { $s = $_; @($all | Where-Object { $_.Severity -eq $s }).Count }) -join '/') '0/28/64/50' 'fleet: severity split'
$never = @($script:CheckCatalog.Keys | Where-Object { $t = $_; @($all | Where-Object { $_.Type -eq $t }).Count -eq 0 })
Assert-Equal ($never -join ',') '' 'every check triggers in at least one scenario'
$dups = @($all | Group-Object { "$($_.Type)|$($_.Host)|$($_.Object)" } | Where-Object { $_.Count -gt 1 })
Assert-Equal $dups.Count 0 'Type + Host + Object unique'

# Windows Home: the same risk, a different way out, and no PIN to ask for.
$homeSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'); $homeSnap.host.os.editionId = 'CoreSingleLanguage'
$homeRes = Invoke-HostChecks -Snapshot $homeSnap -Config $config
Assert-True (@($homeRes.Findings | Where-Object { $_.Type -eq 'bitlocker_os_volume_off' -and $_.Severity -eq 'High' -and $_.Detail -match 'Device encryption' }).Count -eq 1) 'Home: OS volume still High, with the Device encryption way out'
Assert-True (@($homeRes.Findings | Where-Object { $_.Type -eq 'bitlocker_data_volume_off' -and $_.Detail -match 'Home cannot encrypt data volumes' }).Count -eq 1) 'Home: data volume finding says BitLocker is not available'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'bitlocker_os_volume_off' -and $_.Detail -match 'Device encryption' }).Count -eq 0) 'Pro: no Home advice'
$homeLap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_laptop.json'); $homeLap.host.os.editionId = 'Core'
Assert-Equal @((Invoke-HostChecks -Snapshot $homeLap -Config $config).Findings | Where-Object { $_.Type -eq 'bitlocker_tpm_only' }).Count 0 'Home: no "TPM without PIN" finding (a PIN cannot be set)'
Assert-Equal @($lap.Findings | Where-Object { $_.Type -eq 'bitlocker_tpm_only' }).Count 1 'Enterprise laptop: TPM without PIN still flagged'

# Patching: the hotfix list decides. The update history (definitions, .NET, PowerShell...) must not
# hide an unpatched Windows.
$staleSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$staleSnap.patches.hotfixes = @([PSCustomObject]@{ id = 'KB5068865'; description = 'Security Update'; installedOnUtc = '2025-11-20T00:00:00Z' }); $staleSnap.patches.lastUpdateInstalledUtc = '2026-09-30T08:00:00Z'
Assert-True (@((Invoke-HostChecks -Snapshot $staleSnap -Config $config).Findings | Where-Object { $_.Type -eq 'updates_stale' -and $_.Detail -match 'hotfix list' -and $_.Detail -match '2025-11-20' -and $_.Detail -match 'history shows a later item on 2026-09-30' }).Count -eq 1) 'updates_stale: an old hotfix list is not hidden by a recent update history, and the finding says why the screen shows a later date'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'updates_stale' -and $_.Detail -notmatch 'later item' }).Count -eq 1) 'updates_stale: no explanation when the history shows nothing later'
$undatedSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$undatedSnap.patches.hotfixes = @([PSCustomObject]@{ id = 'KB5068865'; description = 'Security Update'; installedOnUtc = $null }); $undatedSnap.patches.lastUpdateInstalledUtc = '2026-09-30T08:00:00Z'
Assert-Equal @((Invoke-HostChecks -Snapshot $undatedSnap -Config $config).Findings | Where-Object { $_.Type -eq 'updates_stale' }).Count 0 'updates_stale: without dated hotfixes the update history is used'

# CIS rule: the finding quotes its own rule, not the range that belongs to the check.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' -and $_.Object -eq 'service: SSDPSRV' -and $_.Severity -eq 'Medium' -and $_.Cis -eq '5.30 (L1)' }).Count -eq 1) 'service finding carries its own CIS rule and level'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' -and $_.Object -eq 'service: XblAuthManager' -and $_.Severity -eq 'Low' }).Count -eq 1) 'non network CIS service is Low'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'autologon_enabled' -and $_.Severity -eq 'High' }).Count -eq 1) 'automatic logon with a stored password is High'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'uac_hardening_gaps' -and $_.Object -eq 'Secure desktop for prompts' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'secure desktop off is Medium'
Assert-Equal (@($weak.Findings | Where-Object { $_.Type -eq 'event_logs_small' } | ForEach-Object { $_.Cis } | Sort-Object) -join ',') '18.10.25.1.2 (L1),18.10.25.4.2 (L1)' 'event log findings quote their own rule'
Assert-Equal @($hard.Findings | Where-Object { $_.Cis }).Count 0 'hardened host: no CIS finding'
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'defender_pua_off' }).Count -eq 1) 'Defender passive mode: PUA check not evaluated'

# Severity that depends on the case.
Assert-True (Has $weak 'defender_exclusion' 'path: C:\Users\Public\Tools' 'High') 'exclusion of a user folder is High'
Assert-True (Has $weak 'defender_exclusion' 'path: C:\Program Files\Contoso ERP\Cache' 'Low') 'exclusion under Program Files is Low'
Assert-True (Has $weak 'defender_exclusion' 'extension: ps1' 'High') 'script extension exclusion is High'
Assert-True (Has $weak 'service_binary_writable' 'service: VendorAgent' 'High') 'writable service file is High'
Assert-True (Has $weak 'service_binary_writable' 'service: PrintHelper' 'Medium') 'writable service folder only is Medium'
Assert-True (Has $weak 'bitlocker_os_volume_off' '' 'High') 'unencrypted OS volume on a workstation is High'
Assert-True (Has $dc 'smb_server_signing_not_required' '' 'High') 'SMB signing on a DC is High'
Assert-True (Has $weak 'smb_server_signing_not_required' '' 'Medium') 'SMB signing on a workstation is Medium'
Assert-True (Has $weak 'builtin_admin_enabled' '' 'Medium') 'built-in admin without LAPS is Medium'
Assert-True (Has $hard 'builtin_admin_enabled' '' 'Low') 'built-in admin under LAPS is Low'
Assert-True (Has $weak 'local_admin_member' 'member: CORP/Helpdesk' 'Low') 'domain group in Administrators is Low'
Assert-True (Has $weak 'local_admin_member' 'member: CORP/jsmith' 'Medium') 'domain user in Administrators is Medium'
Assert-True (-not (Has $weak 'local_admin_member' 'member: CORP/Domain Admins')) 'Domain Admins expected in Administrators'
Assert-True (-not (Has $lap 'local_admin_member')) 'Entra role SIDs expected on Entra joined devices'
Assert-True (-not (Has $weak 'task_binary_writable' 'task: \UserSync -> C:\Users\Public\sync.exe')) 'task running as Users is not a privilege escalation'
Assert-True (Has $weak 'risky_listener' 'tcp/5985 (WinRM over HTTP)') 'WinRM HTTP flagged on a workstation'
Assert-True (-not (Has $weak 'risky_listener' 'tcp/3306 (MySQL)')) 'loopback listener ignored'
Assert-Equal @($weak.Findings | Where-Object { $_.Type -eq 'risky_listener' -and $_.Object -like 'tcp/5900*' }).Count 1 'same port on IPv4 and IPv6 reported once'
Assert-True (Has $lap 'os_support_ending') 'Windows 11 23H2 Enterprise: support ending'
Assert-True (Has $weak 'os_unsupported' 'Windows 10 22H2 Home/Pro') 'Windows 10 22H2 Pro: out of support'

# Roles: checks that don't apply are neither findings nor "not evaluated".
foreach ($t in 'credential_guard_off', 'cached_logons_high', 'laps_not_configured', 'local_admin_member', 'rdp_enabled_workstation') {
    Assert-True (-not (Has $dc $t)) "dc: no $t finding"
    Assert-True (@($dc.NotEvaluated | Where-Object { $_.Type -eq $t }).Count -eq 0) "dc: $t not listed as not evaluated"
}
Assert-True (-not (Has $hard 'spooler_on_dc')) 'spooler check only on DCs'
Assert-True (Has $dc 'spooler_on_dc') 'spooler running on a DC'

# Not evaluated: never silently clean.
$neTypes = @($part.NotEvaluated | ForEach-Object { $_.Type } | Sort-Object)
Assert-Equal $neTypes.Count 22 'partial: checks not evaluated'
foreach ($t in 'defender_realtime_off', 'defender_tamper_off', 'defender_signatures_stale', 'defender_exclusion', 'asr_standard_rules_missing',
    'bitlocker_os_volume_off', 'bitlocker_tpm_only', 'bitlocker_data_volume_off', 'audit_policy_gaps', 'cmdline_audit_off', 'security_log_small',
    'local_admin_member', 'service_binary_writable', 'task_binary_writable', 'autorun_writable', 'credential_guard_off') {
    Assert-True ($neTypes -contains $t) "partial: $t not evaluated"
    Assert-True (-not (Has $part $t)) "partial: no $t finding"
}
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'defender_tamper_off' -and $_.Reason -match 'Passive Mode' }).Count -eq 1) 'passive Defender reason given'
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'service_binary_writable' -and $_.Reason -match 'SkipAcl' }).Count -eq 1) '-SkipAcl reason given'
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'bitlocker_tpm_only' -and $_.Reason -match "collection of 'bitlocker' failed" }).Count -eq 1) 'failed section reason given'
Assert-Equal @($weak.NotEvaluated).Count 0 'weak: everything evaluated'

# A failed parent section covers its children, not the other way round.
$snap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$snap.meta.collectionErrors = @([PSCustomObject]@{ section = 'defender'; message = 'Get-MpComputerStatus failed' })
$ne = @(Get-NotEvaluatedChecks -Snapshot $snap)
Assert-True (@($ne | Where-Object { $_.Type -eq 'defender_exclusion' }).Count -eq 1) "error on 'defender' covers 'defender.exclusions'"
$snap.meta.collectionErrors = @([PSCustomObject]@{ section = 'defender.exclusions'; message = 'not readable' })
$ne = @(Get-NotEvaluatedChecks -Snapshot $snap)
Assert-True (@($ne | Where-Object { $_.Type -eq 'defender_realtime_off' }).Count -eq 0) "error on 'defender.exclusions' leaves 'defender' checks alone"

# Determinism: ages come from the collection date, not today.
$again = Invoke-One (Join-Path $fleet 'hostsnapshot_weak.json')
Assert-Equal ((@($again.Findings) | ForEach-Object { "$($_.Type)|$($_.Object)|$($_.Detail)" }) -join "`n") ((@($weak.Findings) | ForEach-Object { "$($_.Type)|$($_.Object)|$($_.Detail)" }) -join "`n") 'same snapshot, same findings'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'updates_stale' -and $_.Detail -match '140 days' -and $_.Detail -match 'hotfix list' }).Count -eq 1) 'patch age counted at collection time, from the hotfix list'

# AllowedAdmins.
$cfg2 = $config.Clone(); $cfg2.AllowedAdmins = @('CORP/Helpdesk', 'jsmith')
$w2 = Invoke-One (Join-Path $fleet 'hostsnapshot_weak.json') $cfg2
Assert-Equal @($w2.Findings | Where-Object { $_.Type -eq 'local_admin_member' }).Count 1 '-AllowedAdmins by path and by bare name'

# Old collectors wrote empty lists as {}.
$legacy = Join-Path $work 'legacy\hostsnapshot_legacy.json'
New-Item -ItemType Directory -Path (Split-Path $legacy) -Force | Out-Null
$txt = [System.IO.File]::ReadAllText((Join-Path $fleet 'hostsnapshot_hardened.json'))
[System.IO.File]::WriteAllText($legacy, ($txt -replace '"exclusionPaths":\s*\[\s*\]', '"exclusionPaths":  {}'))
Assert-Equal @((Invoke-One $legacy).Findings).Count 2 'legacy {} for an empty list read as empty'

# ------------------------------------------------------------------ end to end
$out = Join-Path $work 'run1'
New-Item -ItemType Directory -Path $out -Force | Out-Null
# Zip input, plus an older snapshot of the same host that must be ignored.
$zipDir = Join-Path $work 'zipped'
New-Item -ItemType Directory -Path $zipDir -Force | Out-Null
Compress-Archive -LiteralPath (Join-Path $fleet 'hostsnapshot_laptop.json') -DestinationPath (Join-Path $zipDir 'hostsnapshot_LT-SALES-112_20261001080000.zip') -Force
& (Join-Path $PSScriptRoot 'New-SyntheticHostSnapshot.ps1') -Scenario laptop -OutFile (Join-Path $zipDir 'hostsnapshot_LT-SALES-112_old.json') -CollectedAtUtc '2026-01-01T08:00:00Z' 6>$null | Out-Null
$mainArgs = @{ Snapshot = @($fleet, $zipDir); OutHtml = (Join-Path $out 'r.html'); OutJsonl = (Join-Path $out 'r.jsonl'); OutRemediation = (Join-Path $out 'rem') }
& (Join-Path $root 'HostBadger.ps1') @mainArgs *>&1 | Out-Null
$csv = @(Import-Csv (Join-Path $out 'r.csv'))
Assert-Equal $csv.Count 142 'end to end: findings CSV (zip read, older duplicate ignored)'
Assert-Equal @($csv | Where-Object { $_.Host -eq 'LT-SALES-112' -and $_.Type -eq 'os_support_ending' } | ForEach-Object { $_.Detail -match '39 days' }).Count 1 'newest snapshot of a host used'
$html = [System.IO.File]::ReadAllText((Join-Path $out 'r.html'))
Assert-True ($html -match 'Incomplete coverage' -and $html -match 'WKS-HR-004') 'report lists not evaluated checks with the host'
Assert-True ($html -match '5 hosts' -and $html -match 'Weakest: WKS-ACCT-017') 'fleet cards'
Assert-True ($html -notmatch 'https?://(?!attack\.mitre\.org)') 'report has no external links except MITRE'
$lines = @(Get-Content (Join-Path $out 'r.jsonl'))
Assert-Equal $lines.Count 147 'JSON Lines: 142 findings + 5 host summaries'
$parsed = @($lines | ForEach-Object { $_ | ConvertFrom-Json })
Assert-Equal @($parsed | Where-Object { $_.event_type -eq 'host_summary' -and $_.host -eq 'WKS-HR-004' -and $_.not_evaluated -eq 22 }).Count 1 'host summary carries the not evaluated count'
$id1 = @($parsed | Where-Object { $_.check -eq 'uac_disabled' })[0].finding_id

# Exceptions and comparison on a second run where the weak host fixed UAC.
$fixed = Join-Path $work 'fleet2'
New-Item -ItemType Directory -Path $fixed -Force | Out-Null
foreach ($f in Get-ChildItem $fleet -Filter *.json) { if ($f.Name -notmatch 'partial') { Copy-Item $f.FullName $fixed } }
$wj = Join-Path $fixed 'hostsnapshot_weak.json'
[System.IO.File]::WriteAllText($wj, ([System.IO.File]::ReadAllText($wj) -replace '"enableLua":\s*0', '"enableLua":  1'))
$exc = Join-Path $work 'exceptions.json'
@(
    [ordered]@{ type = 'smb1_server_enabled'; host = 'WKS-ACCT-017'; object = '*'; reason = 'legacy scanner, replacement ordered'; owner = 'it-ops'; expires = '2027-01-31' },
    [ordered]@{ type = 'netbios_enabled'; host = '*'; object = '*'; reason = 'needed by the label printers'; owner = 'it-ops'; expires = '' },
    [ordered]@{ type = 'guest_enabled'; host = '*'; object = '*'; reason = 'expired on purpose'; owner = 'it-ops'; expires = '2026-01-01' }
) | ConvertTo-Json | Set-Content -LiteralPath $exc -Encoding UTF8
$out2 = Join-Path $work 'run2'
New-Item -ItemType Directory -Path $out2 -Force | Out-Null
$args2 = @{ Snapshot = @($fixed); OutHtml = (Join-Path $out2 'r.html'); OutJsonl = (Join-Path $out2 'r.jsonl'); CompareTo = (Join-Path $out 'r.csv'); ExceptionsFile = $exc }
& (Join-Path $root 'HostBadger.ps1') @args2 *>&1 | Out-Null
$csv2 = @(Import-Csv (Join-Path $out2 'r.csv'))
# 142 - 2 (partial host not collected) - 1 (UAC fixed) - 1 (SMBv1 accepted) - 2 (NetBIOS accepted) = 136
Assert-Equal $csv2.Count 136 'second run: fixed, accepted and missing-host findings gone'
Assert-True (@($csv2 | Where-Object { $_.Type -eq 'guest_enabled' }).Count -eq 1) 'expired exception ignored'
$j2 = @(Get-Content (Join-Path $out2 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
$resolved = @($j2 | Where-Object { $_.event_type -eq 'resolved' })
Assert-True (@($resolved | Where-Object { $_.check -eq 'uac_disabled' -and $_.finding_id -eq $id1 }).Count -eq 1) 'fixed finding resolved, same finding_id'
Assert-True (@($resolved | Where-Object { $_.host -eq 'WKS-HR-004' }).Count -eq 0) 'host missing from the run is not "resolved"'
$html2 = [System.IO.File]::ReadAllText((Join-Path $out2 'r.html'))
Assert-True ($html2 -match 'Accepted risks' -and $html2 -match 'Expired exceptions ignored') 'report shows accepted and expired exceptions'

# ------------------------------------------------------------------ remediation scripts
# Level A only. The scripts are generated text and HostBadger never runs them. Only hosts with a
# fixable finding get a per-host file.
$remFiles = @(Get-ChildItem (Join-Path $out 'rem') -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name)
Assert-Equal ($remFiles.Name -join ',') 'remediate_DC01.ps1,remediate_WKS-ACCT-017.ps1' 'remediation: a script only for hosts with a fixable finding'
$remWeak = New-RemediationScript -HostName 'WKS-ACCT-017' -Role 'workstation' -Findings $all -Config $config -CollectedUtc '2026-10-01 08:00' -ToolVersion 'test'
$remDc = New-RemediationScript -HostName 'DC01' -Role 'dc' -Findings $all -Config $config -CollectedUtc '2026-10-01 08:00' -ToolVersion 'test'
Assert-Equal "$($remWeak.ActionCount)/$($remWeak.FixableFindings)/$($remWeak.TotalFindings)" '78/77/132' 'remediation: weak host settings / findings with a script / findings'
Assert-Equal "$($remDc.ActionCount)/$($remDc.FixableFindings)/$($remDc.TotalFindings)" '2/2/3' 'remediation: domain controller settings / findings with a script / findings'
Assert-Equal @(New-RemediationScript -HostName 'SRV-APP-02' -Role 'server' -Findings $all -Config $config -CollectedUtc 'x' -ToolVersion 'test').ActionCount 0 'remediation: hardened server has nothing to fix'
# Every check type that promises a script must produce one for at least one finding of the fleet. A
# typo in an Object would otherwise hide it.
$roleOf = @{ 'WKS-ACCT-017' = 'workstation'; 'SRV-APP-02' = 'server'; 'LT-SALES-112' = 'workstation'; 'DC01' = 'dc'; 'WKS-HR-004' = 'workstation' }
$noScript = @($script:FixTypes.Keys | Where-Object { $ty = $_; @($all | Where-Object { $_.Type -eq $ty -and @(Get-RemediationActions -Finding $_ -Role $roleOf[$_.Host] -Config $config).Count -gt 0 }).Count -eq 0 })
Assert-Equal ($noScript -join ',') '' 'remediation: every promised fix produces a script line'
Assert-Equal @($script:FixTypes.Keys | Where-Object { -not $script:CheckCatalog.Contains($_) }).Count 0 'remediation: every fix type is a check in the catalog'
foreach ($rf in $remFiles) {
    $rtxt = [System.IO.File]::ReadAllText($rf.FullName)
    $perr = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($rtxt, [ref]$null, [ref]$perr)
    Assert-Equal @($perr).Count 0 "remediation: $($rf.Name) parses"
    Assert-True ($rtxt -notmatch '(?i)Invoke-Expression|\biex\b|DownloadString|DownloadFile|Start-Process|-EncodedCommand|FromBase64String|Add-Type|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Remove-Item\b(?!Property)') "remediation: $($rf.Name) has no download, hidden code or deletion"
    Assert-True ($rtxt -match '\[switch\]\$Apply' -and $rtxt -match 'if \(-not \$Apply\) \{ return \}') "remediation: $($rf.Name) previews unless -Apply"
    Assert-True (@([regex]::Matches($rtxt, "(?m)^Set-HbRegistry .*? -Path '([^']+)'") | Where-Object { $_.Groups[1].Value -notmatch '^HKLM:\\' }).Count -eq 0) "remediation: $($rf.Name) touches only HKLM registry paths"
}
$remHtml = [System.IO.File]::ReadAllText((Join-Path $out 'r.html'))
Assert-True ($remHtml -match 'Remediation scripts' -and $remHtml -match 'remediate_WKS-ACCT-017\.ps1') 'report lists the remediation scripts'
Assert-True (@(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.check -eq 'wdigest_cleartext' -and $_.fix_available -eq $true }).Count -eq 1 -and @(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.check -eq 'bitlocker_os_volume_off' -and $_.fix_available -eq $false }).Count -eq 1) 'JSON Lines: fix_available follows the check'

# The fix scripts shown under each check in the report: one block under every check that has a safe
# fix and none under the others. Every block parses, and the registry ones really run in a private
# branch of HKCU (preview first, then apply).
$fixBlocks = @([regex]::Matches($remHtml, '<pre class="fix-code">(.*?)</pre>', 'Singleline') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) })
$fixableSeen = @($script:FixTypes.Keys | Where-Object { $ty = $_; @($all | Where-Object { $_.Type -eq $ty }).Count -gt 0 })
Assert-Equal @([regex]::Matches($remHtml, '<details class="fix"')).Count $fixableSeen.Count 'report: a fix script under every check that has one, and under no other'
Assert-True (@($fixBlocks | Where-Object { $perr = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($_, [ref]$null, [ref]$perr); @($perr).Count -gt 0 }).Count -eq 0 -and $fixBlocks.Count -ge $fixableSeen.Count) 'report: every fix script parses'
Assert-True (@($fixBlocks | Where-Object { $_ -notmatch '\$Apply = \$false' }).Count -eq 0) 'report: every fix script previews unless $Apply is set to $true'
Assert-True ($remHtml -notmatch '(?i)<pre class="fix-code">[^<]*(Invoke-Expression|DownloadString|Start-Process|FromBase64String)') 'report: no download or hidden code in a fix script'
$inlineRoot = 'HKCU:\Software\HostBadgerInline_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
try {
    $regBlocks = @($fixBlocks | Where-Object { $_ -match '\$changes = @\(' })
    Assert-True ($regBlocks.Count -ge 20) 'report: the registry fix scripts are there to be tested'
    foreach ($rb in $regBlocks) { $null = & ([scriptblock]::Create($rb.Replace("'HKLM:\", "'$inlineRoot\"))) }
    Assert-True (-not (Test-Path $inlineRoot)) 'report fix scripts: the preview creates nothing'
    foreach ($rb in $regBlocks) { $null = & ([scriptblock]::Create($rb.Replace("'HKLM:\", "'$inlineRoot\").Replace('$Apply = $false', '$Apply = $true'))) }
    $wrong = @()
    foreach ($rb in $regBlocks) {
        foreach ($m in [regex]::Matches($rb, "@\{ Path = '([^']+)'; Name = '([^']+)'; Value = (.+?); Type = '(\w+)' \}")) {
            $pth = $m.Groups[1].Value.Replace('HKLM:\', "$inlineRoot\"); $nm = $m.Groups[2].Value; $vl = $m.Groups[3].Value; $ty = $m.Groups[4].Value
            $got = (Get-ItemProperty -LiteralPath $pth -Name $nm -ErrorAction SilentlyContinue).$nm
            $ok = if ($ty -eq 'MultiString') { @($got).Count -eq 0 } elseif ($ty -eq 'DWord') { [int64]$got -eq [int64]$vl } else { "$got" -eq $vl.Trim("'") }
            if (-not $ok) { $wrong += "$nm=$got (wanted $vl)" }
        }
    }
    Assert-Equal ($wrong -join '; ') '' 'report fix scripts: after $Apply = $true every registry value has the value the script promised'
}
finally { Remove-Item -LiteralPath $inlineRoot -Recurse -Force -ErrorAction SilentlyContinue }

# The registry part of the engine, for real, in a private branch of HKCU. The preview changes
# nothing, -Apply sets the value and writes the rollback, a second run changes nothing, and -Restore
# puts back what was there (and removes what was not).
$sbRoot = 'HKCU:\Software\HostBadgerTest_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
try {
    $weakText = [System.IO.File]::ReadAllText((Join-Path $out 'rem\remediate_WKS-ACCT-017.ps1'))
    $regLines = @($weakText -split "`r?`n" | Where-Object { $_ -match '^Set-HbRegistry ' } | ForEach-Object { $_.Replace("-Path 'HKLM:\", "-Path '$sbRoot\") })
    $head = $weakText.Substring(0, $weakText.IndexOf('# ---- '))
    $tail = $weakText.Substring($weakText.IndexOf('# ---------------------------------------------------------------- summary'))
    $sbText = ($head + ($regLines -join "`r`n") + "`r`n`r`n" + $tail).Replace('-not (Test-HbAdmin)', '$false')
    $sbScript = Join-Path $work 'sandbox_remediate.ps1'
    [System.IO.File]::WriteAllText($sbScript, $sbText, (New-Object System.Text.UTF8Encoding($true)))
    $lsaK = "$sbRoot\SYSTEM\CurrentControlSet\Control\Lsa"; $srvK = "$sbRoot\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    New-Item -Path $lsaK -Force | Out-Null; New-Item -Path $srvK -Force | Out-Null
    Set-ItemProperty -Path $lsaK -Name 'LmCompatibilityLevel' -Value 2 -Type DWord
    Set-ItemProperty -Path $srvK -Name 'NullSessionShares' -Value ([string[]]@('share1', 'share2')) -Type MultiString
    $rb = Join-Path $work 'rollback_test.json'
    $null = & $sbScript -IgnoreHostName *>&1
    Assert-Equal (Get-ItemProperty -Path $lsaK -Name 'LmCompatibilityLevel').LmCompatibilityLevel 2 'remediation engine: preview changes nothing (existing value)'
    Assert-True ($null -eq (Get-ItemProperty -Path $lsaK -Name 'NoLMHash' -ErrorAction SilentlyContinue)) 'remediation engine: preview creates nothing'
    $applyOut = & $sbScript -IgnoreHostName -Apply -RollbackFile $rb *>&1 | Out-String
    Assert-Equal (Get-ItemProperty -Path $lsaK -Name 'LmCompatibilityLevel').LmCompatibilityLevel 5 'remediation engine: -Apply sets an existing value'
    Assert-Equal (Get-ItemProperty -Path $lsaK -Name 'NoLMHash').NoLMHash 1 'remediation engine: -Apply creates a missing value'
    Assert-Equal @((Get-ItemProperty -Path $srvK -Name 'NullSessionShares').NullSessionShares).Count 0 'remediation engine: -Apply empties a multi-string'
    $rbEntries = @(); foreach ($x in (Get-Content $rb -Raw | ConvertFrom-Json)) { $rbEntries += $x }
    Assert-True ((Test-Path $rb) -and $rbEntries.Count -ge 30) 'remediation engine: rollback file lists every change'
    Assert-True ($applyOut -match 'Changed \d+' -and $applyOut -cnotmatch '(?m)^FAILED') 'remediation engine: -Apply reports no failure'
    $again = & $sbScript -IgnoreHostName -Apply -RollbackFile (Join-Path $work 'rollback_second.json') *>&1 | Out-String
    Assert-True ($again -match 'Changed 0,') 'remediation engine: a second -Apply changes nothing'
    $null = & $sbScript -IgnoreHostName -Restore $rb -Apply *>&1
    Assert-Equal (Get-ItemProperty -Path $lsaK -Name 'LmCompatibilityLevel').LmCompatibilityLevel 2 'remediation engine: -Restore puts the old value back'
    Assert-True ($null -eq (Get-ItemProperty -Path $lsaK -Name 'NoLMHash' -ErrorAction SilentlyContinue)) 'remediation engine: -Restore removes what it had created'
    Assert-Equal ((Get-ItemProperty -Path $srvK -Name 'NullSessionShares').NullSessionShares -join ',') 'share1,share2' 'remediation engine: -Restore puts the multi-string back'
    # Another computer: refused.
    $refused = $false; try { $null = & $sbScript -Apply *>&1 } catch { $refused = ($_.Exception.Message -match 'generated for WKS-ACCT-017') }
    Assert-True $refused 'remediation script refuses to run on another computer'
}
finally { Remove-Item -LiteralPath $sbRoot -Recurse -Force -ErrorAction SilentlyContinue }

# ------------------------------------------------------------------ optional AI step
# Nothing is sent without -SendToAI. The prompt carries no real name, a name that survives aborts
# the send, and a mock Gemini endpoint round-trips through the real code.
Assert-Equal @(Get-ChildItem $out -Filter '*_ai_*').Count 0 'no AI flag: no prompt, no response, nothing sent'

$aiOut = Join-Path $work 'ai'
New-Item -ItemType Directory -Path $aiOut -Force | Out-Null
$dry = Join-Path $aiOut 'dry.txt'
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $aiOut 'dry.html') -AiDryRun $dry *>&1 | Out-Null
Assert-True (Test-Path -LiteralPath $dry) 'AI dry run writes the prompt file'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $aiOut 'dry_ai_prompt.txt'))) 'AI dry run sends and keeps nothing else'
$prompt = [System.IO.File]::ReadAllText($dry)
$realNames = @('WKS-ACCT-017', 'DC01', 'LT-SALES-112', 'SRV-APP-02', 'WKS-HR-004', 'corp.example', 'jsmith', 'Helpdesk', 'Server Admins', 'LocalAdm',
    'VendorAgent', 'PrintHelper', 'TrayHelper', 'Inventory', 'tvnserver', 'Contoso', 'C:\Users\Public', 'S-1-5-21', 'Intel(R)')
$leaked = @($realNames | Where-Object { $prompt.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
Assert-Equal ($leaked -join ', ') '' 'AI prompt contains no real host, account, path, service or SID'
Assert-True ($prompt -match 'HOST-1' -and $prompt -match 'Coverage gaps' -and $prompt -match 'PATH-\d+') 'AI prompt is tokenized and lists coverage gaps'
Assert-True ($prompt -notmatch 'failed: ') 'collector error messages never reach the prompt'
Assert-True ($prompt -match 'Support ended') 'an account called "support" does not rewrite the word in the text'
Assert-True ($prompt -match 'powershell\.exe') 'stock Windows tools stay readable'
$userPart = $prompt.Substring($prompt.IndexOf('=== USER ==='))
Assert-True ($userPart -match 'CIS 18\.10\.7\.3' -and $userPart -match 'CIS 5\.30' -and $userPart -match 'CIS 2\.3\.7\.5, 2\.3\.7\.6' -and $userPart -notmatch '\bIP-\d') 'CIS rule numbers and lists of them are not taken for IP addresses'
Assert-True ($prompt -match 'Microsoft Windows 10 Pro') 'a task authored by Microsoft does not rewrite the OS name'
Assert-True (@(Test-AiLeak -Pz $pzProbe -Text 'Listening on 10.20.30.40 by x').Count -ge 1 -and @(Test-AiLeak -Pz $pzProbe -Text 'CIS 18.10.7.3 expects 255, build 22631.6199').Count -eq 0) 'leak check: a real address is caught, rule and build numbers are not'
$pzProbe = New-HostPseudonymizer -Snapshots @() -Findings @()
$pzSnaps = @(Get-ChildItem $fleet -Filter *.json | ForEach-Object { Import-HostSnapshot $_.FullName })
$pzFind = @($all)
$pzTest = New-HostPseudonymizer -Snapshots $pzSnaps -Findings $pzFind
Assert-True (@(Test-AiLeak -Pz $pzTest -Text 'the account jsmith on WKS-ACCT-017').Count -ge 2) 'leak check flags names that survive'
Assert-True (@(Test-AiLeak -Pz $pzTest -Text 'S-1-5-21-1111111111-2222222222-3333333333-1342 and C:\Users\bob\x.exe').Count -ge 2) 'leak check flags SIDs and drive paths'
Assert-Equal @(Test-AiLeak -Pz $pzTest -Text 'HOST-1 | account: USER-2 | PATH-3 and C:\Windows\System32\cmd.exe').Count 0 'leak check accepts tokens and stock tools'

# Round trip against a local mock endpoint (the base URL override is the test hook).
$port = Get-Random -Minimum 20000 -Maximum 40000
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()
$cap = [hashtable]::Synchronized(@{})
$aiJson = @{
    executive_summary = 'HOST-1 is the weakest host.'
    remediation_plan  = @(
        @{ title = 'Turn UAC back on'; checks = @('uac_disabled', 'made_up_check'); objects = @('HOST-1'); rationale = 'Admin without prompt.'; effort = 'low'; caveats = 'Reboot needed.' },
        @{ title = 'Invented work package'; checks = @('made_up_check'); objects = @('HOST-1'); rationale = 'x'; effort = 'low'; caveats = '' })
    quick_wins        = @('Disable SMBv1 on HOST-1.')
    monitoring        = @()
    host_priorities   = @(@{ rank = 1; hosts = @('HOST-1', 'HOST-99'); rationale = 'Most findings.' })
    remediation_scripts = @(); triage = @()
} | ConvertTo-Json -Depth 8
$reply = @{ candidates = @(@{ content = @{ parts = @(@{ text = $aiJson }) } }) } | ConvertTo-Json -Depth 8
$ps = [powershell]::Create()
[void]$ps.AddScript({
        param($l, $resp, $c)
        $ctx = $l.GetContext()
        $c.Body = (New-Object System.IO.StreamReader($ctx.Request.InputStream)).ReadToEnd()
        $c.Key = $ctx.Request.Headers['x-goog-api-key']; $c.Url = $ctx.Request.RawUrl
        $bytes = [Text.Encoding]::UTF8.GetBytes($resp)
        $ctx.Response.ContentType = 'application/json'
        $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $ctx.Response.Close()
    }).AddArgument($listener).AddArgument($reply).AddArgument($cap)
$async = $ps.BeginInvoke()
$env:HOSTBADGER_GEMINI_BASEURL = "http://localhost:$port"
try {
    & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $aiOut 'r.html') -SendToAI -ApiKey 'test-key' -Model 'mock-model' -AiMaxAttempts 1 *>&1 | Out-Null
    [void]$async.AsyncWaitHandle.WaitOne(5000)
}
finally { Remove-Item Env:\HOSTBADGER_GEMINI_BASEURL -ErrorAction SilentlyContinue; try { $listener.Stop() } catch { }; $ps.Dispose() }
Assert-Equal $cap.Key 'test-key' 'API key travels in a header'
Assert-True ($cap.Url -match '/v1beta/models/mock-model:generateContent') 'request goes to the model endpoint'
$sentLeaks = @($realNames | Where-Object { "$($cap.Body)".IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
Assert-Equal ($sentLeaks -join ', ') '' 'the request body carries no real name'
Assert-True ((Test-Path (Join-Path $aiOut 'r_ai_prompt.txt')) -and (Test-Path (Join-Path $aiOut 'r_ai_response.json'))) 'prompt and reply kept next to the report'
$aiHtml = [System.IO.File]::ReadAllText((Join-Path $aiOut 'r.html'))
Assert-True ($aiHtml -match 'AI summary and remediation plan' -and $aiHtml -match 'mock-model') 'report gets the AI section'
Assert-True ($aiHtml -match '(?s)Hosts to work on first.*WKS-ACCT-017') 'tokens in the reply are turned back into host names'
Assert-True ($aiHtml -match 'Turn UAC back on' -and $aiHtml -notmatch 'Invented work package') 'items about checks that did not fire are dropped'
Assert-True ($aiHtml -notmatch 'HOST-99') 'unknown host tokens are dropped'
# The launcher, driven with typed answers (menu 2, then the offer that follows the report): "d"
# writes the prompt and sends nothing, "n" leaves it alone.
$psExe = (Get-Process -Id $PID).Path
$wizDir = Join-Path $work 'wizard'; New-Item -ItemType Directory -Path $wizDir -Force | Out-Null
$launcher = Join-Path $root 'Start-HostBadger.ps1'
$wizAnswers = { param($offer) (@('2', $fleet, (Join-Path $wizDir 'w.html'), 'n', '', '', '', $offer) + $(if ($offer -eq 'd') { @((Join-Path $wizDir 'w_prompt.txt')) } else { @() }) + @('q')) -join "`n" }
$wizNo = (& $wizAnswers 'n') | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
Assert-True ($wizNo -match 'Report ready:' -and -not (Test-Path (Join-Path $wizDir 'w_prompt.txt')) -and [regex]::Matches($wizNo, 'Hosts analyzed').Count -eq 1) 'launcher: after the report it offers the AI summary, and "n" does nothing more'
$wizDry = (& $wizAnswers 'd') | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
Assert-True ((Test-Path (Join-Path $wizDir 'w_prompt.txt')) -and $wizDry -match 'Nothing sent') 'launcher: "d" after the report writes the prompt and sends nothing'
# The launcher looks for snapshots by itself: it lists what it finds in a "snapshots" folder, marks an older
# snapshot of the same host, takes the whole folder on Enter, or just the one you pick by number.
$scanDir = Join-Path $work 'scan'; New-Item -ItemType Directory -Path (Join-Path $scanDir 'snapshots') -Force | Out-Null
Copy-Item (Join-Path $fleet 'hostsnapshot_weak.json') (Join-Path $scanDir 'snapshots\hostsnapshot_WKS-ACCT-017_20261001080000.json')
Copy-Item (Join-Path $fleet 'hostsnapshot_weak.json') (Join-Path $scanDir 'snapshots\hostsnapshot_WKS-ACCT-017_20260901080000.json')
Copy-Item (Join-Path $fleet 'hostsnapshot_hardened.json') (Join-Path $scanDir 'snapshots\hostsnapshot_SRV-APP-02_20261001080000.json')
Push-Location $scanDir
try {
    $scanAll = (@('2', '', '', 'n', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    $scanOne = (@('2', '2', '', 'n', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
}
finally { Pop-Location }
Assert-True ($scanAll -match 'Snapshots found in .*snapshots: 3 for 2 host\(s\)' -and $scanAll -match 'WKS-ACCT-017' -and $scanAll -match 'SRV-APP-02' -and $scanAll -match 'older: a folder run ignores it') 'launcher: it lists the snapshots it finds and marks the older one of a host'
Assert-True ($scanAll -match 'Hosts analyzed: 2') 'launcher: Enter takes the whole folder (newest snapshot per host)'
Assert-True ($scanOne -match 'Hosts analyzed: 1') 'launcher: a number picks one snapshot'
$noKey = Join-Path $aiOut 'nokey'
New-Item -ItemType Directory -Path $noKey -Force | Out-Null
$savedKey = $env:GEMINI_API_KEY; $env:GEMINI_API_KEY = ''
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $noKey 'r.html') -SendToAI -ApiKey '' *>&1 | Out-Null } finally { $env:GEMINI_API_KEY = $savedKey }
Assert-True (-not (Test-Path (Join-Path $noKey 'r_ai_response.json'))) 'no key: nothing is sent'
# ------------------------------------------------------------------ local security policy
# The collector's INF parser, cut out of the collector (which can't be dot-sourced) and fed a policy
# export written the way secedit writes it, in UTF-16.
$collectorAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Collect-HostSnapshot.ps1'), [ref]$null, [ref]$null)
$parseFn = $collectorAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'ConvertFrom-SecEditInf' }, $true)[0]
. ([scriptblock]::Create($parseFn.Extent.Text))
$infFile = Join-Path $work 'secpol_sample.inf'
$infText = "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMinimumPasswordAge = 0`r`nMaximumPasswordAge = -1`r`nMinimumPasswordLength = 8`r`nPasswordComplexity = 1`r`nLockoutBadCount = 0`r`nNewAdministratorName = ""Administrator""`r`n[Privilege Rights]`r`nSeDebugPrivilege = *S-1-5-32-544`r`nSeTcbPrivilege = `r`nSeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,CORP\jsmith`r`n"
[System.IO.File]::WriteAllText($infFile, $infText, [System.Text.Encoding]::Unicode)
$pol = ConvertFrom-SecEditInf ([System.IO.File]::ReadAllLines($infFile, [System.Text.Encoding]::Unicode))
Assert-Equal $pol.systemAccess.MaximumPasswordAge -1 'secedit INF: negative value (never expires) parsed'
# Windows Update history: definition updates must not hide an unpatched Windows.
$defFn = $collectorAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Test-DefinitionUpdateTitle' }, $true)[0]
. ([scriptblock]::Create($defFn.Extent.Text))
Assert-True ((Test-DefinitionUpdateTitle 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.449.1.0)') -and (Test-DefinitionUpdateTitle 'Windows Malicious Software Removal Tool x64 - v5.131 (KB890830)') -and (Test-DefinitionUpdateTitle 'Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.2)')) 'update history: definition, platform and MSRT updates do not count as patching'
Assert-True ((Test-DefinitionUpdateTitle "Aggiornamento dell'intelligence sulla sicurezza per Microsoft Defender Antivirus -2267602 KB (versione 1.459.5.0)") -and (Test-DefinitionUpdateTitle 'Aggiornamento per Microsoft Defender Antivirus piattaforma antimalware - 4052623 KB (versione 4.18.26080.4)')) 'update history: localized titles are recognized by their KB number'
Assert-True (-not (Test-DefinitionUpdateTitle '2025-11 Aggiornamento cumulativo per Windows 11 Version 23H2 per sistemi basati su x64 (KB5068865)')) 'update history: a localized cumulative update still counts'
Assert-True (-not (Test-DefinitionUpdateTitle '2025-11 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5068865)') -and -not (Test-DefinitionUpdateTitle 'Windows 11, version 24H2 feature update')) 'update history: cumulative and feature updates count'
Assert-Equal $pol.systemAccess.MinimumPasswordLength 8 'secedit INF: account policy value parsed'
Assert-True (-not $pol.systemAccess.Contains('NewAdministratorName')) 'secedit INF: only the wanted account settings are kept'
Assert-Equal @($pol.privilegeRights.SeTcbPrivilege).Count 0 'secedit INF: a right nobody holds is an empty list'
Assert-Equal ($pol.privilegeRights.SeNetworkLogonRight -join '|') 'S-1-1-0|S-1-5-32-544|CORP\jsmith' 'secedit INF: SIDs and names kept, leading * removed'
Assert-Equal @($weak.Findings | Where-Object { $_.Type -in 'password_policy_weak', 'account_lockout_weak' }).Count 9 'weak: 6 password policy and 3 lockout findings'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'user_rights_excessive' -and $_.Object -eq 'right: SeDebugPrivilege' -and $_.Severity -eq 'High' -and $_.Detail -match 'Users' }).Count -eq 1) 'debug right held by Users is High'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'user_rights_excessive' -and $_.Object -eq 'right: SeBackupPrivilege' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'Backup Operators holding the backup right is Medium'
Assert-Equal @($hard.Findings | Where-Object { $_.Type -match 'password_policy|account_lockout|user_rights|deny_logon' }).Count 0 'hardened server: compliant policy, no finding'
Assert-Equal @($dc.Findings | Where-Object { $_.Type -match 'password_policy|account_lockout|user_rights|deny_logon' }).Count 0 'domain controller: workstation baseline not applied'
Assert-Equal @($part.NotEvaluated | Where-Object { $_.Type -in 'password_policy_weak', 'account_lockout_weak', 'user_rights_excessive', 'deny_logon_rights_missing' }).Count 4 'partial: policy checks not evaluated when the export failed'
# ------------------------------------------------------------------ documentation
# COVERAGE.md is generated from the catalog and the README states the count, so both must follow the
# catalog.
$coverage = [System.IO.File]::ReadAllText((Join-Path $root 'COVERAGE.md'))
$missingDoc = @($script:CheckCatalog.Keys | Where-Object { $coverage -notmatch [regex]::Escape("``$_``") })
Assert-Equal ($missingDoc -join ',') '' 'COVERAGE.md lists every check'
Assert-True ([System.IO.File]::ReadAllText((Join-Path $root 'README.md')) -match "\*\*$($script:CheckCatalog.Count) checks\*\*") 'README states the check count'

# ------------------------------------------------------------------ safety review
$safety = Join-Path $root 'Test-HostBadgerSafety.ps1'
& $safety -Quiet *>&1 | Out-Null
Assert-Equal $LASTEXITCODE 0 'safety review passes on the shipped code'
$tampered = Join-Path $work 'tampered'
New-Item -ItemType Directory -Path $tampered -Force | Out-Null
Copy-Item (Join-Path $root 'Collect-HostSnapshot.ps1'), $safety $tampered
Copy-Item (Join-Path $root 'lib') $tampered -Recurse
Add-Content -LiteralPath (Join-Path $tampered 'Collect-HostSnapshot.ps1') -Value "`nSet-MpPreference -DisableRealtimeMonitoring `$true`nSet-ItemProperty -Path 'HKLM:\SOFTWARE\x' -Name y -Value 1"
& (Join-Path $tampered 'Test-HostBadgerSafety.ps1') -Quiet *>&1 | Out-Null
Assert-Equal $LASTEXITCODE 1 'safety review fails on a tampered copy'

# A script in a subfolder that HostBadger never loads (another tool copied next to it) is reported,
# not mixed into the verdict.
$strayDir = Join-Path $work 'stray'
New-Item -ItemType Directory -Path (Join-Path $strayDir 'OtherTool') -Force | Out-Null
Copy-Item (Join-Path $root 'Collect-HostSnapshot.ps1'), $safety $strayDir
Copy-Item (Join-Path $root 'lib') $strayDir -Recurse
Set-Content -LiteralPath (Join-Path $strayDir 'OtherTool\other.ps1') -Value 'Invoke-Expression "calc"; Install-Module Foo'
$strayOut = & (Join-Path $strayDir 'Test-HostBadgerSafety.ps1') *>&1 | Out-String
Assert-Equal $LASTEXITCODE 0 'safety review: a stray script in another folder does not fail the review'
Assert-True ($strayOut -match 'Not reviewed: 1 script\(s\) in OtherTool') 'safety review: a stray script in another folder is reported as not reviewed'
$tampered3 = Join-Path $work 'tampered3'
New-Item -ItemType Directory -Path $tampered3 -Force | Out-Null
Copy-Item (Join-Path $root 'Collect-HostSnapshot.ps1'), $safety $tampered3
Copy-Item (Join-Path $root 'lib') $tampered3 -Recurse
Add-Content -LiteralPath (Join-Path $tampered3 'Collect-HostSnapshot.ps1') -Value "`nsecedit.exe /configure /db C:\x.sdb /cfg C:\x.inf"
& (Join-Path $tampered3 'Test-HostBadgerSafety.ps1') -Quiet *>&1 | Out-Null
Assert-Equal $LASTEXITCODE 1 'safety review fails on secedit /configure'

$tampered2 = Join-Path $work 'tampered2'
New-Item -ItemType Directory -Path $tampered2 -Force | Out-Null
Copy-Item (Join-Path $root 'Collect-HostSnapshot.ps1'), $safety $tampered2
Copy-Item (Join-Path $root 'lib') $tampered2 -Recurse
Add-Content -LiteralPath (Join-Path $tampered2 'Collect-HostSnapshot.ps1') -Value "`n`$c = New-Object System.Net.Http.HttpClient`n`$null = `$c.GetAsync('https://generativelanguage.googleapis.com/x')"
& (Join-Path $tampered2 'Test-HostBadgerSafety.ps1') -Quiet *>&1 | Out-Null
Assert-Equal $LASTEXITCODE 1 'safety review fails on network code in the collector'
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "HostBadger regression ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)): $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
