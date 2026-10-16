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

# No test may reach the real Gemini, whatever goes wrong (a launcher test whose typed answers slipped
# once sent the synthetic fleet to Google with the developer's key): a fake key, and the AI endpoint
# on a local port where nothing listens. The tests that use the mock endpoint put this back after.
$savedGeminiKey = $env:GEMINI_API_KEY; $savedGeminiBase = $env:HOSTBADGER_GEMINI_BASEURL
$env:GEMINI_API_KEY = 'regression-fake-key'
# The guided menu's saved progress is off in every test but the one that checks it: a test that stopped
# halfway must not leave a "resume?" question that shifts the typed answers of the next one.
$env:HOSTBADGER_NO_RESUME = '1'
$script:NoGemini = 'http://127.0.0.1:9'
$env:HOSTBADGER_GEMINI_BASEURL = $script:NoGemini
# Every test writes under $work: the project folder must not gain a report or an AI file.
$rootFilesBefore = @(Get-ChildItem -LiteralPath (Split-Path $PSScriptRoot -Parent) -File | ForEach-Object { $_.Name })
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("hostbadger_regression_{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$fleet = Join-Path $work 'fleet'
foreach ($sc in 'weak', 'hardened', 'laptop', 'dc', 'partial') {
    & (Join-Path $PSScriptRoot 'New-SyntheticHostSnapshot.ps1') -Scenario $sc -OutFile (Join-Path $fleet "hostsnapshot_$sc.json") 6>$null | Out-Null
}
$config = @{ AllowedAdmins = @(); MaxPatchAgeDays = 45; MaxSignatureAgeDays = 7; SupportWarningDays = 90; MaxCachedLogonsWorkstation = 4; MaxCachedLogonsServer = 1; MinSecurityLogKB = 196608; ExpectedEdr = @(); ExtraEdrServices = @() }

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

Assert-Equal @($weak.Findings).Count 195 'weak: total findings'
Assert-Equal @($hard.Findings).Count 3 'hardened: total findings'
Assert-Equal @($lap.Findings).Count 8 'laptop: total findings'
Assert-Equal @($dc.Findings).Count 28 'dc: total findings'
Assert-Equal @($part.Findings).Count 2 'partial: total findings'
$all = @($weak.Findings) + @($hard.Findings) + @($lap.Findings) + @($dc.Findings) + @($part.Findings)
Assert-Equal ((@('Critical', 'High', 'Medium', 'Low') | ForEach-Object { $s = $_; @($all | Where-Object { $_.Severity -eq $s }).Count }) -join '/') '1/41/108/86' 'fleet: severity split'
# A STIG value no policy sets, with the setting in effect compliant (the weak host's firewall profiles are on): still a finding, at Low.
$effFw = @($weak.Findings | Where-Object { $_.Type -eq 'stig_firewall' -and $_.Found -like 'not configured (in effect:*' })
Assert-True ($effFw.Count -eq 3 -and @($effFw | Where-Object { $_.Severity -ne 'Low' }).Count -eq 0 -and $effFw[0].Detail -match 'setting in effect is compliant') 'STIG: a rule no policy sets but compliant in effect is a Low finding that says so'
# The score measures exposure: DISA STIG, the Brave policy gaps and NoScore findings stay out of it.
$mkF = { param($ty, $sv, $cat, $ns) [PSCustomObject]@{ Type = $ty; Severity = $sv; Category = $cat; NoScore = $ns } }
Assert-Equal (Get-HostScore @((& $mkF 'stig_defender' 'High' 'DISA STIG' $false), (& $mkF 'brave_policy_gaps' 'Medium' 'System Hardening' $false), (& $mkF 'kev_software_match' 'Medium' 'Software' $true))).Score 100 'score: STIG rules, Brave policy gaps and findings counted elsewhere do not lower it'
Assert-Equal (Get-HostScore @((& $mkF 'kev_software_match' 'Low' 'Software' $false))).Score 99 'score: a KEV match not judged by version still counts'
Assert-True (Has $weak 'webclient_webdav_enabled' 'service: WebClient') 'host: the WebClient (WebDAV) service enabled is a coercion/relay finding'
Assert-True (Has $weak 'wpad_not_disabled' 'WPAD auto-discovery') 'host: WPAD not disabled is an NTLM-capture finding'
# edr_expected_missing only exists when the operator names the EDR every host should run.
$cfgEdr = $config.Clone(); $cfgEdr['ExpectedEdr'] = @('SentinelOne')
$edrExpected = Invoke-One (Join-Path $fleet 'hostsnapshot_hardened.json') $cfgEdr
$allWithConfig = @($all) + @($edrExpected.Findings)
# Server 2016 and Server 2025 are not in the five-host fleet; generate one of each (in a separate
# folder, so the fleet analysis still sees five hosts) to exercise the stig_server2016 /
# stig_server2025 checks (and that they quote their own benchmark).
$extra = Join-Path $work 'extra'
foreach ($sc in 'dc2016', 'srv2025') {
    & (Join-Path $PSScriptRoot 'New-SyntheticHostSnapshot.ps1') -Scenario $sc -OutFile (Join-Path $extra "hostsnapshot_$sc.json") 6>$null | Out-Null
}
$dc2016 = Invoke-One (Join-Path $extra 'hostsnapshot_dc2016.json')
$srv2025 = Invoke-One (Join-Path $extra 'hostsnapshot_srv2025.json')
$allWithConfig = @($allWithConfig) + @($dc2016.Findings) + @($srv2025.Findings)
Assert-True (@($dc2016.Findings | Where-Object { $_.Type -eq 'stig_server2016' -and $_.Object -match '^WN16-DC V-' }).Count -eq 2) 'STIG: a Server 2016 domain controller gets the 2016 DC rules'
Assert-True (@($srv2025.Findings | Where-Object { $_.Type -eq 'stig_server2025' -and $_.Object -match '^WN25-MS V-' }).Count -eq 2) 'STIG: a Server 2025 member server gets the 2025 MS rules'
# Script file types, download tools blocked outbound, programs from USB (AtlantHarden gap analysis).
Assert-Equal ((@($weak.Findings | Where-Object { $_.Type -eq 'script_files_execute_on_open' }) | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Found)" }) -join ';') 'file type: .js|Medium|JSFile;file type: .vbs|Medium|VBSFile;file type: .hta|Medium|htafile' 'script types: .js, .vbs and .hta run on a double click (.ps1 opens in Notepad and is not listed)'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'lolbin_outbound_not_blocked' -and $_.Detail -match '^7 of 7 tools have no outbound block rule' }).Count -eq 1 -and @($weak.Findings | Where-Object { $_.Type -eq 'removable_media_execute_allowed' -and $_.Found -eq 'not configured' }).Count -eq 1 -and @($hard.Findings | Where-Object { $_.Type -in 'script_files_execute_on_open', 'lolbin_outbound_not_blocked', 'removable_media_execute_allowed' }).Count -eq 0) 'LOLBins and removable media: flagged on the weak host, clean on the hardened one'
$wshOff = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'); $wshOff.hardening.scriptHostEnabled = 0
Assert-Equal ((@((Invoke-HostChecks -Snapshot $wshOff -Config $config).Findings | Where-Object { $_.Type -eq 'script_files_execute_on_open' }) | ForEach-Object { $_.Object }) -join ',') 'file type: .hta' 'script types: with Windows Script Host disabled only .hta (mshta) is left'
$oldSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'); foreach ($f in 'fileAssociations', 'lolbinOutboundBlocks', 'removableStorage') { $oldSnap.hardening.PSObject.Properties.Remove($f) }
Assert-Equal @((Invoke-HostChecks -Snapshot $oldSnap -Config $config).Findings | Where-Object { $_.Type -in 'script_files_execute_on_open', 'lolbin_outbound_not_blocked', 'removable_media_execute_allowed' }).Count 0 'a snapshot from before these fields is not judged on them'
$jsFix = @(Get-RemediationActions -Finding @($weak.Findings | Where-Object { $_.Object -eq 'file type: .js' })[0] -Role 'workstation' -Config $config)
Assert-True ($jsFix.Count -eq 1 -and $jsFix[0].Path -eq 'HKLM:\SOFTWARE\Classes\.js' -and $jsFix[0].Name -eq '(default)' -and $jsFix[0].Value -eq 'txtfile') 'script types: the fix opens the extension as text (default value txtfile)'
# Bloatware: Store apps installed or provisioned, and antivirus trials, from a curated list.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'bloatware_installed' -and $_.Detail -eq 'King games (Candy Crush...) (installed); Microsoft Solitaire Collection (provisioned for new users).' -and $_.Severity -eq 'Low' }).Count -eq 1 -and @($hard.Findings | Where-Object { $_.Type -eq 'bloatware_installed' }).Count -eq 0) 'bloatware: listed with where it is (installed, provisioned), Calculator and Photos left alone'
$noAppx = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'); $noAppx.meta.sectionsCollected = @($noAppx.meta.sectionsCollected | Where-Object { $_ -ne 'appx' })
Assert-True (@((Invoke-HostChecks -Snapshot $noAppx -Config $config).NotEvaluated | Where-Object { $_.Type -eq 'bloatware_installed' -and $_.Reason -match "section 'appx' not in the snapshot" }).Count -eq 1) 'bloatware: a snapshot without the Store app list says so (not evaluated), never clean'
# Adobe Acrobat Reader DC STIG (V2R1): two rules not configured on the Server 2025 host, which has Reader.
Assert-Equal ((@($srv2025.Findings | Where-Object { $_.Type -eq 'stig_adobe' }) | ForEach-Object { $_.Object }) -join ';') 'ARDC V-213168: bEnhancedSecurityStandalone;ARDC V-213169: bEnhancedSecurityInBrowser' 'STIG Adobe: an installed Acrobat Reader is judged on its STIG, hosts without it are not'
# Brave: the Chrome STIG rules read under Brave's policy key and Brave's own policies (not a DISA STIG).
Assert-Equal ((@($srv2025.Findings | Where-Object { $_.Type -eq 'brave_policy_gaps' }) | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Found)|$($_.Expected)" }) -join ';') 'Brave (DTBC V-221558): RemoteAccessHostFirewallTraversal|Medium|not configured|0;Brave: TorDisabled|Medium|not configured|1' 'Brave: a Chrome STIG policy missing under the Brave key and Tor not disabled; wallet and Rewards off are fine'
Assert-Equal @($all | Where-Object { $_.Type -eq 'brave_policy_gaps' }).Count 0 'Brave: hosts without Brave are not judged on it'
# CIS server services: Print Spooler on a member server (Server 2022 5.2, L2); a domain controller is
# left to spooler_on_dc, a disabled Spooler gives nothing.
$spoolSrv = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
foreach ($sv in @($spoolSrv.services | Where-Object { $_.name -eq 'Spooler' })) { $sv.startMode = 'Auto' }
$spoolRes = @((Invoke-HostChecks -Snapshot $spoolSrv -Config $config).Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' })
Assert-Equal (($spoolRes | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Cis)|$($_.Found)|$($_.Expected)" }) -join ';') 'service: Spooler|Low|5.2 (L2)|Stopped, start mode Auto|disabled unless this is a print server' 'CIS server services: Print Spooler on a member server quotes the server rule 5.2 (L2)'
Assert-True ($spoolRes[0].Detail -match '\(CIS Server 2022 5\.2 expects disabled' -and @($hard.Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' }).Count -eq 0 -and @($dc.Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' }).Count -eq 0) 'CIS server services: the detail names the server benchmark; disabled on the hardened server and left to spooler_on_dc on a DC'
Assert-True (@($dc2016.Findings | Where-Object { $_.Type -in 'stig_server2019', 'stig_server2022', 'stig_server2025' }).Count -eq 0 -and @($srv2025.Findings | Where-Object { $_.Type -in 'stig_server2016', 'stig_server2019', 'stig_server2022' }).Count -eq 0) 'STIG: each server version gets only its own STIG'
# kev_software_match needs a KEV catalog and software_outdated endoflife.date data; both are exercised
# with sample data further down.
$never = @($script:CheckCatalog.Keys | Where-Object { $t = $_; $t -notin 'kev_software_match', 'software_outdated', 'software_cve' -and @($allWithConfig | Where-Object { $_.Type -eq $t }).Count -eq 0 })
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

# BitLocker policy: weak values with their own severity, unset DMA/USB judged only on workstations
# that can have the policy, organizational choices only when set and different.
$blw = @($weak.Findings | Where-Object { $_.Type -eq 'bitlocker_policy_weak' })
Assert-Equal (($blw | Sort-Object Object | ForEach-Object { "$($_.Object -replace '^BitLocker policy: ')=$($_.Severity)" }) -join ',') 'DisableExternalDMAUnderLock=Low,EnableBDEWithNoTPM=Medium,OSHardwareEncryption=Medium,RDVDenyWriteAccess=Low' 'BitLocker policy: weak values and their severity'
Assert-Equal @($blw | Where-Object { $_.Detail -match 'not set' } | ForEach-Object { $_.Object }) 'BitLocker policy: DisableExternalDMAUnderLock' 'BitLocker policy: unset DMA policy judged on a workstation'
Assert-Equal ((@($weak.Findings | Where-Object { $_.Type -eq 'bitlocker_policy_gaps' }) | Sort-Object Object | ForEach-Object { $_.Object -replace '^BitLocker policy: ' }) -join ',') 'FDVDiscoveryVolumeType,OSActiveDirectoryBackup' 'BitLocker policy: gaps only for set values that differ ("1 or 2" accepted)'
Assert-Equal ((@($homeRes.Findings | Where-Object { $_.Type -eq 'bitlocker_policy_weak' }) | Sort-Object Object | ForEach-Object { $_.Object -replace '^BitLocker policy: ' }) -join ',') 'EnableBDEWithNoTPM,OSHardwareEncryption,RDVDenyWriteAccess' 'Home: unset BitLocker policy not judged, explicit values still are'
Assert-Equal @($hard.Findings | Where-Object { $_.Type -like 'bitlocker_policy_*' }).Count 0 'BitLocker policy: hardened host clean'
# CIS on servers: the same checks quote the Windows Server 2022/2019 rule (data\cis-map.json), the
# domain controller or member server variant by role, and "Windows 11 x.y" when the server benchmark
# has no such rule.
$srv = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json')
$srv.host.os.caption = 'Microsoft Windows Server 2022 Standard'; $srv.host.os.build = 20348; $srv.host.os.productType = 3; $srv.host.role = 'server'
$srvRes = @((Invoke-HostChecks -Snapshot $srv -Config $config).Findings)
$f = $srvRes | Where-Object { $_.Type -eq 'winrm_insecure_auth' -and $_.Object -eq 'WinRM service: RunAs credential storage' }
Assert-Equal "$($f.Cis)|$($f.CisBenchmark)|$($f.Detail -match 'CIS Server 2022 18\.10\.89\.2\.4 expects 1')" '18.10.89.2.4 (L1)|CIS Microsoft Windows Server 2022 Benchmark v4.0.0|True' 'CIS server: Server 2022 rule, benchmark and detail'
$f = $srvRes | Where-Object { $_.Type -eq 'bitlocker_policy_weak' -and $_.Object -eq 'BitLocker policy: OSHardwareEncryption' }
Assert-Equal "$($f.Cis)|$($f.CisBenchmark)" 'Windows 11 18.10.9.2.11|CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0' 'CIS server: a rule with no server counterpart keeps its Windows 11 number and says so'
Assert-Equal (@($srvRes | Where-Object { $_.Type -eq 'cached_logons_high' }).Cis) '2.3.7.6 (L2)' 'CIS server: member server variant, with the server profile level'
Assert-Equal (@($weak.Findings | Where-Object { $_.Type -eq 'ldap_client_signing_off' }) | ForEach-Object { "$($_.Cis)|$($_.CisBenchmark)" }) '2.3.11.8 (L1)|CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0' 'CIS Windows 10: the weak host quotes the Windows 10 benchmark'
$w11 = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'); $w11.host.os.caption = 'Microsoft Windows 11 Enterprise'; $w11.host.os.build = 22631
$w11Res = @((Invoke-HostChecks -Snapshot $w11 -Config $config).Findings)
$ssdp = @($w11Res | Where-Object { $_.Type -eq 'service_should_be_disabled' -and $_.Object -eq 'service: SSDPSRV' })
Assert-True ($ssdp.Count -eq 1 -and $ssdp[0].Cis -eq '5.30 (L1)' -and $ssdp[0].CisBenchmark -match 'Windows 11' -and $ssdp[0].Detail -match 'CIS 5\.30 expects') 'CIS Windows 11: the rule numbers the checks are written with, unchanged'
Assert-Equal (@($weak.Findings | Where-Object { $_.Type -eq 'logon_banner_missing' }).Detail) 'No LegalNoticeCaption or LegalNoticeText (CIS Windows 10 2.3.7.5, 2.3.7.6).' 'CIS: every number of a list is translated, the benchmark named once'
$srv.host.os.caption = 'Microsoft Windows Server 2019 Standard'; $srv.host.os.build = 17763
Assert-Equal (@((Invoke-HostChecks -Snapshot $srv -Config $config).Findings | Where-Object { $_.Type -eq 'ldap_client_signing_off' }).Cis) '2.3.11.8 (L1)' 'CIS server: Server 2019 has its own numbers (2.3.11.8, 2.3.11.9 on 2022)'
$srv.host.os.caption = 'Microsoft Windows Server 2022 Standard'; $srv.host.os.build = 20348; $srv.host.os.productType = 2; $srv.host.role = 'dc'
$dcRes = @((Invoke-HostChecks -Snapshot $srv -Config $config).Findings)
Assert-Equal (@($dcRes | Where-Object { $_.Type -eq 'null_session_access' -and $_.Object -eq 'NullSessionPipes' }) | ForEach-Object { "$($_.Cis)|$($_.Detail -match 'besides LSARPC')" }) '2.3.10.6 (L1)|True' 'CIS DC: domain controller variant; pipes judged besides LSARPC, NETLOGON, SAMR'
Assert-Equal (@($dcRes | Where-Object { $_.Type -eq 'anonymous_sam_enum' }).Cis) 'Windows 11 2.3.10.2 (L1)' 'CIS DC: a member-server-only rule is not quoted on a DC'
$srv.hardening.nullSessionPipesCount = 3; $srv.hardening.nullSessionPipesNonDcCount = 0
Assert-Equal @((Invoke-HostChecks -Snapshot $srv -Config $config).Findings | Where-Object { $_.Type -eq 'null_session_access' -and $_.Object -eq 'NullSessionPipes' }).Count 0 'DC: LSARPC, NETLOGON and SAMR alone are not a finding'
$srv.host.role = 'server'; $srv.host.os.productType = 3
Assert-Equal @((Invoke-HostChecks -Snapshot $srv -Config $config).Findings | Where-Object { $_.Type -eq 'null_session_access' -and $_.Object -eq 'NullSessionPipes' }).Count 1 'member server: the same three pipes are a finding'
Assert-True (@(Get-Content (Join-Path $root 'data\cis-map.json') -Raw | ConvertFrom-Json).rules.'2.2.2'.srv2022.Count -eq 2) 'CIS map: user rights map to the DC and the member server variants'

$dcSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_dc.json'); $dcSnap.hardening.bitlockerPolicy = [pscustomobject]@{ UseTPM = 1 }
Assert-Equal (@((Invoke-HostChecks -Snapshot $dcSnap -Config $config).Findings | Where-Object { $_.Type -like 'bitlocker_policy_*' } | ForEach-Object { $_.Type }) -join ',') 'bitlocker_policy_gaps' 'BitLocker policy: unset DMA/USB not judged on a server'

# Patching: the hotfix list decides. The update history (definitions, .NET, PowerShell...) must not
# hide an unpatched Windows.
$staleSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$staleSnap.patches.hotfixes = @([PSCustomObject]@{ id = 'KB5068865'; description = 'Security Update'; installedOnUtc = '2025-11-20T00:00:00Z' }); $staleSnap.patches.lastUpdateInstalledUtc = '2026-09-30T08:00:00Z'
Assert-True (@((Invoke-HostChecks -Snapshot $staleSnap -Config $config).Findings | Where-Object { $_.Type -eq 'updates_stale' -and $_.Detail -match 'hotfix list' -and $_.Detail -match '2025-11-20' -and $_.Detail -match 'history shows a later item on 2026-09-30' }).Count -eq 1) 'updates_stale: an old hotfix list is not hidden by a recent update history, and the finding says why the screen shows a later date'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'updates_stale' -and $_.Detail -notmatch 'later item' }).Count -eq 1) 'updates_stale: no explanation when the history shows nothing later'
$undatedSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$undatedSnap.patches.hotfixes = @([PSCustomObject]@{ id = 'KB5068865'; description = 'Security Update'; installedOnUtc = $null }); $undatedSnap.patches.lastUpdateInstalledUtc = '2026-09-30T08:00:00Z'
Assert-Equal @((Invoke-HostChecks -Snapshot $undatedSnap -Config $config).Findings | Where-Object { $_.Type -eq 'updates_stale' }).Count 0 'updates_stale: without dated hotfixes the update history is used'

# EDR agents: found by the name or the display name of their services, never confused with Defender alone.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'edr_not_found' -and $_.Severity -eq 'Low' }).Count -eq 1) 'EDR: a workstation with no agent is Low'
Assert-True (@($dc.Findings | Where-Object { $_.Type -eq 'edr_agent_stopped' -and $_.Severity -eq 'High' -and $_.Detail -match 'CSFalconService' }).Count -eq 1) 'EDR: an agent that is installed but stopped is High'
Assert-Equal @($hard.Findings + $lap.Findings + $part.Findings | Where-Object { $_.Type -like 'edr_*' }).Count 0 'EDR: hosts with a running agent have no EDR finding'
Assert-True (@($edrExpected.Findings | Where-Object { $_.Type -eq 'edr_expected_missing' -and $_.Object -eq 'expected: SentinelOne' -and $_.Severity -eq 'High' }).Count -eq 1 -and @($edrExpected.Findings | Where-Object { $_.Type -eq 'edr_not_found' }).Count -eq 0) 'EDR: the expected product missing is High, and then "no EDR found" is not also raised'
$cfgHave = $config.Clone(); $cfgHave['ExpectedEdr'] = @('crowdstrike')
Assert-Equal @((Invoke-One (Join-Path $fleet 'hostsnapshot_hardened.json') $cfgHave).Findings | Where-Object { $_.Type -like 'edr_*' }).Count 0 'EDR: the expected product is found, whatever the case of the name'
$cfgOwn = $config.Clone(); $cfgOwn['ExpectedEdr'] = @('Dnscache')
Assert-Equal @((Invoke-One (Join-Path $fleet 'hostsnapshot_hardened.json') $cfgOwn).Findings | Where-Object { $_.Type -like 'edr_*' }).Count 0 'EDR: any other text is looked for in the service names'
$cfgExtra = $config.Clone(); $cfgExtra['ExtraEdrServices'] = @('Spooler')
Assert-Equal @((Invoke-One (Join-Path $fleet 'hostsnapshot_weak.json') $cfgExtra).Findings | Where-Object { $_.Type -eq 'edr_not_found' }).Count 0 'EDR: a service named with -ExtraEdrServices counts as an agent'
$senseSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$senseSnap.services = @([PSCustomObject]@{ name = 'Sense'; displayName = 'Windows Defender Advanced Threat Protection Service'; startMode = 'Manual'; state = 'Stopped'; account = 'LocalSystem'; pathName = ''; executable = ''; writableBy = @() })
$senseRes = Invoke-HostChecks -Snapshot $senseSnap -Config $config
Assert-True (@($senseRes.Findings | Where-Object { $_.Type -eq 'edr_not_found' -and $_.Severity -eq 'Medium' }).Count -eq 1 -and @($senseRes.Findings | Where-Object { $_.Type -eq 'edr_agent_stopped' }).Count -eq 0) 'EDR: the Defender for Endpoint service that was never onboarded is not an agent (and a server without one is Medium)'
$senseSnap.services[0].startMode = 'Auto'
Assert-Equal @((Invoke-HostChecks -Snapshot $senseSnap -Config $config).Findings | Where-Object { $_.Type -eq 'edr_agent_stopped' }).Count 1 'EDR: an onboarded Defender for Endpoint service that is stopped is flagged'
# CIS rule: the finding quotes its own rule, not the range that belongs to the check.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'service_should_be_disabled' -and $_.Object -eq 'service: SSDPSRV' -and $_.Severity -eq 'Medium' -and $_.Cis -eq '5.31 (L1)' }).Count -eq 1) 'service finding carries its own CIS rule and level (Windows 10 numbering: 5.31)'
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
Assert-Equal $neTypes.Count 30 'partial: checks not evaluated'
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
Assert-Equal @((Invoke-One $legacy).Findings).Count 3 'legacy {} for an empty list read as empty'

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
Assert-Equal $csv.Count 236 'end to end: findings CSV (zip read, older duplicate ignored)'
Assert-Equal @($csv | Where-Object { $_.Host -eq 'LT-SALES-112' -and $_.Type -eq 'os_support_ending' } | ForEach-Object { $_.Detail -match '39 days' }).Count 1 'newest snapshot of a host used'
$html = [System.IO.File]::ReadAllText((Join-Path $out 'r.html'))
Assert-True ($html -match 'Incomplete coverage' -and $html -match 'WKS-HR-004') 'report lists not evaluated checks with the host'
Assert-True ($html -match '5 hosts' -and $html -match 'Weakest: WKS-ACCT-017') 'fleet cards'
Assert-True ($html -notmatch 'https?://(?!attack\.mitre\.org)') 'report has no external links except MITRE'
$lines = @(Get-Content (Join-Path $out 'r.jsonl'))
Assert-Equal $lines.Count 241 'JSON Lines: 236 findings + 5 host summaries'
$parsed = @($lines | ForEach-Object { $_ | ConvertFrom-Json })
Assert-Equal @($parsed | Where-Object { $_.event_type -eq 'host_summary' -and $_.host -eq 'WKS-HR-004' -and $_.not_evaluated -eq 30 }).Count 1 'host summary carries the not evaluated count'
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
# 236 - 2 (partial host not collected) - 1 (UAC fixed) - 1 (SMBv1 accepted) - 2 (NetBIOS accepted) = 230
Assert-Equal $csv2.Count 230 'second run: fixed, accepted and missing-host findings gone'
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
Assert-Equal "$($remWeak.ActionCount)/$($remWeak.FixableFindings)/$($remWeak.TotalFindings)" '86/85/195' 'remediation: weak host settings / findings with a script / findings'
Assert-Equal "$($remDc.ActionCount)/$($remDc.FixableFindings)/$($remDc.TotalFindings)" '5/5/28' 'remediation: domain controller settings / findings with a script / findings'
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
Assert-True ($remHtml -match '<th>EDR</th>' -and $remHtml -match 'CrowdStrike Falcon' -and $remHtml -match '\(stopped\)' -and $remHtml -match 'none found') 'report: the hosts table shows which EDR each host runs, stopped or missing'
Assert-True (@(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event_type -eq 'host_summary' -and $_.host -eq 'DC01' -and @($_.edr) -contains 'CrowdStrike Falcon:stopped' }).Count -eq 1) 'JSON Lines: host_summary lists the EDR agents and their state'
Assert-True ($remHtml -match 'Remediation scripts' -and $remHtml -match 'remediate_WKS-ACCT-017\.ps1') 'report lists the remediation scripts'
Assert-True (@(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.check -eq 'wdigest_cleartext' -and $_.fix_available -eq $true }).Count -eq 1 -and @(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.check -eq 'bitlocker_os_volume_off' -and $_.fix_available -eq $false }).Count -eq 1) 'JSON Lines: fix_available follows the check'
# Found / expected: the value on the host next to what the framework requires, for CIS and STIG.
$jl = @(Get-Content (Join-Path $out 'r.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event_type -eq 'finding' })
$pick = { param($c, $o) @($jl | Where-Object { $_.check -eq $c -and $_.object -eq $o }) | ForEach-Object { "$($_.found)|$($_.expected)" } }
Assert-Equal (& $pick 'smb_insecure_guest_auth' 'SMB client') '1|0' 'found/expected: read from a CIS detail ("AllowInsecureGuestAuth = 1 (CIS ... expects 0)")'
Assert-Equal (& $pick 'wdigest_cleartext' 'WDigest') '1|0' 'found/expected: given by a check whose detail does not say it'
Assert-Equal (& $pick 'user_rights_excessive' 'right: SeDebugPrivilege') 'Administrators, Users|Administrators' 'found/expected: who holds a right and who may'
Assert-True (@($jl | Where-Object { $_.check -eq 'stig_windows11' -and $_.found -eq 'not configured' -and $_.expected }).Count -eq 2) 'found/expected: a STIG rule not configured says so, with the required value'
Assert-True (@($jl | Where-Object { $_.cis -and $_.check -notin 'audit_policy_gaps', 'asr_standard_rules_missing' -and -not ($_.found -and $_.expected) }).Count -eq 0) 'found/expected: every CIS finding has both, except the aggregate ones'
Assert-True (@($jl | Where-Object { $_.check -eq 'audit_policy_gaps' -and $null -eq $_.found -and $null -eq $_.expected }).Count -ge 1) 'found/expected: an aggregate finding leaves both null in JSON Lines'
$csvFe = @(Import-Csv (Join-Path $out 'r.csv') | Where-Object { $_.Type -eq 'wdigest_cleartext' })
Assert-True ($csvFe.Count -eq 1 -and $csvFe[0].Found -eq '1' -and $csvFe[0].Expected -eq '0') 'found/expected: CSV columns'
# Dashboard tab: the fleet and one view per host, STIG by product with its release, CIS, Essential Eight.
Assert-True ($remHtml -match "<button class='tab-btn active' data-for='dashboard'" -and $remHtml -match '<div data-tab="details" hidden>' -and [regex]::Matches($remHtml, "class='dash-scope' id='dash-").Count -eq 6 -and $remHtml -match "<option value='dash-host-\d'>WKS-ACCT-017 \(F") 'dashboard: opens first, with the fleet and one view per host in a selector; the full report is the Details tab'
Assert-True ($remHtml -match 'Windows 11 V2R7</td><td class=''num''>\d+/\d+</td>' -and $remHtml -match 'ACSC Essential Eight' -and $remHtml -match 'not a maturity assessment' -and $remHtml -match 'Multi-factor authentication</td><td class=''num'' colspan=''2''>not visible from a host') 'dashboard: STIG compliance by product with its release, Essential Eight coverage that says what it is not'
Assert-Equal (@($script:E8Strategies.Values | ForEach-Object { $_.Checks } | Where-Object { $_ -and -not $script:CheckCatalog.Contains($_) }) -join ',') '' 'Essential Eight: every mapped check exists'
Assert-Equal (@($script:CheckCatalog.Keys | Where-Object { $_ -like 'stig_*' -and -not $script:StigTypeLabel.Contains($_) }) -join ',') '' 'dashboard: every STIG check type has its release label'
# Attacks it enables: every check says what an attacker can do with it, in the report, CSV and JSON Lines.
Assert-Equal ((@($script:CheckCatalog.Keys | Where-Object { -not "$($script:CheckCatalog[$_].Attacks)".Trim() }) + @($script:CheckAttacks.Keys | Where-Object { -not $script:CheckCatalog.Contains($_) })) -join ',') '' 'attacks: every check has its "Attacks it enables" text, and every text belongs to a check'
Assert-True (@($jl | Where-Object { -not $_.attacks }).Count -eq 0 -and @($jl | Where-Object { $_.check -eq 'wdigest_cleartext' })[0].attacks -match 'mimikatz' -and $csvFe[0].Attacks -match '^Clear-text password theft') 'attacks: in every JSON Lines finding and in the CSV'
Assert-True ($remHtml -match '<div class="kv attacks"><b>Attacks it enables\.</b> Clear-text password theft') 'attacks: shown under each check of the report'
$feHtml = [System.IO.File]::ReadAllText((Join-Path $out 'r.html'))
Assert-True ($feHtml -match '<th>Found</th><th>Required</th>' -and $feHtml -match '<td class="found">not configured</td>') 'found/expected: report columns'

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
Assert-True ($prompt -match 'os_unsupported: Windows version out of support \(' -and $prompt -notmatch 'out of USER-\d') 'an account called "support" does not rewrite a check title'
Assert-True ($prompt -match 'powershell\.exe') 'stock Windows tools stay readable'
$userPart = $prompt.Substring($prompt.IndexOf('=== USER ==='))
Assert-True ($userPart -match 'CIS Windows 10 18\.10\.7\.3' -and $userPart -match 'CIS Windows 10 5\.31' -and $userPart -match 'CIS Windows 10 2\.3\.7\.5, 2\.3\.7\.6' -and $userPart -match 'CIS Server 2019 2\.3\.5\.2' -and $userPart -notmatch '\bIP-\d') 'CIS rule numbers and lists of them are not taken for IP addresses, with the server benchmark name too'
Assert-True ($prompt -match 'Microsoft Windows 10 Pro') 'a task authored by Microsoft does not rewrite the OS name'
Assert-True (@(Test-AiLeak -Pz $pzProbe -Text 'Listening on 10.20.30.40 by x').Count -ge 1 -and @(Test-AiLeak -Pz $pzProbe -Text 'CIS 18.10.7.3 expects 255, build 22631.6199').Count -eq 0) 'leak check: a real address is caught, rule and build numbers are not'
$pzProbe = New-HostPseudonymizer -Snapshots @() -Findings @()
Assert-True (@(Test-AiLeak -Pz $pzProbe -Text 'CIS Server 2022 2.3.11.9 expects 1; CIS Windows 11 2.3.10.2').Count -eq 0 -and (Protect-AiText -Pz $pzProbe -Text 'host at 10.1.2.3 (CIS Server 2019 2.3.5.4)') -match '^host at IP-\d+ \(CIS Server 2019 2\.3\.5\.4\)$') 'AI: a server rule number is not an address, a real address still is'
$pzSnaps = @(Get-ChildItem $fleet -Filter *.json | ForEach-Object { Import-HostSnapshot $_.FullName })
$pzFind = @($all)
$pzTest = New-HostPseudonymizer -Snapshots $pzSnaps -Findings $pzFind
Assert-True (@(Test-AiLeak -Pz $pzTest -Text 'the account jsmith on WKS-ACCT-017').Count -ge 2) 'leak check flags names that survive'
Assert-True (@(Test-AiLeak -Pz $pzTest -Text 'os_unsupported: Windows version out of support').Count -eq 0 -and @(Test-AiLeak -Pz $pzTest -Text 'Windows version out of support for support').Count -ge 1) 'leak check: a check title is not a leak, the same word outside it still is'
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
finally { $env:HOSTBADGER_GEMINI_BASEURL = $script:NoGemini; try { $listener.Stop() } catch { }; $ps.Dispose() }
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
# The remediation question follows JSON Lines: "y" and Enter on the folder (next to the report) when the
# offer is "n", plain Enter (no) otherwise.
$wizAnswers = { param($offer) (@('2', $fleet, (Join-Path $wizDir 'w.html'), '', '', '', '', '', 'n', '', '', '', '') + $(if ($offer -eq 'n') { @('y', '') } else { @('') }) + @('', '', '', '', '', $offer) + $(if ($offer -eq 'd') { @('', (Join-Path $wizDir 'w_prompt.txt')) } else { @() }) + @('q')) -join "`n" }
# Run from the test folder: the launcher offers catalogs kept in .\output, and the project's own output
# folder may hold real ones.
Push-Location $wizDir
try {
    $wizNo = (& $wizAnswers 'n') | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    $wizNoPrompt = Test-Path (Join-Path $wizDir 'w_prompt.txt')
    $wizDry = (& $wizAnswers 'd') | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    # Before the run every answer is listed and can be changed: 4 flips "DISA STIG rules", Enter runs.
    $wizEdit = (@('2', $fleet, (Join-Path $wizDir 'e.html'), '', '', '', '', '', 'n', '', '', '', '', '', '', '', '', '', '4', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
}
finally { Pop-Location }
Assert-True ($wizNo -match 'Not running as administrator|Running as administrator' -and $wizNo -notmatch 'Restart this menu as administrator') 'launcher: says up front whether it runs as administrator (the restart is offered only at an interactive console)'
Assert-True ($wizNo -match 'Report ready:' -and -not $wizNoPrompt -and [regex]::Matches($wizNo, 'Hosts analyzed').Count -eq 1) 'launcher: after the report it offers the AI summary, and "n" does nothing more'
Assert-True ($wizNo -match 'remediate_<host>\.ps1' -and @(Get-ChildItem (Join-Path $wizDir 'w_remediation') -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object) -join ',' -eq 'remediate_DC01.ps1,remediate_WKS-ACCT-017.ps1') 'launcher: asks about per-host remediation scripts and writes them next to the report (the hosts with a fix)'
Assert-True ($wizEdit -match 'Settings for this run:' -and $wizEdit -match '\[ 4\] DISA STIG rules\s+no' -and (Test-Path (Join-Path $wizDir 'e.csv')) -and @(Import-Csv (Join-Path $wizDir 'e.csv') | Where-Object { $_.Type -like 'stig_*' }).Count -eq 0 -and @(Import-Csv (Join-Path $wizDir 'e.csv')).Count -gt 0) 'launcher: the answers are listed before the run and one can be changed (DISA STIG turned off)'
Assert-True ((Test-Path (Join-Path $wizDir 'w_prompt.txt')) -and $wizDry -match 'Nothing sent') 'launcher: "d" after the report writes the prompt and sends nothing'
# The launcher looks for snapshots by itself: it lists what it finds in a "snapshots" folder, marks an older
# snapshot of the same host, takes the whole folder on Enter, or just the one you pick by number.
$scanDir = Join-Path $work 'scan'; New-Item -ItemType Directory -Path (Join-Path $scanDir 'snapshots') -Force | Out-Null
Copy-Item (Join-Path $fleet 'hostsnapshot_weak.json') (Join-Path $scanDir 'snapshots\hostsnapshot_WKS-ACCT-017_20261001080000.json')
Copy-Item (Join-Path $fleet 'hostsnapshot_weak.json') (Join-Path $scanDir 'snapshots\hostsnapshot_WKS-ACCT-017_20260901080000.json')
Copy-Item (Join-Path $fleet 'hostsnapshot_hardened.json') (Join-Path $scanDir 'snapshots\hostsnapshot_SRV-APP-02_20261001080000.json')
Push-Location $scanDir
try {
    $scanAll = (@('2', '', '', '', '', '', '', '', 'n', '', '', '', '', '', '', '', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    $scanOne = (@('2', '2', '', '', '', '', '', 'n', '', '', '', '', '', '', '', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    # Remediation: never applied in a test. Option 7 with no backup says so; option 6 stops for a
    # standard user, or is declined at "Continue?" when the tests run elevated.
    $rem7 = (@('7', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    $rem6 = (@('6', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
}
finally { Pop-Location }
Assert-True ($scanAll -match 'Snapshots found in .*snapshots: 3 for 2 host\(s\)' -and $scanAll -match 'WKS-ACCT-017' -and $scanAll -match 'SRV-APP-02' -and $scanAll -match 'older: a folder run ignores it') 'launcher: it lists the snapshots it finds and marks the older one of a host'
Assert-True ($scanAll -match 'Hosts analyzed: 2') 'launcher: Enter takes the whole folder (newest snapshot per host)'
Assert-True ($scanAll -match '2 hosts found: HostBadger can also write one report per host' -and $scanOne -notmatch 'one report per host') 'launcher: asks about per-host reports only for a folder with several hosts'
Assert-True (@(Get-ChildItem $scanDir -Filter 'hostbadger_*_*-*.html' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '_(WKS-ACCT-017|SRV-APP-02)\.html$' }).Count -eq 2) 'launcher: Enter on the per-host question writes one report per host (in .\output by default)'
Assert-True ($scanOne -match 'Hosts analyzed: 1') 'launcher: a number picks one snapshot'
# Saved progress: an analysis that stopped halfway is offered at the next start and resumes with the
# answers it had (the rest is asked); a remediation that stopped is explained, never resumed.
$resDir = Join-Path $work 'resume'; New-Item -ItemType Directory -Path (Join-Path $resDir 'output') -Force | Out-Null
$resState = Join-Path $resDir 'output\hostbadger-wizard-state.json'; $resHtml = Join-Path $resDir 'r.html'
$writeState = { param($o) [System.IO.File]::WriteAllText($resState, ($o | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false))) }
& $writeState ([ordered]@{ version = 1; flow = 'analyze'; stage = 'running'; savedUtc = '2026-10-15 10:00 UTC'; answers = [ordered]@{ 'Snapshot' = $fleet; 'Report HTML path' = $resHtml; 'One report per host? (Y/n)' = 'n'; 'Include the DISA STIG rules? (Y/n)' = ''; 'Show the CIS-based findings in the report? (Y/n)' = ''; 'Show the DISA STIG findings in the report? (Y/n)' = ''; 'CISA KEV catalog: [N]one, [O]nline download, or a [F]ile you already have (N/o/f)' = 'N' } })
Push-Location $resDir; $env:HOSTBADGER_NO_RESUME = ''
try {
    $resOut = (@('y', '', '', '', '', '', '', '', '', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
    $resOk = (Test-Path $resHtml) -and -not (Test-Path $resState)
    & $writeState ([ordered]@{ version = 1; flow = 'remediate'; stage = 'applying'; savedUtc = '2026-10-15 10:00 UTC'; answers = [ordered]@{ run = 'C:\x\output\remediation\20261015_100000' } })
    $resRem = (@('q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String
}
finally { $env:HOSTBADGER_NO_RESUME = '1'; Pop-Location }
Assert-True ($resOut -match 'Unfinished run, saved 2026-10-15 10:00 UTC: Analyze snapshots' -and $resOut -match 'Report HTML path -> .*\(resumed\)' -and $resOut -match 'Hosts analyzed: 5' -and $resOk) 'launcher: an interrupted analysis resumes with its saved answers, finishes, and forgets the saved state'
Assert-True ($resRem -match 'stopped while applying fixes' -and $resRem -match 'option 7 puts them back' -and -not (Test-Path $resState)) 'launcher: an interrupted remediation is explained (restore offered), never resumed'
Assert-True ($rem7 -match 'No remediation backup found' -and ($rem6 -match 'start an elevated PowerShell' -or $rem6 -match 'Nothing changes until you type YES') -and -not (Test-Path (Join-Path $scanDir 'output\remediation'))) 'launcher: remediation needs an administrator and a yes, and restore says when there is nothing to restore'
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
Assert-Equal @($dc.Findings | Where-Object { $_.Type -match 'password_policy|account_lockout|deny_logon' }).Count 0 'domain controller: no local password policy, deny rights judged on the DC list'
# User rights on servers: the DC and member server lists of the CIS Server benchmarks, not the
# workstation one. The DC scenario keeps the Windows default for adding workstations to the domain.
$ur = @($dc.Findings | Where-Object { $_.Type -eq 'user_rights_excessive' })
Assert-Equal (($ur | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Cis)|$($_.CisBenchmark)" }) -join ';') 'right: SeMachineAccountPrivilege|Medium|2.2.5 (L1)|CIS Microsoft Windows Server 2019 Benchmark v4.0.0' 'DC: only Administrators may add workstations (server-only rule, quoted with its Server number)'
Assert-True ($ur[0].Detail -match 'Authenticated Users \(CIS Server 2019 2\.2\.5 expects Administrators\)') 'DC: the detail names who holds the right and the server rule'
$dcWs = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_dc.json'); $dcWs.host.os.caption = 'Microsoft Windows Server 2022 Standard'; $dcWs.host.os.build = 20348
$dcWs.securityPolicy.privilegeRights.SeRemoteInteractiveLogonRight = @('S-1-5-32-544', 'S-1-5-32-555'); $dcWs.securityPolicy.privilegeRights.SeDenyNetworkLogonRight = @()
$r = @((Invoke-HostChecks -Snapshot $dcWs -Config $config).Findings)
Assert-Equal (@($r | Where-Object { $_.Object -eq 'right: SeRemoteInteractiveLogonRight' }) | ForEach-Object { "$($_.Cis)|$($_.Detail -match 'Remote Desktop Users \(CIS Server 2022 2\.2\.9 expects Administrators\)')" }) '2.2.9 (L1)|True' 'DC: Remote Desktop Users on RDP logon is extra (DC variant 2.2.9)'
Assert-Equal (@($r | Where-Object { $_.Type -eq 'deny_logon_rights_missing' -and $_.Object -eq 'right: SeDenyNetworkLogonRight' }).Detail) 'Missing: Guests (CIS Server 2022 2.2.21).' 'DC: deny network logon needs Guests only (2.2.21)'
$ms = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json'); $ms.securityPolicy.privilegeRights.SeInteractiveLogonRight = @('S-1-5-32-544', 'S-1-5-32-545'); $ms.securityPolicy.privilegeRights | Add-Member -NotePropertyName SeMachineAccountPrivilege -NotePropertyValue @('S-1-5-11') -Force
$r = @((Invoke-HostChecks -Snapshot $ms -Config $config).Findings | Where-Object { $_.Type -eq 'user_rights_excessive' })
Assert-Equal (($r | ForEach-Object { "$($_.Object)|$($_.Cis)" }) -join ';') 'right: SeInteractiveLogonRight|2.2.8 (L1)' 'member server: Users on local logon is extra (MS variant 2.2.8); the DC-only right is not judged'

# Server-only CIS rules. The DC scenario runs Windows Server 2019; a Server 2016 DC is built below.
$nlw = @($dc.Findings | Where-Object { $_.Type -eq 'dc_netlogon_policy_weak' } | Sort-Object Object)
Assert-Equal (($nlw | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Cis)" }) -join ';') 'Netlogon: RefusePasswordChange|Medium|2.3.5.5 (L1);Netlogon: VulnerableChannelAllowList|High|2.3.5.2 (L1);Server Operators: schedule tasks|Medium|2.3.5.1 (L1)' 'DC: Zerologon exceptions High, password change refusal and Server Operators tasks Medium'
Assert-True (@($nlw | Where-Object { $_.Detail -match 'CIS Server 2019 2\.3\.5\.2 expects it not configured' -and $_.CisBenchmark -match 'Server 2019' }).Count -eq 1) 'DC on Server 2019: a server-only rule quotes the Server 2019 benchmark'
$dc16 = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_dc.json'); $dc16.host.os.caption = 'Microsoft Windows Server 2016 Standard'; $dc16.host.os.build = 14393
$dc16Res = @((Invoke-HostChecks -Snapshot $dc16 -Config $config).Findings)
Assert-True (@($dc16Res | Where-Object { $_.Type -eq 'dc_netlogon_policy_weak' -and $_.Detail -match 'CIS Server 2016 2\.3\.5\.2' -and $_.CisBenchmark -match 'Server 2016 Benchmark v3\.0\.0' }).Count -eq 1 -and @($dc16Res | Where-Object { $_.Type -in 'stig_server2019', 'stig_server2022', 'stig_server2025' }).Count -eq 0) 'DC on Server 2016: its own CIS benchmark, and no Server 2019/2022/2025 STIG'
$ms16 = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json'); $ms16.host.os.caption = 'Microsoft Windows Server 2016 Standard'; $ms16.host.os.build = 14393; $ms16.laps.windowsLapsPasswordExpirationProtection = 0
Assert-Equal (@((Invoke-HostChecks -Snapshot $ms16 -Config $config).Findings | Where-Object { $_.Object -like 'Windows LAPS*' }) | ForEach-Object { "$($_.CisBenchmark)|$($_.Detail -match 'CIS Server 2022 18\.9\.25\.2')" }) 'CIS Microsoft Windows Server 2022 Benchmark v4.0.0|True' 'Server 2016: the Windows LAPS rule its benchmark lacks is quoted from Server 2022'
Assert-Equal (@($dc.Findings | Where-Object { $_.Type -eq 'server_baseline_gaps' }) | ForEach-Object { "$($_.Object)|$($_.Cis)" }) 'Shutdown without logon|2.3.13.1 (L1)' 'DC: shutdown from the logon screen (2.3.13.1)'
Assert-Equal (@($dc.Findings | Where-Object { $_.Type -eq 'ldap_server_signing_off' } | ForEach-Object { $_.Cis } | Sort-Object) -join ',') '2.3.5.3 (L1),2.3.5.4 (L1)' 'DC: LDAP channel binding and signing quote their server rules'
$ms = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$ms.hardening.serverLogon.forceUnlockLogon = 0; $ms.laps.windowsLapsPasswordExpirationProtection = 0
$r = @((Invoke-HostChecks -Snapshot $ms -Config $config).Findings | Where-Object { $_.Type -eq 'server_baseline_gaps' } | Sort-Object Object)
Assert-Equal (($r | ForEach-Object { "$($_.Object)|$($_.Cis)" }) -join ';') 'Unlock without domain controller|2.3.7.8 (L1);Windows LAPS: password expiration protection|18.9.25.2 (L1)' 'member server: unlock with cached credentials and LAPS expiry protection off'
$ms.laps.windowsLapsBackupDirectory = 1
Assert-Equal @((Invoke-HostChecks -Snapshot $ms -Config $config).Findings | Where-Object { $_.Object -like 'Windows LAPS*' }).Count 0 'LAPS backing up to Entra ID: expiry protection does not apply'
Assert-Equal @($hard.Findings | Where-Object { $_.Type -match 'server_baseline_gaps|dc_netlogon' }).Count 0 'hardened member server: no server-only finding'
Assert-Equal @($part.NotEvaluated | Where-Object { $_.Type -in 'password_policy_weak', 'account_lockout_weak', 'user_rights_excessive', 'deny_logon_rights_missing' }).Count 4 'partial: policy checks not evaluated when the export failed'
# A service folder that users can write: Medium and "DLL planting"; High once non-admin users can start the service.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'service_binary_writable' -and $_.Object -eq 'service: PrintHelper' -and $_.Severity -eq 'Medium' -and $_.Detail -match 'program itself is not writable' -and $_.Detail -match 'DLL planting' }).Count -eq 1) 'service folder writable: Medium, and the finding says the program itself is not writable (DLL planting)'
$startSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json')
foreach ($sv in @($startSnap.services | Where-Object { $_.name -eq 'PrintHelper' })) { Add-Member -InputObject $sv -NotePropertyName startableBy -NotePropertyValue @('S-1-1-0') -Force }
$startRes = Invoke-HostChecks -Snapshot $startSnap -Config $config
Assert-True (@($startRes.Findings | Where-Object { $_.Type -eq 'service_binary_writable' -and $_.Object -eq 'service: PrintHelper' -and $_.Severity -eq 'High' -and $_.Detail -match 'Everyone can start the service' }).Count -eq 1) 'service folder writable and startable by Everyone: High'
foreach ($sv in @($startSnap.services | Where-Object { $_.name -eq 'PrintHelper' })) { $sv.executable = 'C:\ProgramData\Contoso\svc.exe' }
Assert-True (@((Invoke-HostChecks -Snapshot $startSnap -Config $config).Findings | Where-Object { $_.Type -eq 'service_binary_writable' -and $_.Object -eq 'service: PrintHelper' -and $_.Detail -match 'lets users create files by default' }).Count -eq 1) 'service under ProgramData: the finding explains the inherited default permission'
# A folder above a service program that a non-administrator controls.
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'service_path_ancestor_control' -and $_.Object -eq 'service: ContosoUpdater' -and $_.Severity -eq 'Medium' -and $_.Detail -match 'has FullControl on the folder 1 level\(s\) above' -and $_.Detail -match 'owns the folder 2 level\(s\) above' -and $_.Detail -notmatch '[a-z]:\\' }).Count -eq 1) 'ancestor control: a standard account with control of parent folders is Medium, named by level, and the text has no drive path'
$ancSnap = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json')
foreach ($sv in @($ancSnap.services | Where-Object { $_.name -eq 'ContosoUpdater' })) { $sv.ancestorControl = @([PSCustomObject]@{ level = 1; kind = 'acl'; sid = 'S-1-5-32-545'; rights = 'FullControl' }) }
Assert-True (@((Invoke-HostChecks -Snapshot $ancSnap -Config $config).Findings | Where-Object { $_.Type -eq 'service_path_ancestor_control' -and $_.Object -eq 'service: ContosoUpdater' -and $_.Severity -eq 'High' }).Count -eq 1) 'ancestor control: control given to all users on a LocalSystem service is High'
foreach ($sv in @($ancSnap.services | Where-Object { $_.name -eq 'ContosoUpdater' })) { $sv.ancestorControl = @([PSCustomObject]@{ level = 1; kind = 'acl'; sid = ($ancSnap.localAccounts.administrators | Where-Object { $_.class -eq 'User' } | Select-Object -First 1).sid; rights = 'FullControl' }) }
Assert-Equal @((Invoke-HostChecks -Snapshot $ancSnap -Config $config).Findings | Where-Object { $_.Type -eq 'service_path_ancestor_control' }).Count 0 'ancestor control: a member of the local Administrators group is not reported'
# The AI leak check must accept the text of a service finding under ProgramData (no drive path in the prose).
$pdRes = Invoke-HostChecks -Snapshot $startSnap -Config $config
$pdFindings = @($pdRes.Findings | Where-Object { $_.Category -ne 'DISA STIG' })
$pdPz = New-HostPseudonymizer -Snapshots @($startSnap) -Findings $pdFindings -HostOrder @(Get-SnapshotHostName $startSnap)
$pdPrompt = New-AiPrompt -Findings $pdFindings -Hosts @([PSCustomObject]@{ Name = (Get-SnapshotHostName $startSnap); Role = 'workstation'; Score = [PSCustomObject]@{ Score = 10; Grade = 'F'; Penalty = 100; ChecksTriggered = 1 }; NotEvaluated = @($pdRes.NotEvaluated); Edr = @(); EdrKnown = $true; CollectedUtc = (ConvertTo-UtcDate $startSnap.meta.collectedAtUtc); Os = 'x'; AsSystem = $true; AsAdmin = $true; Synthetic = $true; Findings = $pdFindings }) -Pz $pdPz -Comparison $null
Assert-True (@(Test-AiLeak -Pz $pdPz -Text $pdPrompt).Count -eq 0 -and $pdPrompt -match 'lets users create files by default') 'AI: a service finding under ProgramData passes the leak check'
$sdKey = New-Object System.Security.AccessControl.RawSecurityDescriptor 'D:(A;;CCRPWPSDRC;;;WD)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)'
Assert-True (@($sdKey.DiscretionaryAcl | Where-Object { $_.AccessMask -band 0x10 } | ForEach-Object { $_.SecurityIdentifier.Value }) -contains 'S-1-1-0') 'service security descriptor: the start right is bit 0x10'
# ------------------------------------------------------------------ DISA STIG registry rules
Assert-True (@(Get-StigCatalog).Count -ge 450) 'STIG catalog loads (450+ registry rules)'
$stigE = @{ x = @{ op = 'eq'; v = '1' }; t = 'D' }; $stigI = @{ x = @{ op = 'in'; v = @('2', '3'); absentOk = $true }; t = 'D' }
$stigR = @{ x = @{ op = 'range'; min = 16384; max = $null; absentOk = $false }; t = 'D' }; $stigA = @{ x = @{ op = 'absent' }; t = 'N' }
Assert-True ($null -eq (Test-StigValue $stigE $true 1) -and (Test-StigValue $stigE $true 0) -match 'expected 1' -and (Test-StigValue $stigE $false $null) -eq 'not configured') 'STIG value: exact value, wrong value, not configured'
Assert-True ($null -eq (Test-StigValue $stigI $false $null) -and $null -eq (Test-StigValue $stigI $true 3) -and (Test-StigValue $stigI $true 1) -match 'expected 2 or 3') 'STIG value: list of values, absent allowed when the rule says so'
Assert-True ($null -eq (Test-StigValue $stigR $true 32768) -and (Test-StigValue $stigR $true 4096) -match 'expected 16384 or more' -and (Test-StigValue $stigR $false $null) -eq 'not configured') 'STIG value: minimum'
Assert-True ($null -eq (Test-StigValue $stigA $false $null) -and (Test-StigValue $stigA $true 5) -match 'not set') 'STIG value: must be absent'
Assert-Equal (@($hard.Findings | Where-Object { $_.Type -like 'stig_*' }) | ForEach-Object { "$($_.Type)|$($_.Object -match '^WN22-MS V-')|$($_.Detail -match 'not configured')" }) 'stig_server2022|True|True' 'STIG: the compliant host has only the rule left unconfigured, its other Server 2022 member server rules pass'
Assert-True (@($dc.Findings | Where-Object { $_.Type -eq 'stig_server2019' -and $_.Object -match '^WN19-DC V-' }).Count -eq 2 -and @($dc.Findings | Where-Object { $_.Type -eq 'stig_server2022' -or $_.Object -match '^WN19-MS' }).Count -eq 0) 'STIG: a Server 2019 domain controller gets the 2019 DC rules only'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'stig_windows11' }).Count -eq 0 -and @($weak.Findings | Where-Object { $_.Type -eq 'stig_windows10' -and $_.Object -like 'WN10 V-*' }).Count -eq 3 -and @($lap.Findings | Where-Object { $_.Type -eq 'stig_windows10' }).Count -eq 0) 'STIG: Windows 10 is judged against its own STIG and not the Windows 11 one, and the other way round'
Assert-Equal ((@('stig_defender', 'stig_firewall', 'stig_edge', 'stig_chrome', 'stig_firefox', 'stig_office') | ForEach-Object { $ty = $_; @($weak.Findings | Where-Object { $_.Type -eq $ty }).Count }) -join '/') '3/3/3/3/3/3' 'STIG: three unconfigured rules per product on the weak host'
Assert-True (@($lap.Findings | Where-Object { $_.Type -eq 'stig_chrome' -or $_.Type -eq 'stig_office' }).Count -eq 0) 'STIG: a browser or Office that is not installed is not judged'
Assert-True (@($lap.Findings | Where-Object { $_.Type -eq 'stig_windows11' -and $_.Detail -match 'set to Allow, expected Deny' }).Count -eq 1) 'STIG: a wrong value says what it is and what is expected'
Assert-True (@($lap.Findings | Where-Object { $_.Type -eq 'stig_windows11' -and $_.Detail -match 'not configured' }).Count -eq 2) 'STIG: a value that is not configured is a finding'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'stig_office' -and $_.Detail -match 'user policy; 1 of 1 loaded user' }).Count -eq 3) 'STIG: a per-user policy is judged on the loaded user profiles'
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'stig_defender' -and $_.Reason -match 'Passive Mode' }).Count -eq 1) 'STIG: Defender in passive mode: its rules are not evaluated'
$noStig = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$noStig.PSObject.Properties.Remove('stig'); $noStig.meta.sectionsCollected = @($noStig.meta.sectionsCollected | Where-Object { $_ -ne 'stig' })
$noStigRes = Invoke-HostChecks -Snapshot $noStig -Config $config
Assert-True (@($noStigRes.NotEvaluated | Where-Object { $_.Type -like 'stig_*' -and $_.Reason -match "section 'stig' not in the snapshot" }).Count -eq 11 -and @($noStigRes.Findings | Where-Object { $_.Type -like 'stig_*' }).Count -eq 0) 'STIG: a snapshot without the stig section lists the rules as not evaluated, never as clean'
$skipOut = Join-Path $work 'skipstig'; New-Item -ItemType Directory -Path $skipOut -Force | Out-Null
$skipRun = & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $skipOut 'r.html') -SkipStig *>&1 | Out-String
Assert-True (@(Import-Csv (Join-Path $skipOut 'r.csv') | Where-Object { $_.Type -like 'stig_*' }).Count -eq 0 -and @(Import-Csv (Join-Path $skipOut 'r.csv')).Count -eq 209) 'STIG: -SkipStig leaves the STIG findings out and nothing else'
# The progress cursor draws only on an interactive console, moves its frame, and clears its line.
$script:SpinEnabled = $null; $script:SpinWidth = 0; Step-Spinner 'x' 6>&1 | Out-Null
Assert-True ($script:SpinEnabled -eq $false -or [Console]::IsOutputRedirected -eq $false) 'spinner: off when output is redirected'
$script:SpinEnabled = $true; $script:SpinWidth = 0; $script:SpinLast = 0; $spA = (Step-Spinner 'Reading' 6>&1 | Out-String); Start-Sleep -Milliseconds 120; $spB = (Step-Spinner 'Reading' 6>&1 | Out-String); $spC = (Stop-Spinner 6>&1 | Out-String)
Assert-True ($spA -match 'Reading \|' -and $spB -match 'Reading /' -and $spC -match ' {5,}' -and $script:SpinWidth -eq 0) 'spinner: frames advance and the line is cleared'
$script:SpinEnabled = $null; $script:SpinWidth = 0
# Compliance charts on top, and the options to hide CIS / STIG from the report or keep STIG away from Gemini.
$cmp = Get-ComplianceStats -Hosts @(foreach ($sn in 'weak', 'hardened', 'laptop', 'dc', 'partial') { $rr = Invoke-One (Join-Path $fleet "hostsnapshot_$sn.json"); $sx = Import-HostSnapshot (Join-Path $fleet "hostsnapshot_$sn.json"); [PSCustomObject]@{ Name = (Get-SnapshotHostName $sx); Role = Get-SnapshotRole $sx; NotEvaluated = @($rr.NotEvaluated); StigEvaluated = $rr.StigEvaluated } }) -Findings $all
Assert-True ($cmp.StigEvaluated -gt 1500 -and $cmp.StigFailed -eq 27 -and $cmp.CisApplicable -gt 100 -and $cmp.CisFailed -gt 20 -and $cmp.CisFailed -lt $cmp.CisApplicable) 'compliance: STIG rules judged and failed, CIS-based checks applicable and failed'
$hideOut = Join-Path $work 'hide'; New-Item -ItemType Directory -Path $hideOut -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $hideOut 'show.html') *>&1 | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $hideOut 'hide.html') -HideCis -HideStig *>&1 | Out-Null
$showHtml = [System.IO.File]::ReadAllText((Join-Path $hideOut 'show.html')); $hideHtml = [System.IO.File]::ReadAllText((Join-Path $hideOut 'hide.html'))
Assert-True ($showHtml -match 'DISA STIG compliance: \d+% of \d+ rules' -and $showHtml -match 'CIS-based compliance: \d+% of \d+ checks' -and $showHtml -match 'WN11 V-253260') 'report: compliance charts on top, STIG findings listed'
Assert-True ($showHtml.IndexOf('Score per host') -lt $showHtml.IndexOf('DISA STIG compliance') -and $showHtml.IndexOf('DISA STIG compliance') -lt $showHtml.IndexOf('Findings by severity')) 'report: the compliance charts sit under the score'
Assert-True ($showHtml -match 'Summary by framework' -and $showHtml -match 'E8: Restrict administrative privileges' -and $showHtml -match "<details class='dash-more'><summary>Restrict administrative privileges <span class='meta'>\(\d+ not clean\)" -and $showHtml -match 'Checks not clean \(\d+\)' -and $showHtml -match '<b>ACSC Essential Eight\.</b>') 'report: CIS, STIG and Essential Eight have a summary row each, and the dashboard lists the checks that are not clean'
Assert-True ([regex]::Match($showHtml, '(?s)Summary by category</h2>.*?</table>').Value -notmatch '<td>DISA STIG</td>' -and [regex]::Match($showHtml, '(?s)Summary by framework</h2>.*?</table>').Value -match '<td>DISA STIG') 'report: DISA STIG is in the summary by framework, not in the summary by category'
Assert-True ((Get-DashboardHtml -Hosts @([PSCustomObject]@{ Name = 'h'; Role = 'workstation'; Score = [PSCustomObject]@{ Score = 48; Grade = 'D' }; StigByType = @{}; NotEvaluated = @(); OptionalOff = @(); StigEvaluated = 0 }) -All @() -Shown @() -Title 't') -match 'Partial protection') 'dashboard: the verdict follows the grades (48, grade D, is partial protection)'
Assert-True ($hideHtml -match 'DISA STIG compliance' -and $hideHtml -match 'Hidden from this report: \d+ CIS-based and 27 DISA STIG' -and $hideHtml -notmatch 'WN11 V-253260' -and $hideHtml -notmatch 'CIS 18\.10\.7\.3' -and $hideHtml.Length -lt $showHtml.Length) 'report: -HideCis -HideStig leave the findings out and keep the charts'
Assert-Equal @(Import-Csv (Join-Path $hideOut 'hide.csv')).Count 236 'report: hidden findings stay in the CSV'
$aiNo = Join-Path $hideOut 'ai_no.txt'; $aiYes = Join-Path $hideOut 'ai_yes.txt'
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $hideOut 'a.html') -AiDryRun $aiNo *>&1 | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $hideOut 'b.html') -AiDryRun $aiYes -AiIncludeStig *>&1 | Out-Null
$aiNoTxt = [System.IO.File]::ReadAllText($aiNo); $aiYesTxt = [System.IO.File]::ReadAllText($aiYes)
Assert-True ($aiNoTxt -notmatch '## \[\w+\] stig_' -and $aiYesTxt -match '## \[\w+\] stig_windows11' -and $aiYesTxt.Length -gt $aiNoTxt.Length) 'AI: STIG findings stay out of the prompt unless -AiIncludeStig'
# ConvertTo-ReadableFileRights (collector): a FileSystemRights value whose bits don't match any named
# enum member (seen on real installer-written inherit-only ACEs using raw GENERIC_* bits) must not come
# out as a bare, unreadable number in the snapshot. [Type]$value throws for such values even though
# FileSystemRights is a [Flags] enum; this specifically guards against reintroducing that cast.
$rfrSrc = [System.IO.File]::ReadAllText((Join-Path $root 'Collect-HostSnapshot.ps1'))
$rfrFn = [regex]::Match($rfrSrc, '(?s)function ConvertTo-ReadableFileRights \{.*?\r?\n\}\r?\n').Value
Assert-True ([bool]$rfrFn) 'ConvertTo-ReadableFileRights is defined in the collector'
. ([scriptblock]::Create($rfrFn))
Assert-Equal (ConvertTo-ReadableFileRights -536805376) 'GenericRead, GenericWrite, GenericExecute, Delete' 'readable rights: a real-world raw GENERIC_* mask (seen on an Authenticated Users inherit-only ACE) is decomposed into names'
Assert-Equal (ConvertTo-ReadableFileRights ([int64][System.Security.AccessControl.FileSystemRights]::Modify)) 'Modify' 'readable rights: a normally-named value is unchanged'
Assert-Equal (ConvertTo-ReadableFileRights 0x10000000) 'GenericAll' 'readable rights: GENERIC_ALL alone is named, not left as a raw number'
# The collector reads exactly the values the catalog judges.
$collSrc = [System.IO.File]::ReadAllText((Join-Path $root 'Collect-HostSnapshot.ps1'))
$collList = @([regex]::Matches($collSrc, "(?m)^    '([MU])\|([^|]*)\|([^']*)'") | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)|$($_.Groups[3].Value -replace "''", "'")".ToLower() })
$catList = @(Get-StigCatalog | ForEach-Object { "$($_.h)|$($_.k)|$($_.n)".ToLower() } | Select-Object -Unique)
Assert-Equal (@($catList | Where-Object { $collList -notcontains $_ }).Count) 0 'STIG: the collector reads every value the catalog judges'
# ------------------------------------------------------------------ pending updates and software against the CISA KEV catalog
$kevSample = Join-Path $work 'kev_sample.json'
[System.IO.File]::WriteAllText($kevSample, (@{
            title = 'CISA Catalog of Known Exploited Vulnerabilities'; catalogVersion = '2026.10.01'
            vulnerabilities = @(
                @{ cveID = 'CVE-2026-1001'; vendorProject = 'Contoso'; product = 'CAD Viewer'; vulnerabilityName = 'Contoso CAD Viewer file parsing flaw'; dateAdded = '2026-03-02'; knownRansomwareCampaignUse = 'Unknown' },
                @{ cveID = 'CVE-2026-2002'; vendorProject = 'Contoso'; product = 'CAD Viewer'; vulnerabilityName = 'Contoso CAD Viewer RCE'; dateAdded = '2026-08-20'; knownRansomwareCampaignUse = 'Known' },
                @{ cveID = 'CVE-2026-3003'; vendorProject = 'Mozilla'; product = 'Firefox'; vulnerabilityName = 'Firefox use after free'; dateAdded = '2026-05-11'; knownRansomwareCampaignUse = 'Unknown' },
                @{ cveID = 'CVE-2026-4004'; vendorProject = 'Microsoft'; product = 'Windows SMB'; vulnerabilityName = 'SMB flaw'; dateAdded = '2026-06-01'; knownRansomwareCampaignUse = 'Known' },
                @{ cveID = 'CVE-2026-5005'; vendorProject = 'Fabrikam'; product = 'Reporting Suite'; vulnerabilityName = 'Not installed anywhere'; dateAdded = '2026-07-01'; knownRansomwareCampaignUse = 'Unknown' })
        } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
$kevParsed = @(ConvertFrom-KevCatalog ([System.IO.File]::ReadAllText($kevSample)))
Assert-True ($kevParsed.Count -eq 5 -and @($kevParsed | Where-Object { $_.Ransomware }).Count -eq 2) 'KEV: the catalog is parsed (cve, vendor, product, date, ransomware use)'
$cfgKev = $config.Clone(); $cfgKev['Kev'] = $kevParsed
$weakKev = Invoke-One (Join-Path $fleet 'hostsnapshot_weak.json') $cfgKev
$hardKev = Invoke-One (Join-Path $fleet 'hostsnapshot_hardened.json') $cfgKev
Assert-True (Has $weakKev 'kev_software_match' 'software: Contoso CAD Viewer' 'Medium') 'KEV: installed software matching a product with ransomware use is Medium'
Assert-True (Has $weakKev 'kev_software_match' 'software: Mozilla Firefox' 'Low') 'KEV: a plain match is Low'
Assert-Equal @($weakKev.Findings | Where-Object { $_.Type -eq 'kev_software_match' }).Count 2 'KEV: Windows components and products that are not installed do not match'
Assert-True (@($weakKev.Findings | Where-Object { $_.Type -eq 'kev_software_match' -and $_.Detail -match '^Installed as Contoso CAD Viewer \(version 5\.1\.0\)\. CISA KEV lists 2 exploited vulnerabilities' -and $_.Detail -match 'CVE-2026-2002' -and $_.Detail -match 'no version ranges' }).Count -eq 1) 'KEV: the finding names the installed program, the CVEs and says the version is not checked'
Assert-Equal @($hardKev.Findings | Where-Object { $_.Type -eq 'kev_software_match' }).Count 0 'KEV: software without a match gives no finding'
Assert-Equal @($weak.Findings | Where-Object { $_.Type -eq 'kev_software_match' }).Count 0 'KEV: without a catalog the check is off, not "not evaluated"'
Assert-Equal @($weak.NotEvaluated | Where-Object { $_.Type -in 'kev_software_match', 'updates_pending' }).Count 0 'KEV and pending updates: opt-in checks that nobody asked for are not listed as not evaluated'
# Software out of support (lifecycle table in lib\Checks.ps1)
Assert-True ((Has $weak 'software_eol' 'software: Adobe Flash Player' 'High') -and (Has $weak 'software_eol' 'software: Python 2' 'Medium') -and (Has $weak 'software_eol' 'software: Node.js 16' 'Medium') -and (Has $weak 'software_eol' 'software: Microsoft Visual C++ 2010 Redistributable' 'Low')) 'software EOL: Flash High, Python 2 and Node.js 16 Medium, Visual C++ 2010 Low'
Assert-Equal @($weak.Findings | Where-Object { $_.Type -eq 'software_eol' }).Count 4 'software EOL: supported programs (Firefox, Visual C++ 2022, Notepad++) give no finding'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'software_eol' -and $_.Detail -match '^Installed as Python 2\.7\.18 \(64-bit\) \(version 2\.7\.18150\)\. Support for Python 2 ended 2020-01-01, \d+ days before collection\.$' -and $_.Found -eq 'Python 2, end of life 2020-01-01' -and $_.Expected -eq 'a supported release' }).Count -eq 1) 'software EOL: detail, found and expected'
Assert-Equal @($hard.Findings | Where-Object { $_.Type -eq 'software_eol' }).Count 0 'software EOL: hardened host clean'
$eolCase = { param($n, $v) $r = Get-SoftwareLifecycle ([PSCustomObject]@{ name = $n; version = $v }); if ($r) { $r.Product } else { '-' } }
Assert-Equal ((@(
            @('Microsoft .NET Runtime - 6.0.36 (x64)', '48.144.23186'), @('Microsoft ASP.NET Core 3.1.32 - Shared Framework (x64)', '3.1.32.0'), @('Microsoft Windows Desktop Runtime - 8.0.11 (x64)', '64.44.29411'),
            @('Microsoft .NET Framework 4.8.1 Targeting Pack', '4.8.09032'), @('Node.js', '22.11.0'), @('Node.js', '8.17.0'), @('Java 8 Update 431 (64-bit)', '8.0.4310.11'), @('Java 7 Update 80', '7.0.800'),
            @('Microsoft Office Professional Plus 2016', '16.0.4266.1001'), @('Microsoft 365 Apps for enterprise - en-us', '16.0.18129.20158'), @('Microsoft Visual Studio 2010 Tools for Office Runtime (x64)', '10.0.60917'),
            @('Microsoft SQL Server 2014 (64-bit)', ''), @('Microsoft SQL Server 2014 Management Objects', '12.0.2000.8'), @('Adobe Reader XI (11.0.23)', '11.0.23'), @('Adobe Acrobat Reader DC', '24.004.20220'), @('Python 3.12.7 (64-bit)', '3.12.7150.0')
        ) | ForEach-Object { & $eolCase $_[0] $_[1] }) -join '|') 'Microsoft .NET 6|Microsoft .NET Core 3.1|-|-|-|Node.js 9 and older|-|Java 7|Microsoft Office 2016|-|-|Microsoft SQL Server 2014|-|Adobe Reader/Acrobat XI and older|-|-' 'software EOL: names and versions matched to the right release, supported and unrelated programs left alone'
$eolSoon = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json'); $eolSoon.software = @([ordered]@{ name = 'Microsoft .NET Runtime - 8.0.11 (x64)'; version = '8.0.11'; publisher = 'Microsoft Corporation' }, [ordered]@{ name = 'Microsoft SQL Server 2016 (64-bit)'; version = ''; publisher = 'Microsoft Corporation' })
$eolSoon.meta.collectedAtUtc = '2026-07-14T08:00:00Z'
Assert-Equal @((Invoke-HostChecks -Snapshot $eolSoon -Config $config).Findings | Where-Object { $_.Type -eq 'software_eol' }).Count 0 'software EOL: judged at collection time (SQL Server 2016 on its last day of support is not yet a finding)'
# endoflife.date data (API v1 shape, -EolFile / -EolOnline): current dates for software_eol, and
# software_outdated for a program behind the latest release of its line. Collected 2026-10-01.
$eolSample = Join-Path $work 'eol_sample.json'
$eolRel = { param($n, $isEol, $eol, $latest, $date, $eoes) [ordered]@{ name = $n; isEol = $isEol; eolFrom = $eol; eoesFrom = $eoes; latest = $(if ($latest) { [ordered]@{ name = $latest; date = $date } } else { $null }) } }
# SQL Server: one line per service pack, with its label and the latest GDR build.
$sqlRel = { param($n, $label, $isEol, $eol, $latest, $date, $eoes, $gdr) $r = & $eolRel $n $isEol $eol $latest $date $eoes; $r['label'] = $label; $r['custom'] = [ordered]@{ latestGdr = $gdr }; $r }
[System.IO.File]::WriteAllText($eolSample, ([ordered]@{ schema_version = '1.2.1'; total = 9; result = @(
                [ordered]@{ name = 'mssqlserver'; releases = @((& $sqlRel '16.0' "2022 'Dallas'" $false '2033-01-11' '16.0.4295.3 CU27' '2026-09-15' $null '16.0.1200.5'), (& $sqlRel '15.0' "2019 'Aris/Seattle'" $false '2030-01-08' '15.0.4490.9 CU32+GDR' '2026-04-08' $null '15.0.2190.7'),
                        (& $sqlRel '13.0-sp3-acp' '2016 SP3 Azure Connect Pack' $true '2026-07-14' '13.0.7095.1 Azure Connect pack+GDR' '2026-07-14' '2029-07-17' '13.0.7095.1'), (& $sqlRel '13.0-sp3' '2016 SP3' $true '2026-07-14' '13.0.6500.1 GDR' '2026-07-14' '2029-07-17' '13.0.6500.1'),
                        (& $sqlRel '13.0-sp2' '2016 SP2' $true '2022-10-11' '13.0.5893.48 CU17+GDR' '2022-06-14' $null '13.0.5108.50'), (& $sqlRel '12.0-sp3' "2014 'Hekaton' SP3" $true '2024-07-09' '12.0.6449.1 CU4+GDR' '2023-10-10' '2027-07-12' '12.0.6179.1'),
                        (& $sqlRel '10.50-sp3' "2008 R2 'Kilimanjaro' SP3" $true '2019-07-09' '10.50.6785.2 GDR' '2023-02-14' '2022-07-12' '10.50.6785.2')) },
                [ordered]@{ name = 'python'; releases = @((& $eolRel '3.12' $false '2028-10-31' '3.12.9' '2026-06-01'), (& $eolRel '2.7' $true '2020-01-01' '2.7.18' '2020-04-19')) },
                [ordered]@{ name = 'nodejs'; releases = @((& $eolRel '22' $false '2027-04-30' '22.9.0' '2026-09-21'), (& $eolRel '16' $true '2023-09-11' '16.20.2' '2023-08-08')) },
                [ordered]@{ name = 'firefox'; releases = @((& $eolRel '157' $false '2026-10-13' '157.0' '2026-09-15'), (& $eolRel '118' $true '2023-10-24' '118.0.2' '2023-10-10')) },
                [ordered]@{ name = 'oracle-jdk'; releases = @((& $eolRel '8' $true '2022-03-31' '8u503' '2026-07-21' '2030-12-31')) },
                [ordered]@{ name = 'powershell'; releases = @((& $eolRel '7.4' $false '2026-11-10' '7.4.20' '2026-10-06')) },
                [ordered]@{ name = 'notepad-plus-plus'; releases = @((& $eolRel '8.9' $false $null '8.9.8.1' '2026-09-24')) },
                [ordered]@{ name = 'eclipse-temurin'; releases = @((& $eolRel '25' $false '2031-09-30' '25.0.4.1+1' '2026-08-19')) },
                [ordered]@{ name = 'adonisjs'; releases = @((& $eolRel '7' $false $null '7.0.0' '2026-01-01')) })
        } | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
$eolCat = ConvertFrom-EolCatalog ([System.IO.File]::ReadAllText($eolSample))
Assert-True ($eolCat.Count -eq 8 -and -not $eolCat.ContainsKey('adonisjs') -and @($eolCat['oracle-jdk'])[0].EoesFrom -eq '2030-12-31' -and @($eolCat['python'] | Where-Object { $_.Name -eq '3.12' })[0].Latest -eq '3.12.9') 'endoflife.date: the products HostBadger maps are read, with end of support, extended support and latest release'
Assert-Equal (@((ConvertFrom-EolCatalog (ConvertTo-EolCatalogJson $eolCat 'test'))['oracle-jdk']) | ConvertTo-Json -Compress) (@($eolCat['oracle-jdk']) | ConvertTo-Json -Compress) 'endoflife.date: the copy kept next to the report reads back the same'
Assert-True ((Compare-SoftwareVersion '8 Update 431' '8u503') -lt 0 -and (Compare-SoftwareVersion '157.0' '157.0.1') -lt 0 -and (Compare-SoftwareVersion '3.12.9' '3.12.9') -eq 0 -and (Compare-SoftwareVersion '21.0.12' '21.0.5') -gt 0 -and (Compare-SoftwareVersion '25.0.4.1+1' '25.0.4.1+7') -eq 0) 'versions compared number by number, build metadata ignored'
Assert-Equal ((@(@('8.9.1', '8.9.8.1'), @('7.4.20', '7.4.21'), @('157.0', '157.0.1'), @('22.1.0', '23.0.0'), @('3.12.9', '3.12.9')) | ForEach-Object { Get-SoftwareVersionGap $_[0] $_[1] }) -join ',') '7,1,1,0,0' 'version gap: how far behind inside the release line'
$eolHost = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json'); $eolHost.meta.collectedAtUtc = '2026-10-01T08:00:00Z'
$eolHost.software = @(
    [ordered]@{ name = 'Python 3.12.1 (64-bit)'; version = '3.12.1150.0'; publisher = 'Python Software Foundation' },
    [ordered]@{ name = 'Python 2.7.18 (64-bit)'; version = '2.7.18150'; publisher = 'Python Software Foundation' },
    [ordered]@{ name = 'Node.js'; version = '22.8.0'; publisher = 'Node.js Foundation' },
    [ordered]@{ name = 'Mozilla Firefox (x64 en-US)'; version = '118.0'; publisher = 'Mozilla' },
    [ordered]@{ name = 'Java 8 Update 431 (64-bit)'; version = '8.0.4310.11'; publisher = 'Oracle Corporation' },
    [ordered]@{ name = 'PowerShell 7-x64'; version = '7.4.6.0'; publisher = 'Microsoft Corporation' },
    [ordered]@{ name = 'Adobe Flash Player 32 NPAPI'; version = '32.0.0.465'; publisher = 'Adobe' },
    [ordered]@{ name = 'Notepad++ (64-bit x64)'; version = '8.9.1'; publisher = 'Notepad++ Team' },
    [ordered]@{ name = 'Eclipse Temurin JDK with Hotspot 25.0.2+10 (x64)'; version = '25.0.2.10'; publisher = 'Eclipse Adoptium' })
$cfgEol = $config.Clone(); $cfgEol['Eol'] = $eolCat
$eolRes = @((Invoke-HostChecks -Snapshot $eolHost -Config $cfgEol).Findings | Where-Object { $_.Type -like 'software_*' })
Assert-Equal (($eolRes | Sort-Object Type, Object | ForEach-Object { "$($_.Type)|$($_.Object)|$($_.Severity)" }) -join ';') 'software_eol|software: Adobe Flash Player|High;software_eol|software: Java 8|Low;software_eol|software: Python 2|Medium;software_outdated|software: Eclipse Temurin|Low;software_outdated|software: Mozilla Firefox|Medium;software_outdated|software: Notepad++|Low;software_outdated|software: Python|Low' 'endoflife.date: what is judged and how (Node.js one release behind inside the grace period, PowerShell 7.4.20 released after collection)'
Assert-True (@($eolRes | Where-Object { $_.Object -eq 'software: Python' -and $_.Detail -match 'Python 3\.12 is still supported, but 3\.12\.9 came out 2026-06-01, 122 days before collection' -and $_.Found -eq '3.12.1' -and $_.Expected -eq '3.12.9 or later' }).Count -eq 1) 'software outdated: names the release line, the missing release and its date'
Assert-True (@($eolRes | Where-Object { $_.Object -eq 'software: Notepad++' -and $_.Detail -match 'several releases behind 8\.9\.8\.1 \(out 2026-09-24\)' }).Count -eq 1) 'software outdated: several releases behind a recent one is flagged inside the grace period'
Assert-True (@($eolRes | Where-Object { $_.Object -eq 'software: Java 8' -and $_.Detail -match 'Support for Java 8 ended 2022-03-31' -and $_.Detail -match 'Paid extended support runs until 2030-12-31' }).Count -eq 1) 'software EOL: paid extended support still running is Low and says until when'
Assert-True (@($eolRes | Where-Object { $_.Object -eq 'software: Mozilla Firefox' -and $_.Detail -match 'Release line 118 stopped receiving fixes 2023-10-24' }).Count -eq 1 -and @($eolRes | Where-Object { $_.Type -eq 'software_eol' -and $_.Object -match 'Firefox' }).Count -eq 0) 'software outdated: a rapid-release browser on an ended line is behind, not out of support'
Assert-True (@($eolRes | Where-Object { $_.Object -eq 'software: Python 2' -and $_.Detail -match '\(endoflife\.date\)' }).Count -eq 1 -and @($eolRes | Where-Object { $_.Object -eq 'software: Adobe Flash Player' -and $_.Detail -notmatch 'endoflife' }).Count -eq 1) 'software EOL: the downloaded data wins, the table keeps the Object and covers what the data lacks'
$cfgEol['SoftwareGraceDays'] = 5
Assert-True (@((Invoke-HostChecks -Snapshot $eolHost -Config $cfgEol).Findings | Where-Object { $_.Type -eq 'software_outdated' -and $_.Object -eq 'software: Node.js' }).Count -eq 1) 'software outdated: -SoftwareGraceDays sets how long a host may take to update'
Assert-Equal @($weak.NotEvaluated | Where-Object { $_.Type -eq 'software_outdated' }).Count 0 'software outdated: without endoflife.date data the check is off, not "not evaluated"'
# SQL Server instances (collector sqlServer section) against the endoflife.date service pack lines.
Assert-True ((@($eolCat['mssqlserver'] | Where-Object { $_.Name -eq '16.0' }))[0].LatestGdr -eq '16.0.1200.5' -and (@((ConvertFrom-EolCatalog (ConvertTo-EolCatalogJson $eolCat 'test'))['mssqlserver']) | ConvertTo-Json -Compress) -eq (@($eolCat['mssqlserver']) | ConvertTo-Json -Compress)) 'SQL Server: label and latest GDR read, and kept in the copy next to the report'
$sqlRels = @($eolCat['mssqlserver'])
Assert-Equal ((@('13.0.6300.2', '13.0.7050.2', '13.0.5026.0', '12.0.6024.0', '10.50.6000.34', '16.0.1135.2', '16.0.4135.4', '11.0.7001.0') | ForEach-Object { $r = Find-SqlRelease $_ $sqlRels; if ($r) { $r.Name } else { '-' } }) -join ',') '13.0-sp3,13.0-sp3-acp,13.0-sp2,12.0-sp3,10.50-sp3,16.0,16.0,-' 'SQL Server: a build finds its service pack line (SP3, its Azure Connect Pack, SP2, 2008 R2), an unknown version none'
Assert-Equal ((@([PSCustomObject]@{ fileVersion = '13.0.6300.2'; patchLevel = '13.2.5026.0' }, [PSCustomObject]@{ fileVersion = ''; patchLevel = '10.53.6000.34' }, [PSCustomObject]@{ fileVersion = '2015.0131.6300.02'; patchLevel = '13.3.6300.2' }, [PSCustomObject]@{ fileVersion = ''; patchLevel = ''; version = '' }) | ForEach-Object { Get-SqlInstanceVersion $_ }) -join ',') '13.0.6300.2,10.50.6000.34,13.0.6300.2,' 'SQL Server: the engine file version first, else the registry PatchLevel without its service pack number'
$sqlHost = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json'); $sqlHost.meta.collectedAtUtc = '2026-12-01T08:00:00Z'
$sqlHost.software = @([ordered]@{ name = 'Microsoft SQL Server 2016 (64-bit)'; version = ''; publisher = 'Microsoft Corporation' }, [ordered]@{ name = 'Microsoft SQL Server 2014 (64-bit)'; version = ''; publisher = 'Microsoft Corporation' }, [ordered]@{ name = 'Microsoft SQL Server 2022 (64-bit)'; version = ''; publisher = 'Microsoft Corporation' })
$sqlHost.sqlServer = @(
    [PSCustomObject]@{ name = 'A'; id = 'MSSQL13.A'; fileVersion = '13.0.6300.2'; patchLevel = '13.3.6300.2' }, [PSCustomObject]@{ name = 'B'; id = 'MSSQL13.B'; fileVersion = ''; patchLevel = '13.2.5026.0' },
    [PSCustomObject]@{ name = 'C'; id = 'MSSQL12.C'; fileVersion = '12.0.6449.1' }, [PSCustomObject]@{ name = 'D'; id = 'MSSQL16.D'; fileVersion = '16.0.4135.4' },
    [PSCustomObject]@{ name = 'E'; id = 'MSSQL16.E'; fileVersion = '16.0.1000.6' }, [PSCustomObject]@{ name = 'F'; id = 'MSSQL15.F'; fileVersion = '15.0.2190.7' })
$sqlRes = @((Invoke-HostChecks -Snapshot $sqlHost -Config $cfgEol).Findings | Where-Object { $_.Type -like 'software_*' })
Assert-Equal (($sqlRes | Sort-Object Type, Object | ForEach-Object { "$($_.Type)|$($_.Object)|$($_.Severity)|$($_.Found)|$($_.Expected)" }) -join ';') 'software_eol|software: Microsoft SQL Server 2014|Low|Microsoft SQL Server 2014 SP3, end of life 2024-07-09|a supported release or service pack;software_eol|software: Microsoft SQL Server 2016|Medium|Microsoft SQL Server 2016 SP2, end of life 2022-10-11|a supported release or service pack;software_outdated|software: Microsoft SQL Server 2022|Low|16.0.1000.6|16.0.1200.5 or later' 'SQL Server: judged per instance (2016 SP2 out of support, 2014 SP3 under ESU, 2022 behind on both branches, 2019 on its latest GDR), the Programs and Features rows left to it'
Assert-True (@($sqlRes | Where-Object { $_.Object -eq 'software: Microsoft SQL Server 2016' -and $_.Detail -eq 'SQL Server: 2 of 2 instances, the oldest at build 13.0.5026.0 (Microsoft SQL Server 2016 SP2). Support for Microsoft SQL Server 2016 SP2 ended 2022-10-11, 1512 days before collection (endoflife.date).' }).Count -eq 1 -and @($sqlRes | Where-Object { $_.Object -eq 'software: Microsoft SQL Server 2022' -and $_.Detail -match '^SQL Server: 2 of 2 instances, the oldest at build 16\.0\.1000\.6 .*security-only \(GDR\) build is 16\.0\.1200\.5' }).Count -eq 1 -and @($sqlRes | Where-Object { $_.Detail -match 'ESU\) runs until 2027-07-12' }).Count -eq 1) 'SQL Server: the finding names the instances, the service pack line and the branch'
$sqlHost.sqlServer = @([PSCustomObject]@{ name = 'A'; id = 'MSSQL13.A'; fileVersion = '13.0.6300.2' }, [PSCustomObject]@{ name = 'X'; id = 'MSSQL11.X'; fileVersion = '11.0.7001.0' })
Assert-Equal ((@((Invoke-HostChecks -Snapshot $sqlHost -Config $cfgEol).Findings | Where-Object { $_.Type -like 'software_*' }) | Sort-Object Object | ForEach-Object { "$($_.Object)|$($_.Found)" }) -join ';') 'software: Microsoft SQL Server 2014|Microsoft SQL Server 2014, end of life 2024-07-09;software: Microsoft SQL Server 2016|Microsoft SQL Server 2016 SP3, end of life 2026-07-14' 'SQL Server: an instance whose line is unknown leaves the Programs and Features rows to the table'
# Chocolatey package versions (-ChocoFile / -ChocoOnline) for programs endoflife.date lacks: every
# version with its publication date. A feed page as the OData API writes it (typed properties are
# elements with an m:type attribute), with a pre-release, a package fix version (24.9.0.20241201 is
# 24.9.0, first published 2024-11-30) and a release after collection (2026-10-01).
$chocoEntry = { param($v, $d, $pre) "<entry><id>x</id><m:properties><d:Version>$v</d:Version><d:IsPrerelease m:type=`"Edm.Boolean`">$pre</d:IsPrerelease><d:Published m:type=`"Edm.DateTime`">${d}T12:00:00.123</d:Published></m:properties></entry>" }
$chocoFeed = { param($entries) "<?xml version=`"1.0`" encoding=`"utf-8`"?><feed xml:base=`"https://community.chocolatey.org/api/v2/`" xmlns:d=`"http://schemas.microsoft.com/ado/2007/08/dataservices`" xmlns:m=`"http://schemas.microsoft.com/ado/2007/08/dataservices/metadata`" xmlns=`"http://www.w3.org/2005/Atom`"><title type=`"text`">FindPackagesById</title>$($entries -join '')</feed>" }
$chocoPage = & $chocoFeed @((& $chocoEntry '26.4.0' '2026-10-06' 'false'), (& $chocoEntry '24.9.0.20241201' '2024-12-01' 'false'), (& $chocoEntry '24.5.0' '2024-05-15' 'false'), (& $chocoEntry '25.0.0-beta' '2025-01-10' 'true'), (& $chocoEntry '24.9.0' '2024-11-30' 'false'), (& $chocoEntry '24.8.0' '2024-08-20' 'false'), (& $chocoEntry '23.1.0' '2023-06-21' 'false'))
$chocoParsed = ConvertFrom-ChocoFeed $chocoPage
$chocoVers = @(Merge-ChocoVersions $chocoParsed.Versions)
Assert-Equal "$($chocoParsed.Entries)|$((($chocoVers | ForEach-Object { "$($_.Version)@$($_.Published)" }) -join ','))" '7|23.1.0@2023-06-21,24.5.0@2024-05-15,24.8.0@2024-08-20,24.9.0@2024-11-30,26.4.0@2026-10-06' 'Chocolatey feed: versions with their first publication date, pre-releases dropped, a package fix is the program version'
Assert-True ($null -eq (ConvertFrom-ChocoFeed '<!DOCTYPE html><html><body>Error</body></html>') -and (ConvertFrom-ChocoFeed (& $chocoFeed @())).Entries -eq 0) 'Chocolatey feed: an error page is no feed, an empty page ends the paging'
$chocoCat = @{ '7zip' = $chocoVers; 'winscp' = @([PSCustomObject]@{ Version = '6.5.7'; Published = '2026-09-20' }) }
Assert-Equal ((@(ConvertFrom-ChocoCatalog (ConvertTo-ChocoCatalogJson $chocoCat 'test'))[0]['7zip'] | ForEach-Object { $_.Version }) -join ',') '23.1.0,24.5.0,24.8.0,24.9.0,26.4.0' 'Chocolatey: the copy kept next to the report reads back the same'
$chocoHost = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$chocoHost.software = @([ordered]@{ name = '7-Zip 24.01 (x64)'; version = '24.01'; publisher = 'Igor Pavlov' }, [ordered]@{ name = 'WinSCP 6.5.6'; version = '6.5.6'; publisher = 'Martin Prikryl' }, [ordered]@{ name = 'VLC media player'; version = '3.0.21'; publisher = 'VideoLAN' })
$cfgChoco = $config.Clone(); $cfgChoco['Choco'] = $chocoCat
$chocoRes = @((Invoke-HostChecks -Snapshot $chocoHost -Config $cfgChoco).Findings | Where-Object { $_.Type -eq 'software_outdated' })
Assert-Equal (($chocoRes | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Found)|$($_.Expected)" }) -join ';') 'software: 7-Zip|Medium|24.01|24.9.0 or later' 'Chocolatey: 7-Zip behind its releases (26.4.0 came out after collection), WinSCP one release behind inside the grace period, VLC without data not judged'
Assert-True ($chocoRes[0].Detail -match '^Installed as 7-Zip 24\.01 \(x64\) \(version 24\.01\)\. 3 newer releases came out before collection: the first, 24\.5\.0, on 2024-05-15 \(869 days before collection\), the newest 24\.9\.0 on 2024-11-30 \(Chocolatey community repository\)\.$') 'Chocolatey: the finding names the first and the newest release it missed, with their dates'
Assert-Equal @((Invoke-HostChecks -Snapshot $chocoHost -Config $config).Findings | Where-Object { $_.Type -eq 'software_outdated' }).Count 0 'Chocolatey: without the data nothing is judged'
# Known vulnerabilities (-CveFile / -CveOnline): NVD CVE API 2.0 pages, judged on version ranges here,
# and EPSS scores. A page with ranges, an exact version, a platform (AND) node, a rejected CVE, another
# product's CVE, a CVE in KEV and one published after collection (2026-10-01).
$nvdCve = { param($id, $pub, $score, $nodes, $kev, $status)
    $c = [ordered]@{ id = $id; published = "${pub}T10:15:00.000"; vulnStatus = $(if ($status) { $status } else { 'Analyzed' }); metrics = [ordered]@{ cvssMetricV31 = @([ordered]@{ source = 'nvd@nist.gov'; type = 'Primary'; cvssData = [ordered]@{ version = '3.1'; baseScore = $score } }) }; configurations = @([ordered]@{ nodes = @($nodes) }) }
    if ($kev) { $c['cisaExploitAdd'] = $kev }
    [ordered]@{ cve = $c } }
$nvdRange = { param($crit, $ee, $ei) $m = [ordered]@{ vulnerable = $true; criteria = $crit }; if ($ee) { $m['versionEndExcluding'] = $ee }; if ($ei) { $m['versionEndIncluding'] = $ei }; [ordered]@{ operator = 'OR'; negate = $false; cpeMatch = @($m) } }
$sevenAll = 'cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*'
$nvdVulns = @(
    (& $nvdCve 'CVE-2024-11477' '2024-11-22' 7.8 @(& $nvdRange $sevenAll '24.07')),
    (& $nvdCve 'CVE-2025-0411' '2025-01-25' 7.0 @(& $nvdRange $sevenAll '24.09') '2025-02-06'),
    (& $nvdCve 'CVE-2026-9999' '2026-10-05' 9.8 @(& $nvdRange $sevenAll '26.04')),
    (& $nvdCve 'CVE-2020-1111' '2020-01-01' 9.8 @(& $nvdRange $sevenAll '30.00') $null 'Rejected'),
    (& $nvdCve 'CVE-2019-2222' '2019-03-01' 5.5 @(& $nvdRange 'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*')),
    (& $nvdCve 'CVE-2018-3333' '2018-05-01' 8.8 @([ordered]@{ operator = 'AND'; negate = $false; children = @((& $nvdRange $sevenAll $null '9.20'), [ordered]@{ operator = 'OR'; negate = $false; cpeMatch = @([ordered]@{ vulnerable = $false; criteria = 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }) }) })),
    (& $nvdCve 'CVE-2021-4444' '2021-01-01' 9.0 @(& $nvdRange 'cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*' '2.0')))
$nvdPage = [ordered]@{ resultsPerPage = $nvdVulns.Count; startIndex = 0; totalResults = $nvdVulns.Count; format = 'NVD_CVE'; version = '2.0'; vulnerabilities = $nvdVulns } | ConvertTo-Json -Depth 12
$nvdParsed = ConvertFrom-NvdPage $nvdPage @('7-zip:7-zip')
Assert-Equal "$($nvdParsed.Total)|$((@($nvdParsed.Cves | ForEach-Object { $_.id })) -join ',')" '7|CVE-2024-11477,CVE-2025-0411,CVE-2026-9999,CVE-2019-2222,CVE-2018-3333' 'NVD: CVEs of the product kept (rejected ones and other products dropped), ranges found in nested platform nodes'
Assert-Equal ((@($nvdParsed.Cves | ForEach-Object { "$($_.id)=$(Test-CveAffects $_.ranges '23.01')" })) -join ',') 'CVE-2024-11477=True,CVE-2025-0411=True,CVE-2026-9999=True,CVE-2019-2222=True,CVE-2018-3333=False' 'NVD: version ranges and exact versions judged against 23.01'
Assert-True (-not (Test-CveAffects @([ordered]@{ version = ''; si = '2.0'; se = ''; ei = ''; ee = '2.5' }) '2.5') -and (Test-CveAffects @([ordered]@{ version = ''; si = '2.0'; se = ''; ei = ''; ee = '2.5' }) '2.0') -and -not (Test-CveAffects @([ordered]@{ version = ''; si = ''; se = '2.0'; ei = ''; ee = '' }) '2.0')) 'NVD: start and end bounds, including and excluding'
$epssText = "#model_version:v2026.06.15,score_date:2026-10-14T12:00:24Z`ncve,epss,percentile`nCVE-1999-0001,0.04753,0.91738`nCVE-2025-0411,0.67071,0.99293`nCVE-2024-11477,0.02130,0.85000`n"
$wantedCves = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($c in $nvdParsed.Cves) { [void]$wantedCves.Add($c.id) }
$epssParsed = ConvertFrom-EpssCsv $epssText $wantedCves
Assert-Equal "$($epssParsed.Date)|$($epssParsed.Scores.Count)|$($epssParsed.Scores['CVE-2025-0411'])" '2026-10-14|2|0.67071' 'EPSS: the score date and the scores of the CVEs asked for'
$cveCat = @{ Products = @{ '7-Zip' = $nvdParsed.Cves }; Epss = $epssParsed.Scores; EpssDate = $epssParsed.Date }
$cveBack = ConvertFrom-CveCatalog (ConvertTo-CveCatalogJson $cveCat 'test')
Assert-True (@($cveBack.Products['7-Zip']).Count -eq 5 -and $cveBack.Epss['CVE-2024-11477'] -eq 0.0213 -and $cveBack.EpssDate -eq '2026-10-14' -and (Test-CveAffects @($cveBack.Products['7-Zip'])[0].ranges '23.01')) 'NVD: the copy kept next to the report reads back the same'
$cveHost = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_hardened.json')
$cveHost.software = @([ordered]@{ name = '7-Zip 23.01 (x64)'; version = '23.01'; publisher = 'Igor Pavlov' }, [ordered]@{ name = '7-Zip 26.04 (x64)'; version = '26.04'; publisher = 'Igor Pavlov' })
$cfgCve = $config.Clone(); $cfgCve['Cve'] = $cveBack
$cveRes = @((Invoke-HostChecks -Snapshot $cveHost -Config $cfgCve).Findings | Where-Object { $_.Type -eq 'software_cve' })
Assert-Equal (($cveRes | ForEach-Object { "$($_.Object)|$($_.Severity)|$($_.Found)|$($_.Expected)" }) -join ';') 'software: 7-Zip|High|23.01: 3 CVE|24.09 or later' 'software CVE: one finding per program, High with a CVE in KEV, the release that fixes them all'
Assert-True ($cveRes[0].Detail -eq 'Installed as 7-Zip 23.01 (x64) (version 23.01). 3 known vulnerabilities published before collection affect 7-Zip 23.01 (NVD): highest CVSS 7.8 (CVE-2024-11477); 1 in the CISA KEV catalog of exploited vulnerabilities (CVE-2025-0411); highest EPSS 0.671 (CVE-2025-0411, scores of 2026-10-14). Worst: CVE-2024-11477, CVE-2025-0411, CVE-2019-2222.') 'software CVE: count, CVSS, KEV, EPSS and the worst CVEs (the one published after collection is left out)'
$cveNoKev = $cveBack.Clone(); $cveNoKev.Products = @{ '7-Zip' = @($cveBack.Products['7-Zip'] | Where-Object { $_.id -ne 'CVE-2025-0411' }) }; $cveNoKev.Epss = @{}
$cfgCve['Cve'] = $cveNoKev
Assert-Equal @((Invoke-HostChecks -Snapshot $cveHost -Config $cfgCve).Findings | Where-Object { $_.Type -eq 'software_cve' } | ForEach-Object { $_.Severity }) 'Medium' 'software CVE: CVSS 7.8 without KEV or EPSS is Medium'
Assert-Equal @($weak.NotEvaluated | Where-Object { $_.Type -eq 'software_cve' }).Count 0 'software CVE: without NVD data the check is off, not "not evaluated"'
# Pending updates (collected with -CheckUpdates)
Assert-True (Has $weak 'updates_pending' 'update: KB5099999' 'High') 'updates: a Critical missing update is High'
Assert-True (Has $weak 'updates_pending' 'update: KB5088888' 'Medium') 'updates: an Important missing update is Medium'
Assert-True (Has $weak 'updates_pending' 'update: KB5077777' 'Low') 'updates: an update without a Microsoft rating is Low'
Assert-Equal @($weak.Findings | Where-Object { $_.Type -eq 'updates_pending' }).Count 3 'updates: definition updates are not listed'
Assert-True (@($weak.Findings | Where-Object { $_.Type -eq 'updates_pending' -and $_.Object -eq 'update: KB5099999' -and $_.Detail -match 'Reported by WSUS' -and $_.Detail -match 'needs a restart' }).Count -eq 1) 'updates: the finding says who reported it and whether it needs a restart'
Assert-Equal @($lap.Findings | Where-Object { $_.Type -eq 'updates_pending' }).Count 0 'updates: a search that found nothing gives no finding'
$searchFailed = Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_laptop.json')
$searchFailed.updatesPending = $null; $searchFailed.meta.sectionsCollected = @($searchFailed.meta.sectionsCollected | Where-Object { $_ -ne 'updatesPending' })
$searchFailed.meta.collectionErrors = @([PSCustomObject]@{ section = 'updatesPending'; message = 'The search failed: 0x8024402C' })
Assert-True (@((Invoke-HostChecks -Snapshot $searchFailed -Config $config).NotEvaluated | Where-Object { $_.Type -eq 'updates_pending' -and $_.Reason -match '0x8024402C' }).Count -eq 1) 'updates: a search that was asked for and failed is "not evaluated" with the reason'
# The download: one GET to the catalog address, through a local listener
$kevListener = $null
foreach ($try in 1..8) { $kevPort = Get-Random -Minimum 20000 -Maximum 60000; $kevListener = New-Object System.Net.HttpListener; $kevListener.Prefixes.Add("http://127.0.0.1:$kevPort/"); try { $kevListener.Start(); break } catch { $kevListener.Close() } }
$kevPs = [powershell]::Create(); $kevCap = [hashtable]::Synchronized(@{ Url = ''; Method = '' })
$kevPs.Runspace.SessionStateProxy.SetVariable('l', $kevListener); $kevPs.Runspace.SessionStateProxy.SetVariable('cap', $kevCap); $kevPs.Runspace.SessionStateProxy.SetVariable('body', [System.IO.File]::ReadAllText($kevSample))
[void]$kevPs.AddScript({ $ctx = $l.GetContext(); $cap.Url = $ctx.Request.Url.AbsolutePath; $cap.Method = $ctx.Request.HttpMethod; $buf = [System.Text.Encoding]::UTF8.GetBytes($body); $ctx.Response.ContentType = 'application/json'; $ctx.Response.OutputStream.Write($buf, 0, $buf.Length); $ctx.Response.Close() })
$kevAsync = $kevPs.BeginInvoke()
$env:HOSTBADGER_KEV_URL = "http://127.0.0.1:$kevPort/feeds/kev.json"
$kevDl = Join-Path $work 'kevdl'; New-Item -ItemType Directory -Path $kevDl -Force | Out-Null
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $kevDl 'r.html') -KevOnline *>&1 | Out-Null; [void]$kevAsync.AsyncWaitHandle.WaitOne(5000) }
finally { Remove-Item Env:\HOSTBADGER_KEV_URL -ErrorAction SilentlyContinue; try { $kevListener.Stop() } catch { }; $kevPs.Dispose() }
Assert-True ($kevCap.Method -eq 'GET' -and $kevCap.Url -eq '/feeds/kev.json') 'KEV online: a single GET of the catalog'
Assert-True ((Test-Path (Join-Path $kevDl 'r_kev.json')) -and @(Import-Csv (Join-Path $kevDl 'r.csv') | Where-Object { $_.Type -eq 'kev_software_match' }).Count -eq 2) 'KEV online: the catalog is kept next to the report and the findings use it'
$kevHtml = [System.IO.File]::ReadAllText((Join-Path $kevDl 'r.html'))
Assert-True ($kevHtml -match 'Installed software by publisher' -and $kevHtml -match 'Software and the CISA KEV catalog' -and $kevHtml -match 'Missing Windows updates by severity' -and $kevHtml -match '<h2>Installed software</h2>' -and $kevHtml -match 'Contoso CAD Viewer') 'report: software list and the software and update charts'
$kevFileRun = Join-Path $work 'kevfile'; New-Item -ItemType Directory -Path $kevFileRun -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $kevFileRun 'r.html') -KevFile $kevSample *>&1 | Out-Null
Assert-Equal @(Import-Csv (Join-Path $kevFileRun 'r.csv') | Where-Object { $_.Type -eq 'kev_software_match' }).Count 2 'KEV file: -KevFile gives the same findings and needs no network'
# endoflife.date download: one GET, the reduced copy kept next to the report, -EolFile reads it back.
foreach ($try in 1..8) { $eolPort = Get-Random -Minimum 20000 -Maximum 60000; $eolListener = New-Object System.Net.HttpListener; $eolListener.Prefixes.Add("http://127.0.0.1:$eolPort/"); try { $eolListener.Start(); break } catch { $eolListener.Close() } }
$eolPs = [powershell]::Create(); $eolCap = [hashtable]::Synchronized(@{ Url = ''; Method = '' })
$eolPs.Runspace.SessionStateProxy.SetVariable('l', $eolListener); $eolPs.Runspace.SessionStateProxy.SetVariable('cap', $eolCap); $eolPs.Runspace.SessionStateProxy.SetVariable('body', [System.IO.File]::ReadAllText($eolSample))
[void]$eolPs.AddScript({ $ctx = $l.GetContext(); $cap.Url = $ctx.Request.Url.AbsolutePath; $cap.Method = $ctx.Request.HttpMethod; $buf = [System.Text.Encoding]::UTF8.GetBytes($body); $ctx.Response.ContentType = 'application/json'; $ctx.Response.OutputStream.Write($buf, 0, $buf.Length); $ctx.Response.Close() })
$eolAsync = $eolPs.BeginInvoke()
$env:HOSTBADGER_EOL_URL = "http://127.0.0.1:$eolPort/api/v1/products/full"
$eolDl = Join-Path $work 'eoldl'; New-Item -ItemType Directory -Path $eolDl -Force | Out-Null
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $eolDl 'r.html') -EolOnline *>&1 | Out-Null; [void]$eolAsync.AsyncWaitHandle.WaitOne(5000) }
finally { Remove-Item Env:\HOSTBADGER_EOL_URL -ErrorAction SilentlyContinue; try { $eolListener.Stop() } catch { }; $eolPs.Dispose() }
Assert-True ($eolCap.Method -eq 'GET' -and $eolCap.Url -eq '/api/v1/products/full') 'endoflife.date online: a single GET of the data'
$eolRows = @(Import-Csv (Join-Path $eolDl 'r.csv') | Where-Object { $_.Type -like 'software_*' })
Assert-True ((Test-Path (Join-Path $eolDl 'r_eol.json')) -and (([System.IO.File]::ReadAllText((Join-Path $eolDl 'r_eol.json'))) -match 'endoflife\.date .*MIT License') -and @($eolRows | Where-Object { $_.Type -eq 'software_outdated' -and $_.Object -eq 'software: Mozilla Firefox' }).Count -eq 1 -and @($eolRows | Where-Object { $_.Type -eq 'software_eol' -and $_.Object -eq 'software: Node.js 16' -and $_.Detail -match 'endoflife\.date' }).Count -eq 1) 'endoflife.date online: the copy is kept next to the report (with its source) and the findings use it'
$eolFileOut = Join-Path $work 'eolfile'; New-Item -ItemType Directory -Path $eolFileOut -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $eolFileOut 'r.html') -EolFile (Join-Path $eolDl 'r_eol.json') *>&1 | Out-Null
Assert-Equal ((@(Import-Csv (Join-Path $eolFileOut 'r.csv') | Where-Object { $_.Type -like 'software_*' }) | ForEach-Object { "$($_.Type)|$($_.Host)|$($_.Object)|$($_.Severity)" }) -join ';') (($eolRows | ForEach-Object { "$($_.Type)|$($_.Host)|$($_.Object)|$($_.Severity)" }) -join ';') 'endoflife.date file: -EolFile on the kept copy gives the same findings, no network'
# Chocolatey download: every package of the map is asked for, whatever the hosts have, page by page
# until an empty page; a busy answer (503) is tried again.
foreach ($try in 1..8) { $chPort = Get-Random -Minimum 20000 -Maximum 60000; $chListener = New-Object System.Net.HttpListener; $chListener.Prefixes.Add("http://127.0.0.1:$chPort/"); try { $chListener.Start(); break } catch { $chListener.Close() } }
$chPs = [powershell]::Create(); $chCap = [hashtable]::Synchronized(@{ Ids = (New-Object System.Collections.ArrayList); Methods = (New-Object System.Collections.ArrayList); Busy = 0 })
$chPs.Runspace.SessionStateProxy.SetVariable('l', $chListener); $chPs.Runspace.SessionStateProxy.SetVariable('cap', $chCap)
$chPs.Runspace.SessionStateProxy.SetVariable('page', $chocoPage); $chPs.Runspace.SessionStateProxy.SetVariable('empty', (& $chocoFeed @()))
[void]$chPs.AddScript({
        while ($l.IsListening) {
            try { $ctx = $l.GetContext() } catch { break }
            $q = [System.Uri]::UnescapeDataString($ctx.Request.Url.Query)
            $id = if ($q -match "id='([^']+)'") { $Matches[1] } else { '' }
            [void]$cap.Methods.Add($ctx.Request.HttpMethod)
            if ($q -notmatch 'skip=') { [void]$cap.Ids.Add($id) }
            if ($id -eq 'vlc' -and $cap.Busy -eq 0) { $cap.Busy = 1; $ctx.Response.StatusCode = 503; $ctx.Response.Close(); continue }
            $body = if ($id -eq '7zip' -and $q -notmatch 'skip=') { $page } else { $empty }
            $buf = [System.Text.Encoding]::UTF8.GetBytes($body); $ctx.Response.ContentType = 'application/atom+xml'; $ctx.Response.OutputStream.Write($buf, 0, $buf.Length); $ctx.Response.Close()
        }
    })
$chAsync = $chPs.BeginInvoke()
$env:HOSTBADGER_CHOCO_URL = "http://127.0.0.1:$chPort/api/v2/"
$chDl = Join-Path $work 'chocodl'; New-Item -ItemType Directory -Path $chDl -Force | Out-Null
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $chDl 'r.html') -ChocoOnline *>&1 | Out-Null }
finally { Remove-Item Env:\HOSTBADGER_CHOCO_URL -ErrorAction SilentlyContinue; try { $chListener.Stop() } catch { }; $chPs.Dispose() }
Assert-True ((($chCap.Ids | Sort-Object -Unique) -join ',') -eq (($script:ChocoProductMap | ForEach-Object { $_.Id } | Sort-Object -Unique) -join ',') -and @($chCap.Methods | Where-Object { $_ -ne 'GET' }).Count -eq 0 -and $chCap.Busy -eq 1) 'Chocolatey online: only GETs, every package of the list (not just what the hosts have), a busy answer tried again'
$chRows = @(Import-Csv (Join-Path $chDl 'r.csv') | Where-Object { $_.Type -eq 'software_outdated' })
Assert-True ((Test-Path (Join-Path $chDl 'r_choco.json')) -and $chRows.Count -eq 1 -and $chRows[0].Object -eq 'software: 7-Zip' -and $chRows[0].Host -eq 'WKS-ACCT-017' -and $chRows[0].Detail -match '3 newer releases') 'Chocolatey online: the copy is kept next to the report and 7-Zip 23.01 is behind'
$chFileOut = Join-Path $work 'chocofile'; New-Item -ItemType Directory -Path $chFileOut -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $chFileOut 'r.html') -ChocoFile (Join-Path $chDl 'r_choco.json') *>&1 | Out-Null
Assert-Equal @(Import-Csv (Join-Path $chFileOut 'r.csv') | Where-Object { $_.Type -eq 'software_outdated' -and $_.Object -eq 'software: 7-Zip' }).Count 1 'Chocolatey file: -ChocoFile on the kept copy gives the same finding, no network'
# NVD and EPSS download: every CPE of the map, by product (never a version), page by page, the API key
# as a header and never in the kept copy, then the EPSS file (gzip).
foreach ($try in 1..8) { $nvPort = Get-Random -Minimum 20000 -Maximum 60000; $nvListener = New-Object System.Net.HttpListener; $nvListener.Prefixes.Add("http://127.0.0.1:$nvPort/"); try { $nvListener.Start(); break } catch { $nvListener.Close() } }
$epssMs = New-Object System.IO.MemoryStream; $gzw = New-Object System.IO.Compression.GZipStream($epssMs, [System.IO.Compression.CompressionMode]::Compress, $true); $eb = [System.Text.Encoding]::UTF8.GetBytes($epssText); $gzw.Write($eb, 0, $eb.Length); $gzw.Dispose()
$vlcVuln = & $nvdCve 'CVE-2025-5555' '2025-02-01' 6.5 @(& $nvdRange 'cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*' '3.0.22')
$nvPs = [powershell]::Create(); $nvCap = [hashtable]::Synchronized(@{ Cpes = (New-Object System.Collections.ArrayList); Queries = (New-Object System.Collections.ArrayList); Keys = (New-Object System.Collections.ArrayList); Epss = 0 })
foreach ($kv in @(@('l', $nvListener), @('cap', $nvCap), @('page', $nvdPage), @('vlcA', ([ordered]@{ resultsPerPage = 1; startIndex = 0; totalResults = 2; vulnerabilities = @($vlcVuln) } | ConvertTo-Json -Depth 12)), @('vlcB', ([ordered]@{ resultsPerPage = 1; startIndex = 1; totalResults = 2; vulnerabilities = @($vlcVuln) } | ConvertTo-Json -Depth 12)), @('empty', '{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}'), @('gz', $epssMs.ToArray()))) { $nvPs.Runspace.SessionStateProxy.SetVariable($kv[0], $kv[1]) }
[void]$nvPs.AddScript({
        while ($l.IsListening) {
            try { $ctx = $l.GetContext() } catch { break }
            $q = [System.Uri]::UnescapeDataString($ctx.Request.Url.Query)
            [void]$cap.Queries.Add($q); [void]$cap.Keys.Add("$($ctx.Request.Headers['apiKey'])")
            if ($ctx.Request.Url.AbsolutePath -like '*epss*') { $cap.Epss++; $buf = $gz; $ctx.Response.ContentType = 'application/gzip' }
            else {
                $cpe = if ($q -match 'cpe:2\.3:a:([^&]+)') { $Matches[1] } else { '' }
                [void]$cap.Cpes.Add($cpe)
                $body = if ($cpe -eq '7-zip:7-zip') { $page } elseif ($cpe -eq 'videolan:vlc_media_player') { if ($q -match 'startIndex=1') { $vlcB } else { $vlcA } } else { $empty }
                $buf = [System.Text.Encoding]::UTF8.GetBytes($body); $ctx.Response.ContentType = 'application/json'
            }
            $ctx.Response.OutputStream.Write($buf, 0, $buf.Length); $ctx.Response.Close()
        }
    })
$nvAsync = $nvPs.BeginInvoke()
$savedNvdKey = $env:NVD_API_KEY
$env:HOSTBADGER_NVD_URL = "http://127.0.0.1:$nvPort/rest/json/cves/2.0"; $env:HOSTBADGER_EPSS_URL = "http://127.0.0.1:$nvPort/epss_scores-current.csv.gz"; $env:HOSTBADGER_NVD_PAUSE_MS = '0'; $env:NVD_API_KEY = 'regression-fake-nvd-key'
$cvDl = Join-Path $work 'cvedl'; New-Item -ItemType Directory -Path $cvDl -Force | Out-Null
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $cvDl 'r.html') -CveOnline *>&1 | Out-Null }
finally {
    Remove-Item Env:\HOSTBADGER_NVD_URL, Env:\HOSTBADGER_EPSS_URL, Env:\HOSTBADGER_NVD_PAUSE_MS -ErrorAction SilentlyContinue
    if ($savedNvdKey) { $env:NVD_API_KEY = $savedNvdKey } else { Remove-Item Env:\NVD_API_KEY -ErrorAction SilentlyContinue }
    try { $nvListener.Stop() } catch { }; $nvPs.Dispose()
}
$allCpes = @($script:CveCpeMap.Values | ForEach-Object { $_ } | ForEach-Object { $_ -replace '\\', '' } | Sort-Object -Unique)
Assert-True ((((@($nvCap.Cpes | ForEach-Object { $_ -replace '\\', '' }) | Sort-Object -Unique)) -join ',') -eq ($allCpes -join ',') -and @($nvCap.Queries | Where-Object { $_ -match 'cpe:2\.3:a:[^:&]+:[^:&]+:\d' }).Count -eq 0 -and @($nvCap.Cpes | Where-Object { $_ -eq 'videolan:vlc_media_player' }).Count -eq 2 -and $nvCap.Epss -eq 1) 'NVD online: every CPE of the list, by product and never by version, a second page when there is one, one EPSS file'
Assert-True (@($nvCap.Keys | Where-Object { $_ -eq 'regression-fake-nvd-key' }).Count -ge $allCpes.Count -and ([System.IO.File]::ReadAllText((Join-Path $cvDl 'r_cve.json'))) -notmatch 'regression-fake-nvd-key') 'NVD online: the API key goes as a header, never into the kept copy'
$cvRows = @(Import-Csv (Join-Path $cvDl 'r.csv') | Where-Object { $_.Type -eq 'software_cve' })
Assert-True ($cvRows.Count -eq 1 -and $cvRows[0].Host -eq 'WKS-ACCT-017' -and $cvRows[0].Object -eq 'software: 7-Zip' -and $cvRows[0].Severity -eq 'High' -and $cvRows[0].Detail -match 'highest EPSS 0\.671') 'NVD online: 7-Zip 23.01 on the weak host, with KEV and EPSS'
$cvFileOut = Join-Path $work 'cvefile'; New-Item -ItemType Directory -Path $cvFileOut -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $cvFileOut 'r.html') -CveFile (Join-Path $cvDl 'r_cve.json') *>&1 | Out-Null
Assert-Equal (@(Import-Csv (Join-Path $cvFileOut 'r.csv') | Where-Object { $_.Type -eq 'software_cve' }) | ForEach-Object { "$($_.Host)|$($_.Object)|$($_.Severity)|$($_.Detail)" }) (@($cvRows) | ForEach-Object { "$($_.Host)|$($_.Object)|$($_.Severity)|$($_.Detail)" }) 'NVD file: -CveFile on the kept copy gives the same finding, no network'

# Vulnerable drivers (LOLDrivers, by SHA-256): a malicious driver is Critical, a loaded vulnerable one
# High; the blocklist off is Medium; the hardened host has none. The shipped catalog is used unless
# -DriversOnline downloads a fresh one, which replaces it.
$drv = @($weak.Findings | Where-Object { $_.Type -eq 'vulnerable_driver_present' } | Sort-Object Object)
Assert-Equal (($drv | ForEach-Object { "$($_.Object)|$($_.Severity)" }) -join ';') 'driver: kbdhelper|Critical;driver: RTCore64|High' 'drivers: a known malicious driver is Critical, a loaded vulnerable one High'
Assert-True ($drv[1].Detail -match 'is a known vulnerable driver \(RTCore64\.sys, LOLDrivers [0-9a-f-]+\); state Running, start Auto\.$') 'drivers: the detail names the catalog entry and the driver state'
Assert-Equal (@($weak.Findings | Where-Object { $_.Type -eq 'driver_blocklist_off' }) | ForEach-Object { "$($_.Severity)|$($_.Found)|$($_.Expected)" }) 'Medium|0|1' 'drivers: the Microsoft blocklist turned off'
Assert-Equal @($hard.Findings | Where-Object { $_.Type -like '*driver*' }).Count 0 'drivers: a host with stock drivers has no finding'
Assert-True (@($part.NotEvaluated | Where-Object { $_.Type -eq 'vulnerable_driver_present' }).Count -eq 1) 'drivers: a snapshot without the drivers section lists the check as not evaluated'
# A mini catalog in the LOLDrivers format, with keys that differ only by case (the real one has them):
# RTCore64's hash, here as a malicious driver, so the result shows which catalog was used.
$rtHash = (Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json')).drivers.list | Where-Object { $_.name -eq 'RTCore64' } | ForEach-Object { $_.sha256 }
$lolSample = Join-Path $work 'lol_sample.json'
[System.IO.File]::WriteAllText($lolSample, "[{`"Id`":`"test-0001`",`"Category`":`"malicious`",`"Verified`":`"TRUE`",`"CVE`":[`"CVE-2019-16098`"],`"Commands`":{`"Description`":`"x`"},`"Resources`":[],`"KnownVulnerableSamples`":[{`"Filename`":`"RTCore64.sys`",`"OriginalFilename`":`"RTCore64.sys`",`"SHA256`":`"$rtHash`",`"LoadsDespiteHVCI`":`"FALSE`",`"Imports`":{`"init`":1,`"INIT`":2}}]}]")
foreach ($try in 1..8) { $lolPort = Get-Random -Minimum 20000 -Maximum 60000; $lolListener = New-Object System.Net.HttpListener; $lolListener.Prefixes.Add("http://127.0.0.1:$lolPort/"); try { $lolListener.Start(); break } catch { $lolListener.Close() } }
$lolPs = [powershell]::Create(); $lolCap = [hashtable]::Synchronized(@{ Url = ''; Method = '' })
$lolPs.Runspace.SessionStateProxy.SetVariable('l', $lolListener); $lolPs.Runspace.SessionStateProxy.SetVariable('cap', $lolCap); $lolPs.Runspace.SessionStateProxy.SetVariable('body', [System.IO.File]::ReadAllText($lolSample))
[void]$lolPs.AddScript({ $ctx = $l.GetContext(); $cap.Url = $ctx.Request.Url.AbsolutePath; $cap.Method = $ctx.Request.HttpMethod; $buf = [System.Text.Encoding]::UTF8.GetBytes($body); $ctx.Response.ContentType = 'application/json'; $ctx.Response.OutputStream.Write($buf, 0, $buf.Length); $ctx.Response.Close() })
$lolAsync = $lolPs.BeginInvoke()
$env:HOSTBADGER_DRIVERS_URL = "http://127.0.0.1:$lolPort/api/drivers.json"
$lolDl = Join-Path $work 'loldl'; New-Item -ItemType Directory -Path $lolDl -Force | Out-Null
try { & (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $lolDl 'r.html') -DriversOnline *>&1 | Out-Null; [void]$lolAsync.AsyncWaitHandle.WaitOne(5000) }
finally { Remove-Item Env:\HOSTBADGER_DRIVERS_URL -ErrorAction SilentlyContinue; try { $lolListener.Stop() } catch { }; $lolPs.Dispose() }
Assert-True ($lolCap.Method -eq 'GET' -and $lolCap.Url -eq '/api/drivers.json') 'drivers online: a single GET of the catalog'
$lolRows = @(Import-Csv (Join-Path $lolDl 'r.csv') | Where-Object { $_.Type -eq 'vulnerable_driver_present' })
Assert-True ((Test-Path (Join-Path $lolDl 'r_drivers.json')) -and $lolRows.Count -eq 1 -and $lolRows[0].Object -eq 'driver: RTCore64' -and $lolRows[0].Severity -eq 'Critical' -and $lolRows[0].Detail -match 'CVE-2019-16098') 'drivers online: the downloaded catalog replaces the shipped one and is kept next to the report'

# Encrypted snapshots (.hbx): the collector's own Protect-SnapshotBytes (taken from its source; the
# collector is not run) seals a snapshot zip with a password or to a certificate, and HostBadger.ps1
# opens it with -SnapshotPassword or -SnapshotPfx. A wrong password skips the host with a warning.
# The AI offer after a report re-runs the analysis: it must reuse the catalogs downloaded for the
# report (<report>_kev.json, <report>_drivers.json) instead of downloading them again. The launcher's
# own Invoke-AiOffer is taken from its source; the prompt and the run are stubbed.
$lnAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Start-HostBadger.ps1'), [ref]$null, [ref]$null)
. ([scriptblock]::Create($lnAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-AiOffer' }, $true).Extent.Text))
function Read-AiMode { param($Prompt, $Default) 'D' }
function Add-AiParams { param($Params, $Mode) $Params['AiDryRun'] = 'p.txt' }
function Invoke-Sub { param($Script, $P) $script:aiRerun = $P }
$offerDir = Join-Path $work 'offer'; New-Item -ItemType Directory -Path $offerDir -Force | Out-Null
foreach ($n in 'r.html', 'r_kev.json', 'r_drivers.json', 'r_eol.json', 'r_choco.json', 'r_cve.json') { Set-Content -LiteralPath (Join-Path $offerDir $n) -Value '{}' }
$script:aiRerun = $null
Invoke-AiOffer @{ Snapshot = $fleet; OutHtml = (Join-Path $offerDir 'r.html'); KevOnline = $true; DriversOnline = $true; EolOnline = $true; ChocoOnline = $true; CveOnline = $true } 6>&1 | Out-Null
Assert-True ($script:aiRerun -and -not $script:aiRerun.ContainsKey('KevOnline') -and -not $script:aiRerun.ContainsKey('DriversOnline') -and -not $script:aiRerun.ContainsKey('EolOnline') -and -not $script:aiRerun.ContainsKey('ChocoOnline') -and -not $script:aiRerun.ContainsKey('CveOnline') -and $script:aiRerun['CveFile'] -eq (Join-Path $offerDir 'r_cve.json') -and $script:aiRerun['ChocoFile'] -eq (Join-Path $offerDir 'r_choco.json') -and $script:aiRerun['KevFile'] -eq (Join-Path $offerDir 'r_kev.json') -and $script:aiRerun['DriversFile'] -eq (Join-Path $offerDir 'r_drivers.json') -and $script:aiRerun['EolFile'] -eq (Join-Path $offerDir 'r_eol.json') -and $script:aiRerun['AiDryRun']) 'AI offer: the re-run reuses the catalogs kept next to the report, nothing is downloaded again'
Remove-Item Function:\Read-AiMode, Function:\Add-AiParams, Function:\Invoke-Sub, Function:\Invoke-AiOffer
# -DriversFile reads the copy kept by -DriversOnline (and the original drivers.json, through the same converter).
$dfOut = Join-Path $work 'driversfile'; New-Item -ItemType Directory -Path $dfOut -Force | Out-Null
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $dfOut 'r.html') -DriversFile (Join-Path $lolDl 'r_drivers.json') *>&1 | Out-Null
$dfRows = @(Import-Csv (Join-Path $dfOut 'r.csv') | Where-Object { $_.Type -eq 'vulnerable_driver_present' })
Assert-True ($dfRows.Count -eq 1 -and $dfRows[0].Severity -eq 'Critical') 'drivers file: -DriversFile uses a kept catalog, no network'
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $dfOut 'raw.html') -DriversFile $lolSample *>&1 | Out-Null
Assert-Equal @(Import-Csv (Join-Path $dfOut 'raw.csv') | Where-Object { $_.Type -eq 'vulnerable_driver_present' }).Count 1 'drivers file: the original LOLDrivers drivers.json works too'
# The launcher offers a catalog kept by an earlier run (here a converted LOLDrivers copy in .\output) as
# the default: Enter uses it, and the review screen names the file. Nothing is downloaded.
$keptDir = Join-Path $work 'kept'; New-Item -ItemType Directory -Path (Join-Path $keptDir 'output') -Force | Out-Null
Copy-Item (Join-Path $lolDl 'r_drivers.json') (Join-Path $keptDir 'output\old_drivers.json')
Push-Location $keptDir
try { $keptOut = (@('2', $fleet, (Join-Path $keptDir 'k.html'), 'n', '', '','', '', '', '', '', '', '', '', '', '', '', '', '', 'n', 'q') -join "`n") | & $psExe -NoProfile -ExecutionPolicy Bypass -File $launcher 2>&1 | Out-String }
finally { Pop-Location }
$keptRows = @(Import-Csv (Join-Path $keptDir 'k.csv') -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'vulnerable_driver_present' })
Assert-True ($keptOut -match 'Kept from an earlier run: .*old_drivers\.json' -and $keptOut -match 'LOLDrivers catalog\s+file .*old_drivers\.json' -and $keptOut -match 'driver files from .*old_drivers\.json' -and $keptRows.Count -eq 1 -and $keptRows[0].Severity -eq 'Critical') 'launcher: a catalog kept by an earlier run is offered, Enter uses it (no download)'

# The lib files are dot-sourced into HostBadger.ps1's own scope: a variable they set at the top level
# with the name of a parameter silently replaces what the user passed (it once wiped -SnapshotPassword).
$hbParams = @(([System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'HostBadger.ps1'), [ref]$null, [ref]$null)).ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath.ToLower() })
$clash = foreach ($lf in Get-ChildItem (Join-Path $root 'lib') -Filter *.ps1) {
    $la = [System.Management.Automation.Language.Parser]::ParseFile($lf.FullName, [ref]$null, [ref]$null)
    foreach ($as in $la.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $false)) {
        $v = $as.Left -as [System.Management.Automation.Language.VariableExpressionAst]
        if ($v -and $hbParams -contains ($v.VariablePath.UserPath -replace '^script:', '').ToLower()) { "$($lf.Name): $($v.Extent.Text)" }
    }
}
Assert-Equal (@($clash) -join ', ') '' 'lib files set no top-level variable named like a HostBadger.ps1 parameter'
$collAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Collect-HostSnapshot.ps1'), [ref]$null, [ref]$null)
foreach ($fn in 'Protect-SnapshotBytes', 'Get-EncryptionCertificate') { . ([scriptblock]::Create($collAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true).Extent.Text)) }
$encDir = Join-Path $work 'enc'; New-Item -ItemType Directory -Path $encDir -Force | Out-Null
$weakZip = Join-Path $encDir 'w.zip'; Compress-Archive -LiteralPath (Join-Path $fleet 'hostsnapshot_weak.json') -DestinationPath $weakZip -Force
$zipBytes = [System.IO.File]::ReadAllBytes($weakZip); Remove-Item -LiteralPath $weakZip
$pwSnap = Join-Path $encDir 'pw'; New-Item -ItemType Directory -Path $pwSnap -Force | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $pwSnap 'hostsnapshot_WKS-ACCT-017_20261001080000.hbx'), (Protect-SnapshotBytes -Data $zipBytes -Password 'Corr3ct-h0rse'))
$encPw = & (Join-Path $root 'HostBadger.ps1') -Snapshot $pwSnap -OutHtml (Join-Path $encDir 'pw.html') -SnapshotPassword (ConvertTo-SecureString 'Corr3ct-h0rse' -AsPlainText -Force) *>&1 | Out-String
Assert-Equal @(Import-Csv (Join-Path $encDir 'pw.csv')).Count 195 'encryption: a password snapshot opens with -SnapshotPassword and gives the same findings'
$encBad = & (Join-Path $root 'HostBadger.ps1') -Snapshot $pwSnap -OutHtml (Join-Path $encDir 'bad.html') -SnapshotPassword (ConvertTo-SecureString 'wrong' -AsPlainText -Force) *>&1 | Out-String
Assert-True ($encBad -match 'wrong password, or the file is damaged' -and $encBad -match 'No readable snapshot') 'encryption: a wrong password is reported and the host is skipped'
$hbxBytes = [System.IO.File]::ReadAllBytes((Join-Path $pwSnap 'hostsnapshot_WKS-ACCT-017_20261001080000.hbx'))
Assert-True ([Text.Encoding]::ASCII.GetString($hbxBytes, 0, 4) -eq 'HBX1' -and $hbxBytes[4] -eq 1 -and [Text.Encoding]::UTF8.GetString($hbxBytes) -notmatch 'WKS-ACCT-017|HostBadger') 'encryption: the .hbx holds no clear text'
# Certificate: a key made in memory (nothing goes to the certificate store), its .cer for the
# collector and a .pfx for the analyzer.
$encRsa = [System.Security.Cryptography.RSA]::Create(2048)
$encReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList 'CN=HostBadger regression', $encRsa, ([System.Security.Cryptography.HashAlgorithmName]::SHA256), ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$encCert = $encReq.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(1))
$cerFile = Join-Path $encDir 't.cer'; [System.IO.File]::WriteAllBytes($cerFile, $encCert.Export('Cert'))
$pfxFile = Join-Path $encDir 't.pfx'; [System.IO.File]::WriteAllBytes($pfxFile, $encCert.Export('Pfx', 'pfx-pw'))
$certSnap = Join-Path $encDir 'cert'; New-Item -ItemType Directory -Path $certSnap -Force | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $certSnap 'hostsnapshot_WKS-ACCT-017_20261001080000.hbx'), (Protect-SnapshotBytes -Data $zipBytes -Certificate (Get-EncryptionCertificate $cerFile)))
& (Join-Path $root 'HostBadger.ps1') -Snapshot $certSnap -OutHtml (Join-Path $encDir 'cert.html') -SnapshotPfx $pfxFile -SnapshotPfxPassword (ConvertTo-SecureString 'pfx-pw' -AsPlainText -Force) *>&1 | Out-Null
Assert-Equal @(Import-Csv (Join-Path $encDir 'cert.csv')).Count 195 'encryption: a certificate snapshot opens with the private key in -SnapshotPfx'
$encNoKey = & (Join-Path $root 'HostBadger.ps1') -Snapshot $certSnap -OutHtml (Join-Path $encDir 'nokey.html') *>&1 | Out-String
Assert-True ($encNoKey -match 'private key is not available here') 'encryption: without the private key the snapshot is not read, and says why'
$noKevHtml = [System.IO.File]::ReadAllText((Join-Path $hideOut 'show.html'))
Assert-True ($noKevHtml -notmatch 'Software and the CISA KEV catalog' -and $noKevHtml -match 'Installed software by publisher') 'report: no KEV chart without a catalog'
# Local accounts chart: weak 2 admins + 1 standard, hardened 1 admin + 1 disabled, laptop 2 disabled;
# the domain controller (no local accounts) and the partial host (Administrators not readable) are
# left out.
Assert-True ($noKevHtml -match 'Local accounts: administrators vs standard users \(3 host\(s\)\)' -and $noKevHtml -match 'Administrators \(enabled\) \(3,' -and $noKevHtml -match 'Standard users \(enabled\) \(1,' -and $noKevHtml -match 'Disabled \(3,') 'report: local accounts chart, administrators vs standard users'
$mixDc = Get-LocalAccountMix (Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_dc.json')); $mixWeak = Get-LocalAccountMix (Import-HostSnapshot (Join-Path $fleet 'hostsnapshot_weak.json'))
Assert-True ($null -eq $mixDc -and "$($mixWeak.Admin)/$($mixWeak.Standard)/$($mixWeak.Disabled)" -eq '2/1/0') 'local accounts: no mix for a domain controller, members matched by SID'

# The AI prompt: the installed program behind a KEV finding is replaced by a token, the CVE ids stay.
$aiKev = Join-Path $kevFileRun 'ai_kev.txt'
& (Join-Path $root 'HostBadger.ps1') -Snapshot $fleet -OutHtml (Join-Path $kevFileRun 'k.html') -KevFile $kevSample -AiDryRun $aiKev *>&1 | Out-Null
$aiKevTxt = [System.IO.File]::ReadAllText($aiKev)
Assert-True ($aiKevTxt -match 'kev_software_match' -and $aiKevTxt -match 'CVE-2026-2002' -and $aiKevTxt -notmatch 'Installed as Contoso CAD Viewer' -and $aiKevTxt -match 'Installed as SOFTWARE-\d+') 'AI: the installed program name of a KEV finding is tokenized, the CVE ids are not'
Assert-True ($aiKevTxt -match 'software_eol' -and $aiKevTxt -notmatch 'Installed as Python 2\.7\.18' -and $aiKevTxt -match 'software: Python 2' -and $aiKevTxt -match '\(version 32\.0\.0\.465\)' -and $aiKevTxt -match 'no longer supported by its vendor') 'AI: the installed program name of a software EOL finding is tokenized, the lifecycle product and a four-part version are not'
# ------------------------------------------------------------------ real collector run: array-shape smoke test
# Runs the real collector on this machine (whatever it finds) and checks that every array field the
# privilege-escalation checks read (writableBy, ancestorControl, startableBy) came through the
# collector -> JSON -> analyzer round trip with real values, not blank ones. This is the generic
# regression test for the "return , $array" trap: a leading comma on an
# already-built array wraps it as a single element, and a caller iterating that element reads blank
# .kind/.sid/.rights off it instead of the real data. Hand-written synthetic snapshots never exercise
# this collector-internal plumbing, so only a real run catches it.
$realOut = Join-Path $work 'realcollect'; New-Item -ItemType Directory -Path $realOut -Force | Out-Null
& (Join-Path $root 'Collect-HostSnapshot.ps1') -OutDir $realOut -NoZip *>&1 | Out-Null
$realFile = Get-ChildItem $realOut -Filter 'hostsnapshot_*.json' | Select-Object -First 1
Assert-True ([bool]$realFile) 'real collector run: a snapshot was written'
if ($realFile) {
    $realJson = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($realFile.FullName))
    $realServices = @($realJson.services | Where-Object { $_ })
    # Every ancestorControl / writableBy entry must have all three fields populated: a blank one is
    # exactly the symptom of the nesting bug (kind/sid/rights empty while level is still there).
    $badAncestor = @($realServices | ForEach-Object { $_.ancestorControl } | Where-Object { $_ } | Where-Object { -not $_.kind -or -not $_.sid -or -not $_.rights })
    $badWritable = @($realServices | ForEach-Object { $_.writableBy } | Where-Object { $_ } | Where-Object { -not $_.scope -or -not $_.sid -or -not $_.rights })
    Assert-Equal $badAncestor.Count 0 'real collector run: no service has a blank ancestorControl entry'
    Assert-Equal $badWritable.Count 0 'real collector run: no service has a blank writableBy entry'
    # A folder with only trusted owners (SYSTEM, Administrators, TrustedInstaller...) must come back as
    # a true empty array, not a 1-element array wrapping an empty one (the same bug, the all-trusted case).
    # @($x).Count is 1 for $null, not 0: filter nulls first.
    $trustedOnly = @($realServices | Where-Object { "$($_.executable)" -match '(?i)^[a-z]:\\windows\\' }) | Select-Object -First 1
    if ($trustedOnly) { Assert-Equal @($trustedOnly.ancestorControl | Where-Object { $_ }).Count 0 'real collector run: a Windows-owned service folder has no ancestor control entries' }
    # writableBy and ancestorControl must read as [] in the raw JSON, never a bare null (startableBy is
    # allowed to be null: there it means "could not be determined", not "empty").
    $rawJson = [System.IO.File]::ReadAllText($realFile.FullName)
    Assert-Equal ([regex]::Matches($rawJson, '"writableBy":\s*null').Count) 0 'real collector run: writableBy is never a bare null in the JSON'
    Assert-Equal ([regex]::Matches($rawJson, '"ancestorControl":\s*null').Count) 0 'real collector run: ancestorControl is never a bare null in the JSON'
    $realRes = Invoke-HostChecks -Snapshot (Import-HostSnapshot $realFile.FullName) -Config $config
    $privescFindings = @($realRes.Findings | Where-Object { $_.Type -in 'service_path_ancestor_control', 'service_binary_writable', 'task_binary_writable', 'autorun_writable' })
    $blankText = @($privescFindings | Where-Object { [string]::IsNullOrWhiteSpace($_.Detail) -or $_.Detail -match '  (has|owns)  ' -or $_.Detail -match '\[\]' })
    Assert-Equal $blankText.Count 0 'real collector run: no privilege-escalation finding has blank text'
}
# ------------------------------------------------------------------ documentation
# COVERAGE.md is generated from the catalog and the README states the count, so both must follow the
# catalog.
$coverage = [System.IO.File]::ReadAllText((Join-Path $root 'COVERAGE.md'))
$missingDoc = @($script:CheckCatalog.Keys | Where-Object { $coverage -notmatch [regex]::Escape("``$_``") })
Assert-Equal ($missingDoc -join ',') '' 'COVERAGE.md lists every check'
Assert-True ([System.IO.File]::ReadAllText((Join-Path $root 'README.md')) -match "\*\*$($script:CheckCatalog.Count) checks\*\*") 'README states the check count'
# The collector ships with the analyzer: both print the release they belong to.
$verOf = { param($file, $var) if ([System.IO.File]::ReadAllText((Join-Path $root $file)) -match "\`$script:$var = '([^']+)'") { $Matches[1] } }
Assert-Equal (& $verOf 'Collect-HostSnapshot.ps1' 'CollectorVersion') (& $verOf 'HostBadger.ps1' 'HostBadgerVersion') 'collector and analyzer carry the same version'
# Line endings are pinned by .gitattributes (LF in the repository, CRLF on disk): a tool that rewrites a
# file with other line endings must not turn it into a whole-file diff.
$gitAttr = Join-Path $root '.gitattributes'
Assert-True ((Test-Path -LiteralPath $gitAttr) -and ([System.IO.File]::ReadAllText($gitAttr) -match '(?m)^\* text=auto eol=crlf\s*$')) '.gitattributes pins the line endings'

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
$rootNew = @(Get-ChildItem -LiteralPath $root -File | Where-Object { $rootFilesBefore -notcontains $_.Name } | ForEach-Object { $_.Name })
Assert-Equal ($rootNew -join ', ') '' 'the tests leave no file in the project folder'
# Put the developer's Gemini settings back (they matter only when the suite runs in an open session).
$env:GEMINI_API_KEY = $savedGeminiKey; $env:HOSTBADGER_GEMINI_BASEURL = $savedGeminiBase
Write-Host "HostBadger regression ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)): $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
