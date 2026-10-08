<#
.SYNOPSIS
    HostBadger: Windows host hardening analyzer. Reads snapshots written by
    Collect-HostSnapshot.ps1 and writes an HTML report, a findings CSV and,
    optionally, JSON Lines for a SIEM.

.DESCRIPTION
    Collect once on each host (as SYSTEM through EDR Real Time Response, or
    as a local administrator) and analyze anywhere. This script needs no
    module and no rights on the hosts, and it only goes on the network if you
    ask for the optional AI step. Give it one snapshot, a zip or a folder of
    them, and it reports every host in one place.

    If the data for a check couldn't be collected on a host (a section that
    failed, Defender in passive mode, ACLs skipped), the check is listed as
    "not evaluated" for that host. It is never counted as clean.

.PARAMETER Snapshot
    Snapshot files (hostsnapshot_*.json or .zip) or folders holding them
    (searched recursively). Several can be given.
.PARAMETER OutHtml
    HTML report. Default hostbadger_<time>.html in the current folder.
.PARAMETER SkipStig
    Leave out the DISA STIG checks (about 500 registry rules, one finding
    each). The other checks are not affected.
.PARAMETER HideCis
    Do not list the CIS-based findings in the HTML report (the compliance
    charts still count them; the CSV and JSON Lines keep them).
.PARAMETER HideStig
    Same for the DISA STIG findings.
.PARAMETER AiIncludeStig
    Also send the DISA STIG findings to Gemini. Without it they stay out of the
    prompt: there can be hundreds per host, and a prompt that large may make
    Gemini time out.
.PARAMETER KevFile
    CISA Known Exploited Vulnerabilities catalog (known_exploited_vulnerabilities.json)
    that you downloaded. Installed software is matched to it by vendor and product;
    the catalog has no version ranges, so a match is a lead to verify, not a verdict.
.PARAMETER KevOnline
    Download that catalog now. One HTTPS GET to
    www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json;
    nothing is sent. The copy is kept next to the report (<report>_kev.json).
.PARAMETER PerHost
    Also write one HTML report per host next to the fleet report
    (<OutHtml name>_<HOST>.html).
.PARAMETER OutCsv
    Findings CSV. Default: next to the HTML report.
.PARAMETER OutJsonl
    JSON Lines for a SIEM (findings, resolved findings with -CompareTo, one
    summary per host). Not written unless given.
.PARAMETER CompareTo
    Findings CSV of an earlier run: new and resolved findings are shown.
.PARAMETER ExceptionsFile
    JSON list of accepted risks: [{ "type", "host", "object", "reason",
    "owner", "expires" }], host and object accept "*".
.PARAMETER AllowedAdmins
    Members of the local Administrators group that belong there (names as
    "DOMAIN/Group", the bare name, or SIDs). Domain Admins and the built-in
    Administrator are always expected.
.PARAMETER ExpectedEdr
    The EDR every host should run, for example CrowdStrike or SentinelOne (more than one is
    fine). A host without it gets a High finding. Known names: CrowdStrike, SentinelOne,
    DefenderForEndpoint, CarbonBlack, CortexXDR, Sophos, TrendMicro, Trellix, ESET, Symantec,
    Elastic, Cybereason, Cylance, Bitdefender, Huntress. Any other text is looked for in the
    names of the services. Without it, only a host with no known EDR at all is reported.
.PARAMETER ExtraEdrServices
    Names of services that belong to an EDR that HostBadger does not know, so that they are
    counted as an agent (and flagged if they are stopped).
.PARAMETER MaxPatchAgeDays
    Days without an installed update before updates_stale (default 45).
.PARAMETER MaxSignatureAgeDays
    Days before Defender signatures are stale (default 7).
.PARAMETER SupportWarningDays
    Warn this many days before the OS goes out of support (default 90).
.PARAMETER OutRemediation
    Optional folder: besides the fix scripts that the report already shows under
    each check, write one remediate_<host>.ps1 per host with all of that host's
    fixes in one file, for scripted rollouts. It previews unless run with -Apply,
    writes a rollback file, and HostBadger never runs it.
.PARAMETER SendToAI
    Optional: after the report is saved, send the findings to Gemini for an
    executive summary and a remediation plan, and add them to the report.
    Without this switch (or -AiDryRun) nothing is ever sent and HostBadger
    never asks. Host names, domains, accounts, groups, SIDs, paths, service,
    task and autorun names and addresses are replaced by tokens first, the
    collector's error messages are never included, and a leak check refuses
    to send if any real name survived. The exact prompt is saved as
    <report>_ai_prompt.txt, the reply as <report>_ai_response.json.
.PARAMETER AiConfirm
    With -SendToAI: show what will be sent and ask y/N first.
.PARAMETER AiDryRun
    Path: write the exact pseudonymized prompt that would be sent and send
    nothing. Useful for a privacy review before enabling the AI step.
.PARAMETER ApiKey
    Gemini API key. Defaults to $env:GEMINI_API_KEY.
.PARAMETER Model
    Gemini model name. Defaults to gemini-3.7-flash.
.PARAMETER AiMaxAttempts
    How many times to try Gemini on a timeout or a busy server (429/5xx).
    Default 3; 0 keeps trying until it works (Ctrl+C to stop).

.EXAMPLE
    .\HostBadger.ps1 -Snapshot .\snapshots\ -OutHtml fleet.html
.EXAMPLE
    .\HostBadger.ps1 -Snapshot hostsnapshot_PC01_20261006101500.zip -CompareTo last_month.csv -OutJsonl siem.jsonl
#>
[CmdletBinding()]
param(
    [string[]]$Snapshot,
    [string]$OutHtml = '',
    [string]$OutCsv = '',
    [string]$OutJsonl = '',
    [string]$CompareTo = '',
    [string]$ExceptionsFile = '',
    [string[]]$AllowedAdmins = @(),
    [int]$MaxPatchAgeDays = 45,
    [int]$MaxSignatureAgeDays = 7,
    [int]$SupportWarningDays = 90,
    [int]$MaxCachedLogonsWorkstation = 4,
    [int]$MaxCachedLogonsServer = 1,
    [int]$MinSecurityLogKB = 196608,
    [string[]]$ExpectedEdr = @(),
    [string[]]$ExtraEdrServices = @(),
    [string]$OutRemediation = '',
    [switch]$PerHost,
    [switch]$SkipStig,
    [string]$KevFile = '',
    [switch]$KevOnline,
    [switch]$HideCis,
    [switch]$HideStig,
    [switch]$AiIncludeStig,
    [switch]$SendToAI,
    [switch]$AiConfirm,
    [string]$AiDryRun = '',
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model = 'gemini-3.7-flash',
    [int]$AiMaxAttempts = 3
)

$ErrorActionPreference = 'Stop'
$script:HostBadgerVersion = '1.1'
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\Checks.ps1')
. (Join-Path $PSScriptRoot 'lib\AI.ps1')
. (Join-Path $PSScriptRoot 'lib\Remediation.ps1')
. (Join-Path $PSScriptRoot 'lib\Reporting.ps1')

Write-Host @'
     _.--""--._
   .'  |    |  '.
  /    |    |    \      HostBadger 1.1
 |  (o)|    |(o)  |     Windows host hardening
 |     |    |     |     read-only snapshots, offline analysis
  \    '.__.'    /
   '._   \/   _.'
      '--..--'
'@ -ForegroundColor DarkYellow

if (-not $Snapshot -or $Snapshot.Count -eq 0) {
    Write-Host 'Usage: .\HostBadger.ps1 -Snapshot <file|zip|folder> [-OutHtml report.html] [-OutCsv findings.csv] [-OutJsonl siem.jsonl] [-CompareTo old.csv]'
    Write-Host 'Collect first on each host with Collect-HostSnapshot.ps1 (as SYSTEM or administrator). Get-Help .\HostBadger.ps1 -Full for every option.'
    return
}

$started = Get-Date
$config = @{
    AllowedAdmins = @($AllowedAdmins); MaxPatchAgeDays = $MaxPatchAgeDays; MaxSignatureAgeDays = $MaxSignatureAgeDays
    SupportWarningDays = $SupportWarningDays; MaxCachedLogonsWorkstation = $MaxCachedLogonsWorkstation
    MaxCachedLogonsServer = $MaxCachedLogonsServer; MinSecurityLogKB = $MinSecurityLogKB
    ExpectedEdr = @($ExpectedEdr); ExtraEdrServices = @($ExtraEdrServices)
}

$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
if (-not $OutHtml) { $OutHtml = "hostbadger_$stamp.html" }
if (-not $OutCsv) { $OutCsv = ($OutHtml -replace '\.html?$', '') + '.csv' }

# CISA KEV catalog: a file you give, or a download (the only network call outside the AI step).
if ($KevFile -or $KevOnline) {
    $kevJson = $null
    if ($KevFile) {
        if (Test-Path -LiteralPath $KevFile) { $kevJson = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $KevFile).Path) }
        else { Write-Host "KEV file not found: $KevFile" -ForegroundColor Yellow }
    }
    else {
        $kevJson = Get-KevCatalogOnline
        if ($kevJson) {
            $kevCopy = ([System.IO.Path]::GetFullPath($OutHtml) -replace '\.html?$', '') + '_kev.json'
            [System.IO.File]::WriteAllText($kevCopy, $kevJson, (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "KEV catalog kept at $kevCopy" -ForegroundColor DarkGray
        }
    }
    if ($kevJson) {
        try { $config['Kev'] = @(ConvertFrom-KevCatalog $kevJson); Write-Host "KEV catalog: $(@($config['Kev']).Count) exploited vulnerabilities." -ForegroundColor DarkGray }
        catch { Write-Host "KEV catalog not readable: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}

$files = @(Get-SnapshotFiles $Snapshot)
if ($files.Count -eq 0) { Write-Host 'No hostsnapshot_*.json or .zip found.' -ForegroundColor Red; return }

# Several snapshots of one host: the newest one counts.
$latest = @{}
$latestFile = @{}
$snapCount = @{}
$readIndex = 0
foreach ($f in $files) {
    $readIndex++
    Step-Spinner "Reading snapshots ($readIndex of $($files.Count))"
    try { $s = Import-HostSnapshot $f }
    catch { Stop-Spinner; Write-Warning $_.Exception.Message; continue }
    $name = (Get-SnapshotHostName $s).ToUpper()
    $when = ConvertTo-UtcDate $s.meta.collectedAtUtc
    $snapCount[$name] = 1 + [int]$snapCount[$name]
    if (-not $latest.ContainsKey($name) -or $when -gt (ConvertTo-UtcDate $latest[$name].meta.collectedAtUtc)) {
        $latest[$name] = $s
        $latestFile[$name] = $f
    }
}
Stop-Spinner
foreach ($name in ($snapCount.Keys | Sort-Object)) {
    if ($snapCount[$name] -gt 1) { Write-Host "  $name`: $($snapCount[$name]) snapshots, using the newest $($latestFile[$name])" -ForegroundColor DarkGray }
}
if ($latest.Count -eq 0) { Write-Host 'No readable snapshot.' -ForegroundColor Red; return }

$allFindings = New-Object System.Collections.Generic.List[object]
$hosts = New-Object System.Collections.Generic.List[object]
$hostIndex = 0
foreach ($name in ($latest.Keys | Sort-Object)) {
    $hostIndex++
    $s = $latest[$name]
    Step-Spinner "Analyzing host $hostIndex of $($latest.Count)"
    $r = Invoke-HostChecks -Snapshot $s -Config $config
    if ($SkipStig) {
        $r.Findings = @($r.Findings | Where-Object { $_.Category -ne 'DISA STIG' })
        $r.NotEvaluated = @($r.NotEvaluated | Where-Object { $_.Type -notlike 'stig_*' })
    }
    foreach ($f in $r.Findings) { $allFindings.Add($f) }
    $osTxt = if ($s.host -and $s.host.os) { "$($s.host.os.caption) $($s.host.os.displayVersion) (build $($s.host.os.build).$($s.host.os.ubr))" } else { 'unknown' }
    $hosts.Add([PSCustomObject]@{
            Name         = Get-SnapshotHostName $s
            Role         = Get-SnapshotRole $s
            Os           = $osTxt
            CollectedUtc = ConvertTo-UtcDate $s.meta.collectedAtUtc
            AsSystem     = [bool]$s.meta.runningAsSystem
            AsAdmin      = [bool]$s.meta.runningAsAdmin
            Synthetic    = [bool]$s.meta.synthetic
            NotEvaluated = @($r.NotEvaluated)
            Edr          = @(Get-EdrInventory -Snapshot $s -ExtraServices $ExtraEdrServices)
            EdrKnown     = (@($s.services | Where-Object { $_ }).Count -gt 0)
            Findings     = @($r.Findings)
            StigEvaluated = $(if ($SkipStig) { 0 } else { [int]$r.StigEvaluated })
            Software     = @($s.software | Where-Object { $_ })
            UpdatesSource = $(if ($s.updatesPending) { "$($s.updatesPending.source)" } else { '' })
            UpdatesSearched = [bool]($s.meta.options.checkUpdates -and $s.updatesPending)
            Score        = $null
        })
    if (-not $s.meta.runningAsSystem -and -not $s.meta.runningAsAdmin) {
        Stop-Spinner
        Write-Host "  $($hosts[$hosts.Count - 1].Name): collected as a standard user; $(@($r.NotEvaluated).Count) check(s) not evaluated. Collect as SYSTEM or administrator for full coverage." -ForegroundColor Yellow
    }
}
Stop-Spinner
$script:RunHosts = @($hosts | ForEach-Object { $_.Name })

$asOf = ($hosts | Sort-Object CollectedUtc -Descending | Select-Object -First 1).CollectedUtc
$split = Split-FindingsByException -Findings $allFindings.ToArray() -Exceptions (Import-Exceptions $ExceptionsFile) -AsOf $asOf
foreach ($h in $hosts) { $h.Score = Get-HostScore @($split.Active | Where-Object { $_.Host -eq $h.Name }) }

$comparison = if ($CompareTo) { Get-FindingsComparison -Findings $split.Active -PreviousCsv $CompareTo } else { $null }

# Remediation scripts: text files only. HostBadger never runs them.
$remInfo = $null
if ($OutRemediation) {
    $remDir = [System.IO.Path]::GetFullPath($OutRemediation)
    if (-not (Test-Path -LiteralPath $remDir)) { New-Item -ItemType Directory -Path $remDir -Force | Out-Null }
    $remInfo = @()
    foreach ($h in $hosts) {
        $r = New-RemediationScript -HostName $h.Name -Role $h.Role -Findings $split.Active -Config $config -CollectedUtc $h.CollectedUtc.ToString('yyyy-MM-dd HH:mm') -ToolVersion $script:HostBadgerVersion
        $file = ''
        if ($r.ActionCount -gt 0) {
            $file = 'remediate_' + ($h.Name -replace '[^\w\-]', '_') + '.ps1'
            # With a BOM so Windows PowerShell 5.1 reads it as UTF-8.
            [System.IO.File]::WriteAllText((Join-Path $remDir $file), $r.Text, (New-Object System.Text.UTF8Encoding($true)))
        }
        $remInfo += [PSCustomObject]@{ Host = $h.Name; File = $file; Actions = $r.ActionCount; Fixable = $r.FixableFindings; NotFixable = @($r.NotFixable).Count; Total = $r.TotalFindings }
    }
}

Step-Spinner 'Writing the findings CSV'
Export-FindingsCsv -Findings $split.Active -Path $OutCsv
if ($OutJsonl) { Export-FindingsJsonl -Findings $split.Active -Hosts $hosts -Path $OutJsonl -ToolVersion $script:HostBadgerVersion -Comparison $comparison }
$elapsed = (Get-Date) - $started
$elapsedText = if ($elapsed.TotalMinutes -ge 1) { '{0}m {1}s' -f [int][Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds } else { '{0:N1}s' -f $elapsed.TotalSeconds }
Step-Spinner 'Building the HTML report'
$html = ConvertTo-ReportHtml -Hosts $hosts.ToArray() -Split $split -Comparison $comparison -Config $config -ToolVersion $script:HostBadgerVersion -ElapsedText $elapsedText -Remediation $remInfo -HideCis:$HideCis -HideStig:$HideStig -KevLoaded:([bool]$config.Kev)
$htmlFull = [System.IO.Path]::GetFullPath($OutHtml)
[System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))

# One report per host, next to the fleet report: <name>_<HOST>.html
$perHostFiles = @()
if ($PerHost) {
    $base = $htmlFull -replace '\.html?$', ''
    foreach ($h in $hosts) {
        $hn = $h.Name
        $splitH = [PSCustomObject]@{
            Active   = @($split.Active | Where-Object { $_.Host -eq $hn })
            Accepted = @($split.Accepted | Where-Object { $_.Finding.Host -eq $hn })
            Expired  = @($split.Expired)
        }
        $cmpH = $null
        if ($comparison) {
            $cmpH = [PSCustomObject]@{
                PreviousPath = $comparison.PreviousPath
                New          = @($comparison.New | Where-Object { $_.Host -eq $hn })
                Resolved     = @($comparison.Resolved | Where-Object { $_.Host -eq $hn })
                Persisting   = @($comparison.Persisting | Where-Object { $_.Host -eq $hn })
            }
        }
        $remH = if ($remInfo) { @($remInfo | Where-Object { $_.Host -eq $hn }) } else { $null }
        Step-Spinner "Building the report for $hn"
        $htmlH = ConvertTo-ReportHtml -Hosts @($h) -Split $splitH -Comparison $cmpH -Config $config -ToolVersion $script:HostBadgerVersion -ElapsedText $elapsedText -Remediation $remH -HideCis:$HideCis -HideStig:$HideStig -KevLoaded:([bool]$config.Kev)
        $fileH = "$base`_$($hn -replace '[^\w\-]', '_').html"
        [System.IO.File]::WriteAllText($fileH, $htmlH, (New-Object System.Text.UTF8Encoding($false)))
        $perHostFiles += $fileH
    }
}

Stop-Spinner
$active = @($split.Active)
Write-Host ''
Write-Host "Hosts analyzed: $($hosts.Count)"
foreach ($h in ($hosts | Sort-Object { $_.Score.Score })) {
    $hf = @($active | Where-Object { $_.Host -eq $h.Name })
    Write-Host ("  {0,-24} {1,-11} {2} {3,3}/100  {4} finding(s), {5} not evaluated" -f $h.Name, $h.Role, $h.Score.Grade, $h.Score.Score, $hf.Count, @($h.NotEvaluated).Count)
}
Write-Host ("Findings: {0} ({1} Critical, {2} High, {3} Medium, {4} Low){5}" -f $active.Count,
    @($active | Where-Object { $_.Severity -eq 'Critical' }).Count, @($active | Where-Object { $_.Severity -eq 'High' }).Count,
    @($active | Where-Object { $_.Severity -eq 'Medium' }).Count, @($active | Where-Object { $_.Severity -eq 'Low' }).Count,
    $(if (@($split.Accepted).Count) { ", $(@($split.Accepted).Count) accepted" } else { '' }))
Write-Host "Report:   $OutHtml"
Write-Host "Findings: $OutCsv"
foreach ($pf in $perHostFiles) { Write-Host "Host:     $pf" }
if ($OutJsonl) { Write-Host "SIEM:     $OutJsonl" }
if ($remInfo) {
    foreach ($ri in $remInfo) { if ($ri.File) { Write-Host ("Fix:      {0}  ({1} setting(s) for {2} of {3} finding(s))" -f (Join-Path $remDir $ri.File), $ri.Actions, $ri.Fixable, $ri.Total) } }
    Write-Host "          Preview first (it changes nothing without -Apply), try it on a pilot host, then -Apply; -Restore <rollback file> -Apply undoes it." -ForegroundColor DarkGray
}

# --------------------------------------------------------------------------
# Optional AI step. The report is already on disk by now; without -SendToAI or
# -AiDryRun nothing below runs, and HostBadger never asks.
# --------------------------------------------------------------------------
if (-not $SendToAI -and -not $AiDryRun) { return }
# The DISA STIG findings can be hundreds per host. They go to Gemini only if asked for (-AiIncludeStig):
# a prompt that large can make the request time out.
$aiFindings = if ($AiIncludeStig) { $active } else { @($active | Where-Object { $_.Category -ne 'DISA STIG' }) }
$stigLeftOut = $active.Count - $aiFindings.Count
if ($stigLeftOut -gt 0) { Write-Host "AI: $stigLeftOut DISA STIG finding(s) are not part of the prompt (add -AiIncludeStig to send them; a very large prompt may time out)." -ForegroundColor DarkGray }
if ($AiIncludeStig -and @($active | Where-Object { $_.Category -eq 'DISA STIG' }).Count -gt 0) { Write-Host 'AI: DISA STIG findings included; with this many findings Gemini may time out.' -ForegroundColor Yellow }
if ($aiFindings.Count -eq 0) { Write-Host 'No findings: AI step skipped (nothing to ground a summary on).'; return }

$hostOrder = @($hosts | Sort-Object { $_.Score.Score }, Name | ForEach-Object { $_.Name })
Step-Spinner 'Replacing names with tokens'
$pz = New-HostPseudonymizer -Snapshots @($latest.Values) -Findings $aiFindings -HostOrder $hostOrder
Step-Spinner 'Building the AI prompt'
$userPrompt = New-AiPrompt -Findings $aiFindings -Hosts $hosts.ToArray() -Pz $pz -Comparison $comparison
Stop-Spinner
$leaks = @(Test-AiLeak -Pz $pz -Text $userPrompt)
if ($leaks.Count -gt 0) {
    Write-Host "AI step aborted: identifiers still present after pseudonymization: $($leaks -join ', '). Nothing was sent. Please report this as a bug." -ForegroundColor Red
    return
}
$maskedCount = $pz.Reverse.Count

if ($AiDryRun) {
    Write-AiPromptFile -Path $AiDryRun -UserPrompt $userPrompt
    Write-Host "AI dry run: prompt written to $AiDryRun ($($userPrompt.Length) chars, $maskedCount identifiers pseudonymized). Nothing sent." -ForegroundColor Cyan
    return
}

# Written before sending, so it can be read first (and kept as the record of what left).
$promptFile = Get-AiSidecarPath $htmlFull '_ai_prompt.txt'
Write-AiPromptFile -Path $promptFile -UserPrompt $userPrompt
if ($AiConfirm) {
    Write-Host ''
    Write-Host "Optional AI step (Gemini, model $Model):" -ForegroundColor Cyan
    Write-Host "  Sent: $($aiFindings.Count) findings grouped by check (max 12 lines per check), host table, coverage gaps, comparison if any."
    Write-Host "  Pseudonymized: $maskedCount identifiers (hosts, domains, accounts, groups, SIDs, paths, service/task/autorun/adapter names, addresses). The map never leaves this machine."
    Write-Host "  Not sent: the snapshots, ACL dumps, collector error messages."
    Write-Host "  Exactly what would be sent: $promptFile" -ForegroundColor Cyan
    $answer = Read-Host 'Open that file if you want, then: send to Gemini for an executive summary and remediation plan? (y/N)'
    if ($answer -notmatch '^[Yy]') { Write-Host "Nothing sent. Deterministic report saved to $OutHtml."; return }
}
else { Write-Host "AI prompt kept at $promptFile ($maskedCount identifiers pseudonymized)" }
if (-not $ApiKey) { Write-Host 'ERROR: no API key (-ApiKey or GEMINI_API_KEY). Deterministic report kept as is.' -ForegroundColor Red; return }

$raw = Invoke-GeminiAnalysis -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model -MaxAttempts $AiMaxAttempts
if (-not $raw) { Write-Host "AI step failed; deterministic report kept at $OutHtml." -ForegroundColor Yellow; return }
$responseFile = Get-AiSidecarPath $htmlFull '_ai_response.json'
Write-AiResponseFile -Path $responseFile -Raw $raw
Write-Host "Gemini reply (still pseudonymized) kept at $responseFile"
$aiResult = ConvertFrom-AiResponse -Raw $raw -Pz $pz -Findings $aiFindings -Model $Model

$html = ConvertTo-ReportHtml -Hosts $hosts.ToArray() -Split $split -Comparison $comparison -Config $config -ToolVersion $script:HostBadgerVersion -ElapsedText $elapsedText -AiResult $aiResult -Remediation $remInfo -HideCis:$HideCis -HideStig:$HideStig -KevLoaded:([bool]$config.Kev)
[System.IO.File]::WriteAllText($htmlFull, $html, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "AI section added to $OutHtml ($(@($aiResult.RemediationPlan).Count) remediation items)." -ForegroundColor Green
