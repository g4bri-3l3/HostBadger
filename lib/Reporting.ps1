# HostBadger reporting: the HTML report, the findings CSV, JSON Lines for a SIEM, and the comparison
# with a previous run. One report covers one host or a whole fleet.

function Export-FindingsCsv {
    param($Findings, [string]$Path)
    $rows = @($Findings | Select-Object Severity, Type, Title, Category, Host, Object, Detail, Mitre, Cis, CisBenchmark, Found, Expected, Attacks)
    if ($rows.Count -eq 0) {
        # Keep the header, so that -CompareTo still works against a clean run.
        'Severity,Type,Title,Category,Host,Object,Detail,Mitre,Cis,CisBenchmark,Found,Expected,Attacks' | Set-Content -LiteralPath $Path -Encoding UTF8
        return
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Get-FindingKey {
    param($Finding)
    return "$($Finding.Type)|$($Finding.Host)|$($Finding.Object)".ToLower()
}

function Get-FindingId {
    # The same check on the same host and object gets the same id in every run.
    param($Finding)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-FindingKey $Finding)))
        return (-join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') }))
    }
    finally { $sha.Dispose() }
}

function Get-FindingsComparison {
    param($Findings, [string]$PreviousCsv)
    $prev = @(Import-Csv -LiteralPath $PreviousCsv)
    $prevMap = @{}; foreach ($p in $prev) { $prevMap[(Get-FindingKey $p)] = $p }
    $curMap = @{}; foreach ($c in $Findings) { $curMap[(Get-FindingKey $c)] = $c }
    # A host that is missing from this run isn't "resolved". It just wasn't collected.
    $hostsNow = @{}; foreach ($c in $Findings) { $hostsNow["$($c.Host)".ToLower()] = $true }
    foreach ($h in $script:RunHosts) { $hostsNow["$h".ToLower()] = $true }
    return [PSCustomObject]@{
        New          = @($Findings | Where-Object { -not $prevMap.ContainsKey((Get-FindingKey $_)) })
        Resolved     = @($prev | Where-Object { -not $curMap.ContainsKey((Get-FindingKey $_)) -and $hostsNow.ContainsKey("$($_.Host)".ToLower()) })
        Persisting   = @($Findings | Where-Object { $prevMap.ContainsKey((Get-FindingKey $_)) })
        PreviousPath = $PreviousCsv
    }
}

# One JSON object per line, for any SIEM. The event_type is finding, resolved, or host_summary (one
# per host, with the score, the counts and the checks not evaluated). SIEM searches depend on these
# fields, so add fields but never rename or remove them.
$script:SeverityScore = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

function Export-FindingsJsonl {
    param($Findings, $Hosts, [string]$Path, [string]$ToolVersion, $Comparison = $null)
    $sb = New-Object System.Text.StringBuilder
    $byHost = @{}; foreach ($h in $Hosts) { $byHost[$h.Name.ToLower()] = $h }
    $newKeys = @{}
    if ($Comparison) { foreach ($n in @($Comparison.New)) { $newKeys[(Get-FindingKey $n)] = $true } }
    $base = {
        param([string]$EventType, [string]$HostName)
        $h = $byHost["$HostName".ToLower()]
        [ordered]@{
            time         = $(if ($h) { $h.CollectedUtc.ToString('o') } else { $null })
            event_type   = $EventType
            run_id       = $(if ($h) { "$($h.Name)-$($h.CollectedUtc.ToString('yyyyMMddHHmmss'))" } else { $null })
            tool         = 'HostBadger'
            tool_version = $ToolVersion
            host         = $HostName
            host_role    = $(if ($h) { $h.Role } else { $null })
        }
    }
    foreach ($f in $Findings) {
        $o = & $base 'finding' $f.Host
        $o['severity'] = $f.Severity
        $o['severity_score'] = $script:SeverityScore[$f.Severity]
        $o['check'] = $f.Type
        $o['title'] = $f.Title
        $o['category'] = $f.Category
        $o['object'] = $f.Object
        $o['detail'] = $f.Detail
        $o['mitre'] = $f.Mitre
        $o['cis'] = $f.Cis
        $o['cis_benchmark'] = $(if ($f.CisBenchmark) { $f.CisBenchmark } else { $null })
        # The value on the host and the value the framework requires (CIS or STIG), when the check knows them.
        $o['found'] = $(if ($f.Found) { $f.Found } else { $null })
        $o['expected'] = $(if ($f.Expected) { $f.Expected } else { $null })
        $o['fix_available'] = [bool]($script:FixTypes -and $script:FixTypes.ContainsKey($f.Type))
        $o['finding_id'] = Get-FindingId $f
        $o['status'] = $(if (-not $Comparison) { $null } elseif ($newKeys.ContainsKey((Get-FindingKey $f))) { 'new' } else { 'persisting' })
        # What an attacker can do with it (the check's "Attacks it enables").
        $o['attacks'] = $(if ($f.Attacks) { $f.Attacks } else { $null })
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    if ($Comparison) {
        foreach ($r in @($Comparison.Resolved)) {
            $o = & $base 'resolved' $r.Host
            $o['severity'] = $r.Severity
            $o['severity_score'] = $script:SeverityScore["$($r.Severity)"]
            $o['check'] = $r.Type
            $o['title'] = $r.Title
            $o['object'] = $r.Object
            $o['finding_id'] = Get-FindingId $r
            $o['status'] = 'resolved'
            [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
        }
    }
    foreach ($h in $Hosts) {
        $o = & $base 'host_summary' $h.Name
        $hf = @($Findings | Where-Object { $_.Host -eq $h.Name })
        $o['score'] = $h.Score.Score
        $o['grade'] = $h.Score.Grade
        $o['os'] = $h.Os
        $o['findings'] = $hf.Count
        foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $o[$s.ToLower()] = @($hf | Where-Object { $_.Severity -eq $s }).Count }
        $o['not_evaluated'] = @($h.NotEvaluated).Count
        $o['not_evaluated_checks'] = [string[]]@($h.NotEvaluated | ForEach-Object { $_.Type })
        $o['collected_as_system'] = $h.AsSystem
        # The EDR agents found among the services, as name:state (empty list if none, null if the services were not collected).
        $o['edr'] = $(if ($h.EdrKnown) { [string[]]@(@($h.Edr) | ForEach-Object { "$($_.Name):$($_.State)" }) } else { $null })
        # Essential Eight maturity level per strategy from what the host shows (null: not visible from a
        # host or not applicable); e8_capped lists the strategies where the next level could not be judged.
        if ($h.E8) {
            $lv = [ordered]@{}; foreach ($k in $h.E8.Keys) { $lv[$k] = $h.E8[$k].Level }
            $o['e8_levels'] = $lv
            $o['e8_capped'] = [string[]]@($h.E8.Keys | Where-Object { $h.E8[$_].Capped })
        }
        [void]$sb.AppendLine(($o | ConvertTo-Json -Compress -Depth 3))
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-SevPill {
    param([string]$Severity)
    return "<span class=`"sev-pill sev-pill-$($Severity.ToLower())`">$Severity</span>"
}

function Get-MitreLink {
    param([string]$Id)
    if (-not $Id) { return '' }
    return "<a href=`"https://attack.mitre.org/techniques/$($Id -replace '\.', '/')/`" target=`"_blank`" rel=`"noopener`">$Id</a>"
}

$script:BadgerAscii = @'
     _.--""--._
   .'  |    |  '.
  /    |    |    \
 |  (o)|    |(o)  |
 |     |    |     |
  \    '.__.'    /
   '._   \/   _.'
      '--..--'
'@

# Keycap palette: an ink ramp for categories (three warm/cool accents at the end for 12-way
# spread), and the keycap red / coral / amber / tint for severity.
$script:BadgerCategoryRamp = @('#161513', '#2B2925', '#45413A', '#5F5A51', '#78726A', '#8F887C', '#ABA497', '#C6BFB0', '#DDD6C8', '#8A6E4B', '#5E7384', '#9AA39C')
$script:BadgerSeverityColors = @('#E2372A', '#EF8A6F', '#F2B632', '#B9B1A1')

function Get-SvgPieChart {
    param([string[]]$Labels, [int[]]$Values, [string[]]$Colors, [int]$Size = 130, [string]$CenterLabel = '')
    $total = ($Values | Measure-Object -Sum).Sum
    if ($total -le 0) { return "<p class='meta'>No data.</p>" }
    $cx = $Size / 2; $cy = $Size / 2
    $strokeWidth = [Math]::Round($Size * 0.13, 1)
    $r = ($Size / 2) - ($strokeWidth / 2) - 1
    $circ = [Math]::Round(2 * [Math]::PI * $r, 2)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $rings = "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='#E7E3D8' stroke-width='$($strokeWidth.ToString($inv))' />"
    $legend = ''; $cum = 0
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $v = $Values[$i]
        if ($v -le 0) { continue }
        $seg = [Math]::Round(($v / $total) * $circ, 2)
        $off = [Math]::Round(-1 * $cum, 2)
        $rings += "<circle cx='$cx' cy='$cy' r='$($r.ToString($inv))' fill='none' stroke='$($Colors[$i % $Colors.Count])' stroke-width='$($strokeWidth.ToString($inv))' stroke-dasharray='$($seg.ToString($inv)) $($circ.ToString($inv))' stroke-dashoffset='$($off.ToString($inv))'><title>$(ConvertTo-HtmlSafe $Labels[$i]): $v</title></circle>"
        $cum += $seg
        $pct = [Math]::Round(($v / $total) * 100, 1).ToString($inv)
        $legend += "<div class='pie-legend-item'><span class='pie-legend-swatch' style='background:$($Colors[$i % $Colors.Count])'></span>$(ConvertTo-HtmlSafe $Labels[$i]) ($v, $pct%)</div>"
    }
    $svg = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size' role='img'><g transform='rotate(-90 $cx $cy)'>$rings</g><text x='$cx' y='$($cy - 2)' text-anchor='middle' font-size='20' font-weight='600' fill='#23211C'>$total</text><text x='$cx' y='$($cy + 14)' text-anchor='middle' font-size='9' fill='#5F5A4F'>$CenterLabel</text></svg>"
    return "<div class='pie-chart-wrap'>$svg<div class='pie-legend'>$legend</div></div>"
}

function Get-ComplianceStats {
    # STIG: rules judged on the hosts against the STIG findings. CIS: the CIS-based checks that apply to
    # a host (its role, and evaluated) against the ones that fired. A check can cover several CIS rules,
    # so this counts checks, not benchmark rules.
    param($Hosts, $Findings)
    $stigEval = 0; foreach ($hostItem in @($Hosts)) { $stigEval += [int]$hostItem.StigEvaluated }
    $stigFail = [Math]::Min($stigEval, @($Findings | Where-Object { $_.Category -eq 'DISA STIG' }).Count)
    $typesByHost = @{}
    foreach ($f in @($Findings)) { if (-not $typesByHost.ContainsKey("$($f.Host)")) { $typesByHost["$($f.Host)"] = @{} }; $typesByHost["$($f.Host)"]["$($f.Type)"] = $true }
    $cisApplicable = 0; $cisFail = 0
    foreach ($hostItem in @($Hosts)) {
        $ne = @{}; foreach ($n in @($hostItem.NotEvaluated | Where-Object { $_ })) { $ne["$($n.Type)"] = $true }
        $fired = $typesByHost["$($hostItem.Name)"]
        foreach ($t in $script:CheckCatalog.Keys) {
            $m = $script:CheckCatalog[$t]
            if (-not ($m.Cis -or $m.CisServer)) { continue }
            if ("$($hostItem.Role)" -ne 'unknown' -and $m.Roles -notcontains "$($hostItem.Role)") { continue }
            if ($ne.ContainsKey($t)) { continue }
            $cisApplicable++
            if ($fired -and $fired.ContainsKey($t)) { $cisFail++ }
        }
    }
    return [PSCustomObject]@{ StigEvaluated = $stigEval; StigFailed = $stigFail; CisApplicable = $cisApplicable; CisFailed = $cisFail }
}

function Get-RingSvg {
    # A score ring: the share of the circle that is done, the big number and a small label under it.
    # GoodAt / MidAt: where the ring turns green and amber (the score ring follows the grades).
    param([double]$Percent, [string]$Big, [string]$Small = '', [int]$Size = 120, [double]$GoodAt = 80, [double]$MidAt = 50)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $pct = [Math]::Max(0, [Math]::Min(100, $Percent))
    $color = if ($pct -ge $GoodAt) { '#6E8B5F' } elseif ($pct -ge $MidAt) { '#F2B632' } else { '#E2372A' }
    $sw = [Math]::Round($Size * 0.11, 1); $r = ($Size / 2) - ($sw / 2) - 2; $c = $Size / 2
    $circ = 2 * [Math]::PI * $r; $dash = $circ * $pct / 100
    return "<svg class='ring' viewBox='0 0 $Size $Size' width='$Size' height='$Size' role='img' aria-label='$(ConvertTo-HtmlSafe "$Big $Small")'>" +
    "<circle cx='$c' cy='$c' r='$($r.ToString($inv))' fill='none' stroke='#E7E3D8' stroke-width='$($sw.ToString($inv))'/>" +
    "<circle cx='$c' cy='$c' r='$($r.ToString($inv))' fill='none' stroke='$color' stroke-width='$($sw.ToString($inv))' stroke-linecap='round' stroke-dasharray='$($dash.ToString('0.##', $inv)) $($circ.ToString('0.##', $inv))' transform='rotate(-90 $c $c)'/>" +
    "<text x='$c' y='$($c + 2)' text-anchor='middle' font-size='$([int]($Size * 0.24))' font-weight='800' fill='#161513' font-family='Bahnschrift, Segoe UI, sans-serif'>$(ConvertTo-HtmlSafe $Big)</text>" +
    "<text x='$c' y='$($c + [int]($Size * 0.19))' text-anchor='middle' font-size='$([int]($Size * 0.09))' fill='#5F5A51' font-family='Cascadia Mono, Consolas, monospace'>$(ConvertTo-HtmlSafe $Small)</text></svg>"
}

function Get-DashBar {
    # A bar for a share done, coloured like the rings.
    param([double]$Percent)
    $cls = if ($Percent -ge 80) { '' } elseif ($Percent -ge 50) { ' class=''mid''' } else { ' class=''low''' }
    return "<span$cls style='width:$([int][Math]::Max(1, $Percent))%'></span>"
}

function Get-DashboardHtml {
    # One dashboard for a set of hosts (the fleet, or one host): the score, DISA STIG compliance by
    # product, CIS-based compliance, the Essential Eight strategies, the categories and the top risks.
    # $All: every active finding of these hosts (compliance counts hidden ones too); $Shown: what the
    # report lists.
    param($Hosts, $All, $Shown, [string]$Title)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    $hostsArr = @($Hosts)
    $scores = @($hostsArr | ForEach-Object { [int]$_.Score.Score })
    $avg = if ($scores.Count) { [int][Math]::Round(($scores | Measure-Object -Average).Average) } else { 0 }
    $grade = if ($hostsArr.Count -eq 1) { "$($hostsArr[0].Score.Grade)" } else { '' }
    $sev = @('Critical', 'High', 'Medium', 'Low'); $cnt = @{}; foreach ($s in $sev) { $cnt[$s] = @($Shown | Where-Object { $_.Severity -eq $s }).Count }
    $fixable = @($All | Where-Object { $script:FixTypes -and $script:FixTypes.ContainsKey("$($_.Type)") }).Count
    $comp = Get-ComplianceStats -Hosts $hostsArr -Findings $All
    $fired = @{}; foreach ($f in @($All)) { $fired["$($f.Host)|$($f.Type)"] = $true }
    # The verdict follows the grades (Get-HostScore): A-B good, C-D partial, E-F weak.
    $verdict = if ($avg -ge 70) { 'Good protection' } elseif ($avg -ge 40) { 'Partial protection' } else { 'Weak protection' }

    # Score panel.
    & $w "<div class='dash-hero'>$(Get-RingSvg -Percent $avg -Big "$avg" -Small '/ 100' -Size 150 -GoodAt 70 -MidAt 40)<div class='dash-hero-text'>"
    & $w "<div class='dash-kicker'>$(& $H $Title)</div><div class='dash-big'>Hardening score$(if ($grade) { " &middot; grade $(& $H $grade)" })</div>"
    & $w "<div class='dash-verdict v$([int]($avg -ge 70) + [int]($avg -ge 40))'>$verdict</div>"
    & $w "<div class='dash-sevs'>$(($sev | ForEach-Object { "<span class='sev-pill sev-pill-$($_.ToLower())'>$($cnt[$_]) $_</span>" }) -join ' ')</div>"
    & $w "<div class='meta'>Exposure checks only: the DISA STIG rules have their own panel below.</div>"
    & $w "<div class='meta'>$(@($Shown).Count) finding(s) on $($hostsArr.Count) host(s) &middot; $fixable with a reversible fix script &middot; <a href='#' onclick=""hbTab('details'); return false;"">open the details</a></div>"
    & $w '</div></div>'

    & $w "<div class='dash-grid'>"
    # DISA STIG by product.
    $stigTypes = @($script:StigTypeLabel.Keys | Where-Object { $t = $_; ($hostsArr | ForEach-Object { [int]$_.StigByType[$t] } | Measure-Object -Sum).Sum -gt 0 })
    if ($comp.StigEvaluated -gt 0) {
        $okS = $comp.StigEvaluated - $comp.StigFailed; $pS = 100 * $okS / $comp.StigEvaluated
        & $w "<div class='dash-panel'><div class='dash-panel-head'>$(Get-RingSvg -Percent $pS -Big "$([int][Math]::Round($pS))%" -Small 'compliant')<div><div class='dash-panel-title'>DISA STIG</div><div class='meta'>$okS of $($comp.StigEvaluated) registry rules met; $($comp.StigEvaluated - $okS) not met, one finding each (the DISA STIG count in the summary by framework)</div></div></div><table class='dash-table'>"
        foreach ($t in $stigTypes) {
            $ev = ($hostsArr | ForEach-Object { [int]$_.StigByType[$t] } | Measure-Object -Sum).Sum
            $bad = [Math]::Min($ev, @($All | Where-Object { $_.Type -eq $t }).Count)
            & $w "<tr><td>$(& $H $script:StigTypeLabel[$t])</td><td class='num'>$($ev - $bad)/$ev</td><td class='bar'>$(Get-DashBar (100 * ($ev - $bad) / [Math]::Max(1, $ev)))</td></tr>"
        }
        & $w '</table></div>'
    }
    else { & $w "<div class='dash-panel'><div class='dash-panel-title'>DISA STIG</div><p class='meta'>Not judged (no STIG rules on these hosts, or -SkipStig).</p></div>" }
    # CIS.
    if ($comp.CisApplicable -gt 0) {
        $okC = $comp.CisApplicable - $comp.CisFailed; $pC = 100 * $okC / $comp.CisApplicable
        # Each benchmark with how many findings quote it. A check that follows a rule only the Windows
        # Server benchmarks have (mDNS, 18.6.4.1) quotes Server 2022 on a workstation too: say so.
        $roleOf = @{}; foreach ($hx in $hostsArr) { $roleOf["$($hx.Name)"] = "$($hx.Role)" }
        $benches = @($All | Where-Object { $_.CisBenchmark } | Group-Object CisBenchmark | Sort-Object Count -Descending | ForEach-Object { "$("$($_.Name)" -replace '^CIS Microsoft ', '' -replace ' Benchmark', '') ($($_.Count))" })
        $srvOnWks = @($All | Where-Object { "$($_.CisBenchmark)" -match 'Windows Server' -and $roleOf["$($_.Host)"] -eq 'workstation' } | ForEach-Object { $_.Type } | Select-Object -Unique)
        if ($srvOnWks.Count) { $benches += "on workstations, $($srvOnWks -join ', ') follow$(if ($srvOnWks.Count -eq 1) { 's' }) a rule that only the Windows Server benchmarks have, so the Server rule number is quoted" }
        & $w "<div class='dash-panel'><div class='dash-panel-head'>$(Get-RingSvg -Percent $pC -Big "$([int][Math]::Round($pC))%" -Small 'clean')<div><div class='dash-panel-title'>CIS benchmarks</div><div class='meta'>$okC of $($comp.CisApplicable) CIS-based checks clean</div></div></div>"
        if ($benches.Count) { & $w "<p class='meta'>Rules quoted from (findings): $(& $H ($benches -join '; '))</p>" }
        # The CIS-based checks that fired, with the rules they quote.
        $cisBad = @($All | Where-Object { $_.Cis } | Group-Object Type | ForEach-Object {
                $ws = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
                [PSCustomObject]@{ Type = $_.Name; Worst = $ws; Rank = $script:SeverityRank[$ws]; Count = $_.Count; Hosts = @($_.Group | ForEach-Object { $_.Host } | Select-Object -Unique).Count; Rules = @($_.Group | ForEach-Object { "$($_.Cis)" -split ',\s*' } | Where-Object { $_ } | Sort-Object -Unique) }
            } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = 'Count'; Descending = $true })
        if ($cisBad.Count) {
            $li = @($cisBad | ForEach-Object { "<li>$(Get-SevPill $_.Worst) $(& $H $script:CheckCatalog[$_.Type].Title) <span class='meta'>CIS $(& $H (@($_.Rules | Select-Object -First 4) -join ', '))$(if ($_.Rules.Count -gt 4) { ' ...' }) &middot; $($_.Count) finding(s) on $($_.Hosts) host(s)</span></li>" })
            & $w "<details class='dash-more'><summary>Checks not clean ($($cisBad.Count))</summary><ul class='dash-list'>$($li -join '')</ul></details>"
        }
        & $w '</div>'
    }
    # Essential Eight: the maturity level each strategy reaches from the requirements a host shows
    # (Get-E8Maturity, per host); for several hosts, the lowest. Each strategy opens on the
    # requirements not met and not judged, in the ASD wording, with the checks behind them.
    $e8Rows = @(); $e8Met = 0; $e8Judged = 0; $overall = $null; $overallCapped = $false
    foreach ($k in $script:E8Strategies.Keys) {
        $st = $script:E8Strategies[$k]
        $per = @($hostsArr | Where-Object { $_.E8 } | ForEach-Object { $_.E8[$k] } | Where-Object { $_ })
        $levels = @($per | Where-Object { $null -ne $_.Level })
        $label = & $H $st.Label
        if ($levels.Count -eq 0) {
            $why = if (@($per | Where-Object { $_.NotApplicable }).Count -gt 0 -and $k -eq 'macros') { 'not applicable (no Microsoft Office)' } elseif ($st.Note) { $st.Note } else { 'not applicable' }
            $e8Rows += "<tr><td>$label</td><td class='num' colspan='2'>$(& $H $why)</td></tr>"
            continue
        }
        $minL = ($levels | ForEach-Object { [int]$_.Level } | Measure-Object -Minimum).Minimum
        $capped = @($levels | Where-Object { [int]$_.Level -eq $minL -and $_.Capped }).Count -gt 0
        if ($null -eq $overall -or $minL -lt $overall) { $overall = $minL; $overallCapped = $capped } elseif ($minL -eq $overall -and $capped) { $overallCapped = $true }
        # Requirements across the hosts: how many hosts miss each one, or could not be judged.
        $byReq = [ordered]@{}
        foreach ($p in $per) {
            foreach ($rq in @($p.Requirements | Where-Object { $_.State -ne 'na' })) {
                if (-not $byReq.Contains($rq.Req)) { $byReq[$rq.Req] = [PSCustomObject]@{ Row = $rq; Unmet = 0; Unknown = 0; Met = 0 } }
                $e8Judged++
                switch ($rq.State) { 'unmet' { $byReq[$rq.Req].Unmet++ } 'unknown' { $byReq[$rq.Req].Unknown++ } default { $byReq[$rq.Req].Met++; $e8Met++ } }
            }
        }
        $items = @()
        foreach ($b in @($byReq.Values | Sort-Object { $_.Row.Level })) {
            if ($b.Unmet -eq 0 -and $b.Unknown -eq 0) { continue }
            $titles = (@($b.Row.Checks | Where-Object { $script:CheckCatalog.Contains($_) } | ForEach-Object { $script:CheckCatalog[$_].Title }) -join '; ')
            $state = if ($b.Unmet) { "not met on $($b.Unmet) host(s)" } else { "not judged on $($b.Unknown) host(s)" }
            $items += "<li><span class='e8-ml'>ML$($b.Row.Level)</span> $(& $H $b.Row.Req) <span class='meta'>$state &middot; $(& $H $titles)$(if ($b.Row.Note) { " &middot; $(& $H $b.Row.Note)" })</span></li>"
        }
        $metCount = @($byReq.Values | Where-Object { $_.Unmet -eq 0 -and $_.Unknown -eq 0 }).Count
        if ($metCount) { $items += "<li class='meta'>$metCount requirement(s) met on every host.</li>" }
        $label = "<details class='dash-more'><summary>$label <span class='meta'>($($byReq.Count) requirement(s) judged)</span></summary><ul class='dash-list'>$($items -join '')</ul></details>"
        $mlText = "ML$minL$(if ($capped) { '+?' })"
        $e8Rows += "<tr><td>$label</td><td class='num' title='$(if ($capped) { 'a requirement of the next level could not be judged' } else { 'maturity level from what a host shows' })'>$mlText</td><td class='bar'>$(Get-DashBar (100 * $minL / 3))</td></tr>"
    }
    if ($e8Judged -gt 0) {
        $pE = 100 * $e8Met / $e8Judged
        & $w "<div class='dash-panel'><div class='dash-panel-head'>$(Get-RingSvg -Percent $pE -Big "ML$overall" -Small 'from a host')<div><div class='dash-panel-title'>ACSC Essential Eight</div><div class='meta'>Maturity levels from the requirements a host shows (ASD model, November 2023): $e8Met of $e8Judged met$(if ($hostsArr.Count -gt 1) { ', lowest host per strategy' }). Multi-factor authentication, backups, central logging and scanning cadence need evidence a host does not hold, so this is an upper bound, not an assessment.$(if ($overallCapped) { ' ML<n>+? means a requirement of the next level could not be judged.' })</div></div></div><table class='dash-table'>$($e8Rows -join '')</table></div>"
    }
    & $w '</div>'

    # Categories.
    & $w "<h3 class='dash-h'>Hardening categories</h3><div class='dash-cats'>"
    foreach ($cat in @($script:CheckCatalog.Values | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)) {
        $fs = @($Shown | Where-Object { $_.Category -eq $cat })
        $worst = if ($fs.Count) { ($fs | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity } else { '' }
        $checks = @($fs | ForEach-Object { $_.Type } | Select-Object -Unique).Count
        & $w "<div class='dash-cat$(if (-not $fs.Count) { ' clean' })'><div class='dash-cat-name'>$(& $H $cat)</div><div class='dash-cat-num'>$($fs.Count)</div><div class='meta'>$(if ($fs.Count) { "$checks check(s) &middot; worst $(Get-SevPill $worst)" } else { 'clean' })</div></div>"
    }
    & $w '</div>'

    # Top risks: the checks with the worst severity, then the most hosts.
    $top = @($Shown | Group-Object Type | ForEach-Object {
            $w0 = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $w0; Rank = $script:SeverityRank[$w0]; Hosts = @($_.Group | ForEach-Object { $_.Host } | Select-Object -Unique).Count; Count = $_.Count }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = 'Hosts'; Descending = $true }, @{ Expression = 'Count'; Descending = $true } | Select-Object -First 6)
    if ($top.Count) {
        & $w "<h3 class='dash-h'>Top risks</h3><div class='dash-risks'>"
        foreach ($t in $top) {
            $m = $script:CheckCatalog[$t.Type]
            & $w "<div class='dash-risk'><div>$(Get-SevPill $t.Worst) <span class='check-title'>$(& $H $m.Title)</span></div><div class='dash-risk-attack'>$(& $H $m.Attacks)</div><div class='meta'>$($t.Count) finding(s) on $($t.Hosts) host(s)$(if ($script:FixTypes -and $script:FixTypes.ContainsKey($t.Type)) { ' &middot; fix script available' })</div></div>"
        }
        & $w '</div>'
    }
    return $sb.ToString()
}

function ConvertTo-ReportHtml {
    param($Hosts, $Split, $Comparison, [hashtable]$Config, [string]$ToolVersion, [string]$ElapsedText, $AiResult = $null, $Remediation = $null, [switch]$HideCis, [switch]$HideStig, [switch]$KevLoaded)
    $H = { param($t) ConvertTo-HtmlSafe "$t" }
    # Compliance is computed on everything; hiding only changes what the report lists.
    $compliance = Get-ComplianceStats -Hosts $Hosts -Findings @($Split.Active)
    $findings = @($Split.Active)
    $hiddenCis = 0; $hiddenStig = 0
    $hideTypes = @()
    if ($HideCis) {
        $hiddenCis = @($findings | Where-Object { $_.Cis }).Count
        $findings = @($findings | Where-Object { -not $_.Cis })
        $hideTypes += @($script:CheckCatalog.Keys | Where-Object { $script:CheckCatalog[$_].Cis -or $script:CheckCatalog[$_].CisServer })
    }
    if ($HideStig) {
        $hiddenStig = @($findings | Where-Object { $_.Category -eq 'DISA STIG' }).Count
        $findings = @($findings | Where-Object { $_.Category -ne 'DISA STIG' })
        $hideTypes += @($script:CheckCatalog.Keys | Where-Object { $_ -like 'stig_*' })
    }
    if ($hideTypes.Count -gt 0) {
        $Hosts = @($Hosts | ForEach-Object {
                $copy = New-Object PSObject
                foreach ($p in $_.PSObject.Properties) { Add-Member -InputObject $copy -NotePropertyName $p.Name -NotePropertyValue $p.Value }
                $copy.NotEvaluated = @($_.NotEvaluated | Where-Object { $_ -and $hideTypes -notcontains $_.Type })
                $copy
            })
    }
    $sb = New-Object System.Text.StringBuilder
    $w = { param($t) [void]$sb.AppendLine($t) }
    $sevOrder = @('Critical', 'High', 'Medium', 'Low')
    $counts = @{}; foreach ($s in $sevOrder) { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
    $single = @($Hosts).Count -eq 1
    # Not $h: PowerShell names are case-insensitive, and $H is the encoder.
    $hostRoles = @{}; foreach ($hostItem in $Hosts) { $hostRoles["$($hostItem.Name)"] = "$($hostItem.Role)" }
    $titleTarget = if ($single) { $Hosts[0].Name } else { "$(@($Hosts).Count) hosts" }

    & $w '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<title>HostBadger report - $(& $H $titleTarget)</title>"
    & $w @'
<style>
  /* "Keycap" theme: paper, ink, hard shadows. Self-contained: system font stacks, no web fonts. */
  :root {
    --paper: #F3EFE6; --surface: #FFFDF8; --tint: #E8E2D4; --ink: #161513; --muted: #5F5A51;
    --red: #E2372A; --red-soft: #FBD9D2; --coral: #EF8A6F; --amber: #F2B632; --amber-soft: #FBE7B5; --green: #84CC5F;
    --line: 3px solid var(--ink);
    --shadow: 7px 7px 0 var(--ink); --shadow-sm: 4px 4px 0 var(--ink); --shadow-xs: 3px 3px 0 var(--ink);
    --display: "Bahnschrift", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
    --body: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif;
    --mono: "Cascadia Mono", "Cascadia Code", Consolas, ui-monospace, monospace;
    /* Semantic aliases used by the report code and the charts. */
    --critical: var(--red); --slate: var(--ink); --accent: var(--muted);
    --required: #3F6B3A;
  }
  body {
    max-width: 1240px; margin: 0 auto; padding: 28px 24px 64px; color: var(--ink); line-height: 1.5;
    font-family: var(--body); font-size: 15px; -webkit-font-smoothing: antialiased;
    background: var(--paper) radial-gradient(circle, rgba(22, 21, 19, .10) 1.1px, transparent 1.5px) 0 0 / 18px 18px;
  }
  @media (max-width: 700px) { body { padding: 16px 16px 40px; } .badger-logo { font-size: 7px; } }
  :focus-visible { outline: 3px solid var(--ink); outline-offset: 3px; }

  h1 {
    font-family: var(--display); font-weight: 800; letter-spacing: -0.04em; line-height: .95; font-size: clamp(1.7rem, 3.4vw, 2.6rem);
    border: var(--line); border-radius: 22px; background: var(--surface); box-shadow: var(--shadow); padding: 20px 24px; margin: 0 0 28px;
  }
  h1.title { display: flex; align-items: center; gap: 22px; }
  .badger-logo {
    font-family: var(--mono); font-size: 10px; line-height: 1.05; font-weight: 700; margin: 0; flex-shrink: 0;
    color: var(--surface); background: var(--ink); border-radius: 14px; padding: 10px 12px; box-shadow: 4px 4px 0 var(--red);
  }
  h2 { margin: 0; font-family: var(--display); font-weight: 750; letter-spacing: -0.03em; font-size: clamp(1.3rem, 2.2vw, 1.8rem); color: var(--ink); }
  h3 { font-family: var(--display); letter-spacing: -0.02em; }
  .meta { font-family: var(--mono); font-size: 12px; line-height: 1.55; letter-spacing: .01em; color: var(--muted); }
  h1 + .meta { text-transform: uppercase; letter-spacing: .06em; font-size: 11.5px; }
  code { background: var(--tint); border: 1.5px solid var(--ink); border-radius: 6px; padding: 0 5px; font-family: var(--mono); font-size: 0.92em; }

  /* Score cards: keys with a hard shadow. */
  .cards { display: flex; flex-wrap: wrap; gap: 18px; margin: 26px 0 30px; clear: both; }
  .card {
    border: var(--line); border-radius: 18px; background: var(--surface); box-shadow: var(--shadow-sm);
    padding: 14px 20px 16px; min-width: 140px; transition: transform .12s ease, box-shadow .12s ease;
  }
  .card:hover { transform: translate(-2px, -2px); box-shadow: 6px 6px 0 var(--ink); }
  .card .num, .grade { font-family: var(--display); font-weight: 800; font-size: 2.4rem; letter-spacing: -0.04em; line-height: 1; color: var(--ink); }
  .card .lbl { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-top: 6px; }
  .card.critical { background: var(--red); } .card.critical .num, .card.critical .lbl { color: var(--surface); }
  .card.high { background: var(--red-soft); } .card.medium { background: var(--amber); } .card.low { background: var(--tint); }

  /* Severity pills as small keycaps. */
  .sev-pill {
    display: inline-block; white-space: nowrap; font-family: var(--mono); font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    border: 2px solid var(--ink); border-radius: 8px; padding: 3px 9px; box-shadow: 2px 2px 0 var(--ink); color: var(--ink);
  }
  .sev-pill-critical { background: var(--red); color: var(--surface); }
  .sev-pill-high { background: var(--red-soft); }
  .sev-pill-medium { background: var(--amber); }
  .sev-pill-low { background: var(--tint); }

  /* Sections and checks: bento panels. */
  details { margin-top: 34px; }
  details > summary { cursor: pointer; list-style: none; border-bottom: var(--line); padding-bottom: 10px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2 { display: inline-block; }
  details > summary::before { content: '\25b6'; display: inline-block; margin-right: 8px; font-size: 14px; color: var(--red); transition: transform .15s ease; }
  details[open] > summary::before { transform: rotate(90deg); }
  details.check {
    margin: 12px 0; border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-xs);
    transition: box-shadow .12s ease, transform .12s ease;
  }
  details.check:hover { transform: translate(-1px, -1px); box-shadow: var(--shadow-sm); }
  details.check[open] { box-shadow: var(--shadow); }
  details.check > summary { border-bottom: none; padding: 12px 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  details.check[open] > summary { border-bottom: var(--line); }
  details.check > summary::before { margin-right: 0; }
  details.check .body { padding: 12px 18px 16px; }
  .check-title { font-family: var(--display); font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; }
  .check-id { font-family: var(--mono); font-size: 11px; letter-spacing: .06em; color: var(--muted); }
  .count { margin-left: auto; font-family: var(--mono); font-size: 11px; letter-spacing: .06em; background: var(--tint); border: 2px solid var(--ink); border-radius: 99px; padding: 1px 10px; }
  .kv { font-size: 13px; margin: 6px 0; }
  .kv b { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); }
  .kv.attacks { border-left: 3px solid var(--red); padding-left: 8px; }
  .kv.attacks b { color: var(--red); }

  /* Tables: ink header, mono labels, framed panel. */
  .table-wrap { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); overflow-x: auto; margin: 14px 0; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-top: 1.5px solid var(--tint); }
  th { background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10.5px; font-weight: 500; letter-spacing: .1em; text-transform: uppercase; padding: 10px 12px; border-top: none; }
  tr.data-row:nth-child(even) td { background: #FAF6EE; }
  tr.data-row:hover td { background: var(--amber-soft); }
  td.found, td.required { font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-word; max-width: 220px; }
  td.found { color: var(--red); }
  td.required { color: var(--required); font-weight: 600; }
  tr.filter-row td { background: var(--tint); padding: 5px 6px; }
  tr.filter-row input { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 11px; padding: 4px 7px; border: 2px solid var(--ink); border-radius: 8px; background: var(--surface); }
  tr.filter-row input:focus { outline: 3px solid var(--red); outline-offset: 1px; }
  .filter-status { font-family: var(--mono); font-size: 11px; color: var(--muted); margin: 6px 0 0 2px; }
  .compare-new { color: var(--red); font-weight: bold; }
  .compare-resolved { color: var(--muted); font-weight: bold; }

  /* Callouts. */
  blockquote { background: var(--surface); border: var(--line); border-left-width: 10px; border-radius: 14px; box-shadow: var(--shadow-xs); margin: 14px 0; padding: 12px 16px; }
  .warn { background: var(--red-soft); border-left-color: var(--red); }

  /* Charts: each one a bento panel. */
  .chart-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 22px; margin: 18px 0; grid-auto-flow: dense; }
  .chart-row > div { border: var(--line); border-radius: 16px; background: var(--surface); box-shadow: var(--shadow-sm); padding: 14px 18px; min-width: 0; }
  .chart-row > div.chart-wide { grid-column: span 2; }
  .chart-wide .pie-legend { columns: 2; column-gap: 28px; }
  .pie-chart-wrap { display: flex; align-items: center; gap: 16px; }
  .pie-chart-wrap svg { flex-shrink: 0; }
  .pie-chart-title { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .pie-legend { font-size: 12px; min-width: 0; }
  .pie-legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; white-space: nowrap; }
  .pie-legend-swatch { display: inline-block; width: 10px; height: 10px; border: 1.5px solid var(--ink); border-radius: 3px; flex-shrink: 0; }

  /* AI section. */
  .ai-section { background: var(--surface); border: var(--line); border-radius: 18px; box-shadow: var(--shadow); padding: 6px 24px 20px; margin-top: 18px; }
  .ai-badge { display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--ink); background: var(--green); border: 2px solid var(--ink); border-radius: 8px; box-shadow: 2px 2px 0 var(--ink); padding: 2px 10px; margin: 12px 0 8px; }
  .ai-section h3 { color: var(--ink); margin: 16px 0 6px; }
  .ai-section ol li { margin: 6px 0; }
  .ai-script { background: var(--ink); color: #ECE7DC; border: var(--line); border-radius: 12px; padding: 10px 12px; font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-x: auto; margin: 6px 0; }
  .ai-triage td { vertical-align: top; }

  /* Remediation fix scripts. */
  details.fix { margin: 12px 0 4px; border: 3px dashed var(--ink); border-radius: 14px; padding: 8px 14px 12px; background: var(--surface); }
  details.fix > summary { font-family: var(--display); font-weight: 700; color: var(--ink); border-bottom: none; padding-bottom: 0; }
  details.fix > summary::before { display: none; }
  .fix-box { position: relative; margin: 8px 0; }
  .fix-code { background: var(--ink); color: #ECE7DC; border: var(--line); border-radius: 12px; padding: 10px 12px; font-family: var(--mono); font-size: 12px; white-space: pre; overflow-x: auto; margin: 0; }
  .fix-box .copy { position: absolute; top: 8px; right: 8px; font-family: var(--mono); font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase; padding: 3px 9px; border: 2px solid var(--surface); border-radius: 8px; background: var(--red); color: var(--surface); cursor: pointer; }

  /* Tabs and dashboard. */
  .tabs { display: flex; gap: 12px; margin: 22px 0 6px; flex-wrap: wrap; align-items: center; }
  .tab-btn { font-family: var(--mono); font-size: 12px; letter-spacing: .1em; text-transform: uppercase; border: var(--line); border-radius: 12px; background: var(--surface); box-shadow: var(--shadow-xs); padding: 8px 16px; cursor: pointer; color: var(--ink); }
  .tab-btn.active { background: var(--ink); color: var(--paper); box-shadow: 3px 3px 0 var(--red); }
  .tabs select { font-family: var(--mono); font-size: 12px; border: var(--line); border-radius: 12px; background: var(--surface); padding: 7px 10px; margin-left: auto; }
  .dash-hero { display: flex; align-items: center; gap: 26px; flex-wrap: wrap; border: var(--line); border-radius: 22px; background: var(--surface); box-shadow: var(--shadow); padding: 20px 26px; margin: 18px 0 24px; }
  .dash-hero-text { flex: 1; min-width: 240px; }
  .dash-kicker { font-family: var(--mono); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
  .dash-big { font-family: var(--display); font-weight: 800; font-size: 1.9rem; letter-spacing: -0.03em; }
  .dash-verdict { font-family: var(--mono); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; display: inline-block; border: 2px solid var(--ink); border-radius: 8px; padding: 2px 10px; margin: 6px 0 10px; background: var(--red); color: var(--surface); }
  .dash-verdict.v1 { background: var(--amber); color: var(--ink); } .dash-verdict.v2 { background: #6E8B5F; color: var(--surface); }
  .dash-sevs { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .dash-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 22px; }
  .dash-panel { border: var(--line); border-radius: 18px; background: var(--surface); box-shadow: var(--shadow-sm); padding: 16px 18px; min-width: 0; }
  .dash-panel-head { display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }
  svg.ring { flex-shrink: 0; }
  .dash-table td.bar span.mid { background: var(--amber); } .dash-table td.bar span.low { background: var(--red); }
  .dash-panel-title { font-family: var(--display); font-weight: 800; font-size: 1.25rem; letter-spacing: -0.02em; }
  .dash-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  details.dash-more { margin-top: 0; }
  details.dash-more > summary { border-bottom: none; padding-bottom: 0; }
  details.dash-more > summary::before { font-size: 10px; margin-right: 6px; }
  .dash-list { margin: 6px 0 4px 16px; padding: 0; font-size: 12px; }
  .dash-list li { margin: 3px 0; }
  .e8-ml { display: inline-block; font-family: var(--mono, monospace); font-size: 10px; font-weight: 700; border: 1.5px solid var(--ink); border-radius: 4px; padding: 0 4px; background: var(--amber); color: var(--ink); }
  .dash-table td { border-top: 1.5px solid var(--tint); padding: 5px 4px; }
  .dash-table td.num { font-family: var(--mono); white-space: nowrap; text-align: right; width: 1%; }
  .dash-table td.bar { width: 34%; }
  .dash-table td.bar span { display: block; height: 9px; border: 1.5px solid var(--ink); border-radius: 6px; background: #6E8B5F; min-width: 2px; }
  .dash-h { margin: 30px 0 12px; font-size: 1.3rem; }
  .dash-cats { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 14px; }
  .dash-cat { border: var(--line); border-radius: 14px; background: var(--surface); box-shadow: var(--shadow-xs); padding: 10px 14px; }
  .dash-cat.clean { background: var(--tint); box-shadow: none; }
  .dash-cat-name { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
  .dash-cat-num { font-family: var(--display); font-weight: 800; font-size: 1.9rem; line-height: 1.1; }
  .dash-risks { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 14px; }
  .dash-risk { border: var(--line); border-left-width: 9px; border-left-color: var(--red); border-radius: 14px; background: var(--surface); box-shadow: var(--shadow-xs); padding: 10px 14px; }
  .dash-risk-attack { font-size: 13px; margin: 6px 0; }

  @media print {
    body { background: #fff; max-width: none; }
    [data-tab], .dash-scope { display: block !important; }
    .tabs { display: none; }
    h1, .card, details.check, .table-wrap, .chart-row > div, blockquote, .ai-section { box-shadow: none; }
    .card:hover, details.check:hover { transform: none; }
  }
</style>
<script>
function copyFix(btn) {
  var text = btn.parentNode.querySelector('pre').innerText;
  var done = function () { btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = 'Copy'; }, 1500); };
  if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, function () {}); return; }
  var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch (e) {} document.body.removeChild(ta);
}
function hbTab(name) {
  Array.prototype.forEach.call(document.querySelectorAll('[data-tab]'), function (e) { e.hidden = e.getAttribute('data-tab') !== name; });
  Array.prototype.forEach.call(document.querySelectorAll('.tab-btn'), function (b) { b.classList.toggle('active', b.getAttribute('data-for') === name); });
  var sel = document.getElementById('dash-host'); if (sel) { sel.style.display = name === 'dashboard' ? '' : 'none'; }
}
function hbScope(sel) {
  Array.prototype.forEach.call(document.querySelectorAll('.dash-scope'), function (d) { d.hidden = d.id !== sel.value; });
}
function filterBadgerTable(input) {
  var table = input.closest('table');
  var filters = Array.prototype.map.call(table.querySelectorAll('tr.filter-row input'), function (i) { return i.value.toLowerCase(); });
  var rows = table.querySelectorAll('tr.data-row'); var shown = 0;
  rows.forEach(function (row) {
    var cells = row.children; var ok = true;
    for (var i = 0; i < filters.length; i++) { if (filters[i] && (!cells[i] || cells[i].textContent.toLowerCase().indexOf(filters[i]) === -1)) { ok = false; break; } }
    row.style.display = ok ? '' : 'none'; if (ok) shown++;
  });
  var status = table.parentNode.parentNode.querySelector('.filter-status');
  if (status) status.textContent = shown + ' of ' + rows.length + ' rows shown';
}
</script>
</head><body>
'@
    & $w "<h1 class=`"title`"><pre class='badger-logo' role='img' aria-label='HostBadger badger'>$(& $H $script:BadgerAscii)</pre><span>HostBadger: Windows Host Hardening Report</span></h1>"
    $newest = ($Hosts | Sort-Object CollectedUtc -Descending | Select-Object -First 1).CollectedUtc
    $oldest = ($Hosts | Sort-Object CollectedUtc | Select-Object -First 1).CollectedUtc
    $when = if ($newest -eq $oldest) { "snapshot $($newest.ToString('yyyy-MM-dd HH:mm')) UTC" } else { "snapshots $($oldest.ToString('yyyy-MM-dd')) to $($newest.ToString('yyyy-MM-dd')) UTC" }
    & $w "<div class=`"meta`">$(& $H $titleTarget) &middot; $when &middot; HostBadger v$ToolVersion &middot; analysis $ElapsedText</div>"
    if (@($Hosts | Where-Object { $_.Synthetic }).Count -gt 0) { & $w '<blockquote>Synthetic snapshots generated for testing and demonstration. No real host data.</blockquote>' }

    if ($hiddenCis -gt 0 -or $hiddenStig -gt 0 -or $HideCis -or $HideStig) {
        $what = @(); if ($HideCis) { $what += "$hiddenCis CIS-based" }; if ($HideStig) { $what += "$hiddenStig DISA STIG" }
        & $w "<blockquote>Hidden from this report: $($what -join ' and ') finding(s) (the compliance charts below still count them; the CSV and JSON Lines keep them).</blockquote>"
    }

    # ---------------- Dashboard tab (the fleet, and one view per host with a selector) ----------------
    $tabSel = ''
    if (-not $single) {
        $opts = @("<option value='dash-fleet'>Fleet ($(@($Hosts).Count) hosts)</option>") + @($Hosts | Sort-Object { $_.Score.Score } | ForEach-Object { $i = [array]::IndexOf(@($Hosts), $_); "<option value='dash-host-$i'>$(& $H $_.Name) ($($_.Score.Grade) &middot; $($_.Score.Score))</option>" })
        $tabSel = "<select id='dash-host' onchange='hbScope(this)' aria-label='Dashboard scope'>$($opts -join '')</select>"
    }
    & $w "<nav class='tabs'><button class='tab-btn active' data-for='dashboard' onclick=""hbTab('dashboard')"">Dashboard</button><button class='tab-btn' data-for='details' onclick=""hbTab('details')"">Details</button>$tabSel</nav>"
    & $w '<div data-tab="dashboard">'
    if ($single) { & $w "<div class='dash-scope' id='dash-fleet'>$(Get-DashboardHtml -Hosts $Hosts -All @($Split.Active) -Shown $findings -Title $Hosts[0].Name)</div>" }
    else {
        & $w "<div class='dash-scope' id='dash-fleet'>$(Get-DashboardHtml -Hosts $Hosts -All @($Split.Active) -Shown $findings -Title "Fleet of $(@($Hosts).Count) hosts")</div>"
        $actByHost = @{}; foreach ($f in @($Split.Active)) { $k = "$($f.Host)"; if (-not $actByHost.ContainsKey($k)) { $actByHost[$k] = New-Object System.Collections.Generic.List[object] }; $actByHost[$k].Add($f) }
        $shownByHost = @{}; foreach ($f in @($findings)) { $k = "$($f.Host)"; if (-not $shownByHost.ContainsKey($k)) { $shownByHost[$k] = New-Object System.Collections.Generic.List[object] }; $shownByHost[$k].Add($f) }
        $i = 0
        foreach ($hx in @($Hosts)) {
            $hAll = if ($actByHost.ContainsKey($hx.Name)) { $actByHost[$hx.Name].ToArray() } else { @() }
            $hShown = if ($shownByHost.ContainsKey($hx.Name)) { $shownByHost[$hx.Name].ToArray() } else { @() }
            & $w "<div class='dash-scope' id='dash-host-$i' hidden>$(Get-DashboardHtml -Hosts @($hx) -All $hAll -Shown $hShown -Title "$($hx.Name) ($($hx.Role))")</div>"
            $i++
        }
    }
    & $w '</div>'
    & $w '<div data-tab="details" hidden>'

    # ---------------- Cards ----------------
    & $w '<div class="cards">'
    if ($single) { & $w "<div class=`"card`"><div class=`"grade`">$($Hosts[0].Score.Grade) &middot; $($Hosts[0].Score.Score)/100</div><div class=`"lbl`">Hardening score ($($Hosts[0].Score.ChecksTriggered) checks triggered)</div></div>" }
    else {
        $avg = [int][Math]::Round((@($Hosts | ForEach-Object { $_.Score.Score }) | Measure-Object -Average).Average)
        & $w "<div class=`"card`"><div class=`"num`">$(@($Hosts).Count)</div><div class=`"lbl`">Hosts</div></div>"
        & $w "<div class=`"card`"><div class=`"grade`">$avg/100</div><div class=`"lbl`">Average hardening score</div></div>"
        $worstHost = $Hosts | Sort-Object { $_.Score.Score } | Select-Object -First 1
        & $w "<div class=`"card`"><div class=`"grade`">$($worstHost.Score.Grade) &middot; $($worstHost.Score.Score)</div><div class=`"lbl`">Weakest: $(& $H $worstHost.Name)</div></div>"
    }
    foreach ($s in $sevOrder) { & $w "<div class=`"card $($s.ToLower())`"><div class=`"num`">$($counts[$s])</div><div class=`"lbl`">$s findings</div></div>" }
    & $w '</div>'
    & $w '<div class="meta">Score per host = 100 &times; e<sup>&minus;penalty/100</sup>, where penalty sums a weight per triggered check at its worst severity (Critical 20, High 8, Medium 3, Low 1); any Critical caps it at 35, any High at 65. It measures exposure: DISA STIG rules and the Brave policy gaps are compliance, shown on their own, and a KEV name match already judged by version (CVE data) is not counted twice.</div>'

    # ---------------- Compliance ----------------
    $compCharts = @()
    $comp = @('Compliant', 'Not compliant'); $compColors = @('#6E8B5F', '#E2372A')
    if ($compliance.StigEvaluated -gt 0) {
        $okS = $compliance.StigEvaluated - $compliance.StigFailed
        $compCharts += "<div><div class='pie-chart-title'>DISA STIG compliance: $([int][Math]::Round(100 * $okS / $compliance.StigEvaluated))% of $($compliance.StigEvaluated) rules judged</div>$(Get-SvgPieChart -Labels $comp -Values @($okS, $compliance.StigFailed) -Colors $compColors -CenterLabel 'rules')</div>"
    }
    if ($compliance.CisApplicable -gt 0) {
        $okC = $compliance.CisApplicable - $compliance.CisFailed
        $compCharts += "<div><div class='pie-chart-title'>CIS-based compliance: $([int][Math]::Round(100 * $okC / $compliance.CisApplicable))% of $($compliance.CisApplicable) checks</div>$(Get-SvgPieChart -Labels $comp -Values @($okC, $compliance.CisFailed) -Colors $compColors -CenterLabel 'checks')</div>"
    }

    $sevVals = @($sevOrder | ForEach-Object { $counts[$_] })
    $cats = @($script:CheckCatalog.Values | ForEach-Object { $_.Category } | Select-Object -Unique)
    $catVals = @($cats | ForEach-Object { $c = $_; @($findings | Where-Object { $_.Category -eq $c }).Count })
    $sevChart = "<div><div class='pie-chart-title'>Findings by severity</div>$(Get-SvgPieChart -Labels $sevOrder -Values $sevVals -Colors $script:BadgerSeverityColors -CenterLabel 'findings')</div>"
    $catChart = "<div class='chart-wide'><div class='pie-chart-title'>Findings by category</div>$(Get-SvgPieChart -Labels $cats -Values $catVals -Colors $script:BadgerCategoryRamp -CenterLabel 'findings')</div>"
    $gradeChart = ''
    if (-not $single) {
        $grades = @('A', 'B', 'C', 'D', 'E', 'F')
        $gVals = @($grades | ForEach-Object { $g = $_; @($Hosts | Where-Object { $_.Score.Grade -eq $g }).Count })
        $gradeChart = "<div><div class='pie-chart-title'>Hosts by grade</div>$(Get-SvgPieChart -Labels $grades -Values $gVals -Colors @('#2B2823', '#4B463D', '#7C7465', '#F2B632', '#EF8A6F', '#E2372A') -CenterLabel 'hosts')</div>"
    }

    # ---------------- Software and updates charts ----------------
    $allSoftware = @(foreach ($hostItem in $Hosts) { foreach ($sw in @($hostItem.Software)) { if ($sw) { [PSCustomObject]@{ Host = $hostItem.Name; Name = "$($sw.name)"; Version = "$($sw.version)"; Publisher = "$($sw.publisher)" } } } })
    $swCharts = @()
    if ($allSoftware.Count -gt 0) {
        # Publishers written differently ("Google LLC", "Google Inc.") count as one.
        $pubKey = { param($p) $k = ("$p".ToLower() -replace '[^a-z0-9]+', ' ').Trim() -replace '\b(inc|llc|ltd|corp|corporation|co|gmbh|sa|ag|limited|incorporated)\b', ''; ($k -replace '\s+', ' ').Trim() }
        $byPub = $allSoftware | Group-Object { $k = & $pubKey $_.Publisher; if ($k) { $k } else { '(unknown)' } } | Sort-Object Count -Descending
        $top = @($byPub | Select-Object -First 7)
        $pubLabels = @($top | ForEach-Object { $first = ($_.Group | Select-Object -First 1).Publisher; if ($_.Name -eq '(unknown)') { 'Unknown publisher' } elseif ($first.Length -gt 26) { $first.Substring(0, 26) } else { $first } })
        $pubVals = @($top | ForEach-Object { $_.Count })
        $rest = $allSoftware.Count - ($pubVals | Measure-Object -Sum).Sum
        if ($rest -gt 0) { $pubLabels += 'Other publishers'; $pubVals += $rest }
        $swCharts += "<div><div class='pie-chart-title'>Installed software by publisher ($($allSoftware.Count) installs)</div>$(Get-SvgPieChart -Labels $pubLabels -Values $pubVals -Colors $script:BadgerCategoryRamp -CenterLabel 'programs')</div>"
        if ($KevLoaded) {
            $kevCount = [Math]::Min($allSoftware.Count, @($Split.Active | Where-Object { $_.Type -eq 'kev_software_match' }).Count)
            $swCharts += "<div><div class='pie-chart-title'>Software and the CISA KEV catalog (by name)</div>$(Get-SvgPieChart -Labels @('Matches a KEV product', 'No match') -Values @($kevCount, ($allSoftware.Count - $kevCount)) -Colors @('#E2372A', '#6E8B5F') -CenterLabel 'programs')</div>"
        }
    }
    if (@($Hosts | Where-Object { $_.UpdatesSearched }).Count -gt 0) {
        $upd = @($Split.Active | Where-Object { $_.Type -eq 'updates_pending' })
        $searched = @($Hosts | Where-Object { $_.UpdatesSearched }).Count
        if ($upd.Count -eq 0) { $swCharts += "<div><div class='pie-chart-title'>Missing Windows updates: none found ($searched host(s) searched)</div>$(Get-SvgPieChart -Labels @('Up to date') -Values @($searched) -Colors @('#6E8B5F') -CenterLabel 'hosts')</div>" }
        else { $swCharts += "<div><div class='pie-chart-title'>Missing Windows updates by severity ($searched host(s) searched)</div>$(Get-SvgPieChart -Labels @('High', 'Medium', 'Low') -Values @(@($upd | Where-Object { $_.Severity -eq 'High' }).Count, @($upd | Where-Object { $_.Severity -eq 'Medium' }).Count, @($upd | Where-Object { $_.Severity -eq 'Low' }).Count) -Colors @('#EF8A6F', '#F2B632', '#B9B1A1') -CenterLabel 'updates')</div>" }
    }
    # ---------------- Local accounts: administrators versus standard users ----------------
    # Domain controllers have no local accounts, and a host whose Administrators group could not be
    # read is left out rather than counted as standard users.
    $acctChart = $null
    $mixes = @($Hosts | Where-Object { $_.AccountMix } | ForEach-Object { $_.AccountMix })
    if ($mixes.Count -gt 0) {
        $aAdm = ($mixes | Measure-Object -Property Admin -Sum).Sum
        $aStd = ($mixes | Measure-Object -Property Standard -Sum).Sum
        $aDis = ($mixes | Measure-Object -Property Disabled -Sum).Sum
        $acctChart = "<div><div class='pie-chart-title'>Local accounts: administrators vs standard users ($($mixes.Count) host(s))</div>$(Get-SvgPieChart -Labels @('Administrators (enabled)', 'Standard users (enabled)', 'Disabled') -Values @($aAdm, $aStd, $aDis) -Colors @('#EF8A6F', '#6E8B5F', '#B9B1A1') -CenterLabel 'accounts')</div>"
    }
    # One grid for all of them, the short legends first and the long category legend near the end.
    $allCharts = @($compCharts) + @($sevChart) + @($acctChart) + @($swCharts) + @($catChart) + @($gradeChart) | Where-Object { $_ }
    & $w "<div class='chart-row'>$($allCharts -join '')</div>"


    # ---------------- Coverage ----------------
    $allNe = @($Hosts | ForEach-Object { $_.NotEvaluated } | Where-Object { $_ })
    if ($allNe.Count -gt 0) {
        & $w '<blockquote class="warn"><b>Incomplete coverage.</b> Some data could not be collected; the checks below were <b>not evaluated</b> on the hosts listed (zero findings there does not mean compliant).<ul>'
        foreach ($g in ($allNe | Group-Object Type | Sort-Object Name)) {
            $hostsTxt = (@($g.Group | ForEach-Object { $_.Host } | Select-Object -Unique) -join ', ')
            $reasons = (@($g.Group | ForEach-Object { $_.Reason } | Select-Object -Unique) -join ' / ')
            & $w "<li><code>$($g.Name)</code> $(& $H $script:CheckCatalog[$g.Name].Title) &middot; $(@($g.Group).Count) host(s): $(& $H $hostsTxt). $(& $H $reasons)</li>"
        }
        & $w '</ul></blockquote>'
    }

    # ---------------- AI section (optional, written by AI.ps1) ----------------
    if ($AiResult) { & $w (ConvertTo-AiSectionHtml $AiResult) }

    # ---------------- Hosts ----------------
    & $w "<details open><summary><h2>Hosts</h2></summary><div class=`"table-wrap`"><table><tr><th>Host</th><th>Role</th><th>Operating system</th><th>Collected (UTC)</th><th>As</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Not evaluated</th><th>EDR</th></tr>"
    # Not $h: PowerShell names are case-insensitive, and $H is the encoder.
    foreach ($hst in ($Hosts | Sort-Object { $_.Score.Score }, Name)) {
        $hf = @($findings | Where-Object { $_.Host -eq $hst.Name })
        $as = if ($hst.AsSystem) { 'SYSTEM' } elseif ($hst.AsAdmin) { 'admin' } else { '<span style="color:var(--critical)">standard user</span>' }
        $row = "<tr class=`"data-row`"><td><b>$(& $H $hst.Name)</b></td><td>$(& $H $hst.Role)</td><td>$(& $H $hst.Os)</td><td>$($hst.CollectedUtc.ToString('yyyy-MM-dd HH:mm'))</td><td>$as</td><td>$($hst.Score.Grade) &middot; $($hst.Score.Score)</td>"
        foreach ($s in $sevOrder) { $row += "<td>$(@($hf | Where-Object { $_.Severity -eq $s }).Count)</td>" }
        # What EDR the host runs: the agents found among its services, or "none found"; "unknown" without a service list.
        $edrText = if (-not $hst.EdrKnown) { '<span class="meta">unknown</span>' }
        elseif (@($hst.Edr).Count -eq 0) { '<span class="meta">none found</span>' }
        else { (@($hst.Edr | ForEach-Object { $c = if ($_.State -eq 'running') { '' } else { ' <span style="color:var(--critical)">(stopped)</span>' }; "$(& $H $_.Name)$c" }) -join '<br>') }
        $row += "<td>$(@($hst.NotEvaluated).Count)</td><td>$edrText</td></tr>"
        & $w $row
    }
    & $w '</table></div></details>'

    # ---------------- Remediation scripts ----------------
    if ($Remediation) {
        & $w '<details open><summary><h2>Remediation scripts</h2></summary>'
        & $w '<p class="meta">One script per host for the findings that have a safe, standard fix: a single setting, set to the value the benchmark expects. Each script only previews unless run with <code>-Apply</code>, saves the previous values in a rollback file (<code>-Restore &lt;file&gt; -Apply</code> puts them back), and refuses to run on another computer. HostBadger never runs them. Findings that need a decision (banner text, allowed administrators, password policy, services, BitLocker, Credential Guard, LAPS, user rights) have no script: follow the remediation text of the check.</p>'
        & $w '<div class="table-wrap"><table><tr><th>Host</th><th>Script</th><th>Settings</th><th>Findings with a script</th><th>Findings without</th></tr>'
        foreach ($ri in @($Remediation | Sort-Object Host)) {
            $fileTxt = if ($ri.File) { "<code>$(& $H $ri.File)</code>" } else { '<span class="meta">none</span>' }
            & $w "<tr class=`"data-row`"><td><b>$(& $H $ri.Host)</b></td><td>$fileTxt</td><td>$($ri.Actions)</td><td>$($ri.Fixable)</td><td>$($ri.NotFixable)</td></tr>"
        }
        & $w '</table></div></details>'
    }

    # ---------------- Category summary (DISA STIG is a framework: its row is in the summary by framework)
    & $w '<details open><summary><h2>Summary by category</h2></summary><div class="table-wrap"><table><tr><th>Category</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Checks triggered</th><th>Hosts affected</th></tr>'
    foreach ($c in @($cats | Where-Object { $_ -ne 'DISA STIG' })) {
        $cf = @($findings | Where-Object { $_.Category -eq $c })
        $row = "<tr class=`"data-row`"><td>$(& $H $c)</td>"
        foreach ($s in $sevOrder) { $row += "<td>$(@($cf | Where-Object { $_.Severity -eq $s }).Count)</td>" }
        $row += "<td>$(@($cf | ForEach-Object { $_.Type } | Select-Object -Unique).Count)</td><td>$(@($cf | ForEach-Object { $_.Host } | Select-Object -Unique).Count)</td></tr>"
        & $w $row
    }
    & $w '</table></div></details>'

    # ---------------- Summary by framework: CIS, DISA STIG and the Essential Eight strategies cut across
    # the categories, so a finding can count in more than one row.
    $e8TypeSet = @{}; foreach ($k in $script:E8Strategies.Keys) { foreach ($t in @($script:E8Strategies[$k].Checks)) { $e8TypeSet[$t] = $true } }
    $fwRows = New-Object System.Collections.Generic.List[object]
    $fwRows.Add(@('CIS benchmarks', @($findings | Where-Object { $_.Cis }), $(if ($HideCis) { "$hiddenCis hidden (-HideCis)" } else { '' })))
    $fwRows.Add(@('DISA STIG', @($findings | Where-Object { $_.Category -eq 'DISA STIG' }), $(if ($HideStig) { "$hiddenStig hidden (-HideStig)" } else { '' })))
    $fwRows.Add(@('ACSC Essential Eight (checks tied to its requirements)', @($findings | Where-Object { $e8TypeSet.ContainsKey("$($_.Type)") }), ''))
    foreach ($k in $script:E8Strategies.Keys) {
        $st = $script:E8Strategies[$k]; $set = @($st.Checks)
        $fwRows.Add(@("&nbsp;&nbsp;&nbsp;E8: $(& $H $st.Label)", @($findings | Where-Object { $set -contains "$($_.Type)" }), $(if ($st.Note) { $st.Note } else { '' })))
    }
    & $w '<details open><summary><h2>Summary by framework</h2></summary><p class="meta">CIS, DISA STIG and the ACSC Essential Eight cut across the categories: a finding can count in more than one row. The Essential Eight rows are the HostBadger checks that judge a requirement of each strategy; the maturity levels are in the dashboard.</p><div class="table-wrap"><table><tr><th>Framework</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Checks triggered</th><th>Hosts affected</th></tr>'
    foreach ($fr in $fwRows) {
        $ff = @($fr[1]); $name = if ($fr[0] -like '&nbsp;*') { $fr[0] } else { & $H $fr[0] }
        $row = "<tr class=`"data-row`"><td>$name$(if ($fr[2]) { " <span class='meta'>($(& $H $fr[2]))</span>" })</td>"
        foreach ($s in $sevOrder) { $row += "<td>$(@($ff | Where-Object { $_.Severity -eq $s }).Count)</td>" }
        $row += "<td>$(@($ff | ForEach-Object { $_.Type } | Select-Object -Unique).Count)</td><td>$(@($ff | ForEach-Object { $_.Host } | Select-Object -Unique).Count)</td></tr>"
        & $w $row
    }
    & $w '</table></div></details>'

    # ---------------- Findings by check ----------------
    & $w '<details open><summary><h2>Findings by check</h2></summary>'
    if ($findings.Count -eq 0) { & $w '<p>No findings.</p>' }
    $typeRows = @($findings | Group-Object Type | ForEach-Object {
            $worst = ($_.Group | Sort-Object { - $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
            [PSCustomObject]@{ Type = $_.Name; Worst = $worst; Items = $_.Group; Rank = $script:SeverityRank[$worst] }
        } | Sort-Object @{ Expression = 'Rank'; Descending = $true }, @{ Expression = { $_.Items.Count }; Descending = $true })
    foreach ($t in $typeRows) {
        $meta = $script:CheckCatalog[$t.Type]
        $nHosts = @($t.Items | ForEach-Object { $_.Host } | Select-Object -Unique).Count
        & $w "<details class=`"check`"><summary>$(Get-SevPill $t.Worst)<span class=`"check-title`">$(& $H $meta.Title)</span><span class=`"check-id`">$($t.Type) &middot; $(& $H $meta.Category)</span><span class=`"count`">$(@($t.Items).Count) finding(s) on $nHosts host(s)</span></summary><div class=`"body`">"
        & $w "<div class=`"kv`"><b>Why it matters.</b> $(& $H $meta.Description)</div>"
        if ($meta.Attacks) { & $w "<div class=`"kv attacks`"><b>Attacks it enables.</b> $(& $H $meta.Attacks)</div>" }
        & $w "<div class=`"kv`"><b>Remediation.</b> $(& $H $meta.Remediation)</div>"
        if ($meta.Mitre) { & $w "<div class=`"kv`"><b>MITRE ATT&amp;CK.</b> $(Get-MitreLink $meta.Mitre)</div>" }
        $e8Of = @($script:E8Requirements | Where-Object { @($_.Checks) -contains $t.Type } | ForEach-Object { "$($script:E8Strategies[$_.S].Label), ML$($_.L): $($_.Req)" } | Select-Object -Unique)
        if ($e8Of.Count) { & $w "<div class=`"kv`"><b>ACSC Essential Eight.</b> $(& $H ($e8Of -join ' | '))</div>" }
        if ($meta.Cis -or $meta.CisServer) {
            if ($meta.Cis) { & $w "<div class=`"kv`"><b>CIS Windows 11 Enterprise v3.0.0.</b> rule $(& $H $meta.Cis)</div>" }
            # Servers quote their own benchmark (data\cis-map.json): list the rules their findings name.
            foreach ($g in @($t.Items | Where-Object { $_.CisBenchmark -and $_.CisBenchmark -notmatch 'Windows 11' } | Group-Object CisBenchmark)) {
                $rules = @($g.Group | ForEach-Object { "$($_.Cis)" } | Where-Object { $_ } | Sort-Object -Unique)
                & $w "<div class=`"kv`"><b>$(& $H ($g.Name -replace '^CIS Microsoft ', 'CIS ' -replace ' Benchmark', '')).</b> rule $(& $H ($rules -join '; '))</div>"
            }
        }
        # Found / Required: the value on the host next to the value the framework asks for, when known.
        $fe = @($t.Items | Where-Object { $_.Found -or $_.Expected }).Count -gt 0
        & $w "<div class=`"table-wrap`"><table><tr><th>Severity</th><th>Host</th><th>Object</th>$(if ($fe) { '<th>Found</th><th>Required</th>' })<th>Detail</th></tr>"
        foreach ($f in ($t.Items | Sort-Object { - $script:SeverityRank[$_.Severity] }, Host, Object)) {
            $feCells = if ($fe) { "<td class=`"found`">$(& $H $f.Found)</td><td class=`"required`">$(& $H $f.Expected)</td>" } else { '' }
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td><b>$(& $H $f.Host)</b></td><td>$(& $H $f.Object)</td>$feCells<td>$(& $H $f.Detail)</td></tr>"
        }
        & $w '</table></div>'
        # The fix, when there is a safe, standard one: plain PowerShell right under the findings it
        # fixes.
        if ($script:FixTypes -and $script:FixTypes.ContainsKey($t.Type)) {
            $blocks = @(Get-CheckFixBlocks -Type $t.Type -Findings $t.Items -HostRoles $hostRoles -Config $Config)
            if ($blocks.Count -gt 0) {
                $withScript = $blocks[0].WithScript
                & $w "<details class=`"fix`" open><summary>Fix script <span class=`"meta`">$withScript of $(@($t.Items).Count) finding(s) &middot; read it, run it elevated in Windows PowerShell 5.1; it changes nothing until <code>`$Apply = `$true</code></span></summary>"
                foreach ($b in $blocks) {
                    $forHosts = if ($blocks.Count -gt 1 -or @($b.Hosts).Count -lt $nHosts) { "<div class=`"meta`">For: $(& $H ($b.Hosts -join ', '))</div>" } else { '' }
                    & $w "$forHosts<div class=`"fix-box`"><button type=`"button`" class=`"copy`" onclick=`"copyFix(this)`">Copy</button><pre class=`"fix-code`">$(& $H $b.Code)</pre></div>"
                }
                $missing = @($t.Items).Count - $withScript
                if ($missing -gt 0) { & $w "<div class=`"meta`">$missing finding(s) of this check have no script: follow the remediation text above.</div>" }
                & $w '<div class="meta">Group Policy or Intune can set a value back: fix it there if the host is managed. Test on a pilot host first.</div></details>'
            }
        }
        & $w '</div></details>'
    }
    & $w '</details>'

    # ---------------- Comparison ----------------
    if ($Comparison) {
        & $w "<details open><summary><h2>Comparison with previous run</h2></summary><p class=`"meta`">Baseline: $(& $H $Comparison.PreviousPath). Matched by (check, host, object); hosts missing from this run are not counted as resolved.</p>"
        & $w "<div class=`"cards`"><div class=`"card`"><div class=`"num compare-new`">$(@($Comparison.New).Count)</div><div class=`"lbl`">New</div></div><div class=`"card`"><div class=`"num compare-resolved`">$(@($Comparison.Resolved).Count)</div><div class=`"lbl`">Resolved</div></div><div class=`"card`"><div class=`"num`">$(@($Comparison.Persisting).Count)</div><div class=`"lbl`">Still present</div></div></div>"
        & $w '<div class="table-wrap"><table><tr><th>Status</th><th>Severity</th><th>Check</th><th>Host</th><th>Object</th><th>Detail</th></tr>'
        foreach ($f in $Comparison.New) { & $w "<tr class=`"data-row`"><td class=`"compare-new`">NEW</td><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Host)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        foreach ($f in $Comparison.Resolved) { & $w "<tr class=`"data-row`"><td class=`"compare-resolved`">RESOLVED</td><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Host)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td></tr>" }
        & $w '</table></div></details>'
    }

    # ---------------- Accepted risks ----------------
    if (@($Split.Accepted).Count -gt 0 -or @($Split.Expired).Count -gt 0) {
        & $w '<details><summary><h2>Accepted risks (exceptions)</h2></summary>'
        if (@($Split.Expired).Count -gt 0) {
            & $w '<blockquote class="warn"><b>Expired exceptions ignored</b> (their findings are back in the report):<ul>'
            foreach ($e in $Split.Expired) { & $w "<li><code>$(& $H $e.type)</code> / $(& $H $e.host) / $(& $H $e.object): expired $(& $H $e.expires). $(& $H $e.reason)</li>" }
            & $w '</ul></blockquote>'
        }
        & $w '<div class="table-wrap"><table><tr><th>Severity</th><th>Check</th><th>Host</th><th>Object</th><th>Reason</th><th>Owner</th><th>Expires</th></tr>'
        foreach ($a in $Split.Accepted) {
            & $w "<tr class=`"data-row`"><td>$(Get-SevPill $a.Finding.Severity)</td><td>$($a.Finding.Type)</td><td>$(& $H $a.Finding.Host)</td><td>$(& $H $a.Finding.Object)</td><td>$(& $H $a.Exception.reason)</td><td>$(& $H $a.Exception.owner)</td><td>$(& $H $a.Exception.expires)</td></tr>"
        }
        & $w '</table></div></details>'
    }

    # ---------------- Installed software (filterable) ----------------
    if ($allSoftware.Count -gt 0) {
        $kevNames = @{}
        foreach ($kf in @($Split.Active | Where-Object { $_.Type -eq 'kev_software_match' })) {
            $mm = [regex]::Match("$($kf.Detail)", '^Installed as (.+) \((?:version [^)]*|no version recorded)\)\.')
            if ($mm.Success) { $kevNames["$($kf.Host)|$($mm.Groups[1].Value)".ToLower()] = $true }
        }
        $rows = @($allSoftware | Group-Object { "$($_.Name)|$($_.Version)|$($_.Publisher)".ToLower() } | Sort-Object { $_.Group[0].Name })
        $shown = @($rows | Select-Object -First 3000)
        & $w "<details><summary><h2>Installed software</h2></summary><p class=`"meta`">What Programs and Features lists on $(@($Hosts).Count) host(s): $($allSoftware.Count) installs, $($rows.Count) distinct. Per-user installs are not listed.$(if ($KevLoaded) { ' The last column marks programs that match a product in the CISA KEV catalog by name only (no version ranges: verify against the vendor advisory).' })</p><div class=`"table-wrap`"><table>"
        & $w '<tr><th>Program</th><th>Version</th><th>Publisher</th><th>Hosts</th><th>KEV</th></tr>'
        & $w ('<tr class="filter-row">' + ((1..5 | ForEach-Object { '<td><input type="text" placeholder="filter" oninput="filterBadgerTable(this)"></td>' }) -join '') + '</tr>')
        foreach ($g in $shown) {
            $first = $g.Group[0]
            $hostNames = @($g.Group | ForEach-Object { $_.Host } | Select-Object -Unique)
            $isKev = @($hostNames | Where-Object { $kevNames.ContainsKey("$_|$($first.Name)".ToLower()) }).Count -gt 0
            $hostsCell = if ($single) { '' } else { "$($hostNames.Count)" }
            & $w "<tr class=`"data-row`"><td>$(& $H $first.Name)</td><td>$(& $H $first.Version)</td><td>$(& $H $first.Publisher)</td><td>$hostsCell</td><td>$(if ($isKev) { 'match' } else { '' })</td></tr>"
        }
        & $w "</table></div><div class=`"filter-status`">$($shown.Count) rows$(if ($rows.Count -gt $shown.Count) { " (first 3000 of $($rows.Count))" })</div></details>"
    }

    # ---------------- All findings (filterable) ----------------
    & $w '<details><summary><h2>All findings</h2></summary><div class="table-wrap"><table>'
    & $w '<tr><th>Severity</th><th>Check</th><th>Category</th><th>Host</th><th>Object</th><th>Detail</th><th>MITRE</th></tr>'
    & $w ('<tr class="filter-row">' + ((1..7 | ForEach-Object { '<td><input type="text" placeholder="filter" oninput="filterBadgerTable(this)"></td>' }) -join '') + '</tr>')
    foreach ($f in ($findings | Sort-Object { - $script:SeverityRank[$_.Severity] }, Host, Type, Object)) {
        & $w "<tr class=`"data-row`"><td>$(Get-SevPill $f.Severity)</td><td>$($f.Type)</td><td>$(& $H $f.Category)</td><td>$(& $H $f.Host)</td><td>$(& $H $f.Object)</td><td>$(& $H $f.Detail)</td><td>$(Get-MitreLink $f.Mitre)</td></tr>"
    }
    & $w "</table></div><div class=`"filter-status`">$($findings.Count) rows</div></details>"

    & $w "<p class=`"meta`" style=`"margin-top:32px`">Thresholds: updates $($Config.MaxPatchAgeDays) days, Defender signatures $($Config.MaxSignatureAgeDays) days, cached logons $($Config.MaxCachedLogonsWorkstation) (workstations) / $($Config.MaxCachedLogonsServer) (servers), Security log $($Config.MinSecurityLogKB) KB, support warning $($Config.SupportWarningDays) days.</p>"
    & $w '</div>'
    & $w '<p class="meta">Generated by HostBadger from read-only snapshots. The report contains host configuration details: handle as confidential.</p>'
    & $w '</body></html>'
    return $sb.ToString()
}
