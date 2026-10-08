<#
.SYNOPSIS
    HostBadger launcher: one guided entry point for collection and analysis.

.DESCRIPTION
    A small menu, so nobody has to remember parameters:

      1  Collect this machine            (Collect-HostSnapshot.ps1, read-only)
      2  Analyze snapshots               (HostBadger.ps1: one snapshot, a zip or a folder of them)
      3  Collect and analyze this machine
      4  Add an AI summary               (Gemini; names replaced by tokens first)
      5  Safety review                   (Test-HostBadgerSafety.ps1: what the scripts can do)

    Nothing here changes the machine. The AI step sends nothing unless you
    choose it, and shows you the exact text first when you ask for a dry run.

    Double-click use: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-HostBadger.ps1
    (the policy is bypassed for that process only; a policy enforced by GPO still wins).

.EXAMPLE
    .\Start-HostBadger.ps1
#>

[CmdletBinding()]
Param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Show-Banner {
    Write-Host @'
     _.--""--._
   .'  |    |  '.
  /    |    |    \      HostBadger
 |  (o)|    |(o)  |     Windows host hardening
 |     |    |     |     collect, analyze, optional AI summary
  \    '.__.'    /
   '._   \/   _.'
      '--..--'
'@ -ForegroundColor DarkYellow
}

function Invoke-Sub {
    param([string]$Script, [hashtable]$Params = @{})
    $path = Join-Path $root $Script
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "Missing $Script next to the launcher." -ForegroundColor Red; return }
    Write-Host "`n--- $Script ---`n" -ForegroundColor Cyan
    # A failing step must not kill the menu, so we report it and go back. Out-Host shows whatever
    # the script prints and keeps it from being mistaken for a value the menu needs.
    try { & $path @Params | Out-Host }
    catch { Write-Host "$Script stopped: $($_.Exception.Message)" -ForegroundColor Red }
}

# Path prompt with Tab completion; falls back to Read-Host when redirected.
function Read-Path {
    param([string]$Prompt, [string]$Default = "")
    $label = "$Prompt" + $(if ($Default) { " [$Default]" } else { "" })
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { $v = Read-Host $label; if ([string]::IsNullOrWhiteSpace($v)) { return $Default } return $v.Trim() }
    Write-Host -NoNewline "${label}: "; $buf = ''; $tm = @(); $ti = 0
    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') { Write-Host ''; if ([string]::IsNullOrWhiteSpace($buf)) { return $Default } return $buf.Trim() }
        elseif ($key.Key -eq 'Backspace') { if ($buf.Length) { $buf = $buf.Substring(0, $buf.Length - 1); Write-Host -NoNewline "`b `b" }; $tm = @() }
        elseif ($key.Key -eq 'Tab') {
            if ($tm.Count -eq 0) {
                $hd = $buf -match '[\\/]'; $dir = if ($hd) { Split-Path $buf -Parent } else { '.' }; $leaf = if ($buf) { Split-Path $buf -Leaf } else { '' }
                try { $tm = @(Get-ChildItem -LiteralPath $dir -Filter ($leaf + '*') -ErrorAction SilentlyContinue | ForEach-Object { $n = if ($_.PSIsContainer) { $_.Name + [IO.Path]::DirectorySeparatorChar } else { $_.Name }; if ($hd) { Join-Path $dir $n } else { $n } }) } catch { $tm = @() }
                $ti = 0
            }
            if ($tm.Count) { $c = $tm[$ti % $tm.Count]; $ti++; if ($buf.Length) { Write-Host -NoNewline (("`b" * $buf.Length) + (" " * $buf.Length) + ("`b" * $buf.Length)) }; $buf = $c; Write-Host -NoNewline $buf }
        }
        elseif ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) { $buf += $key.KeyChar; Write-Host -NoNewline $key.KeyChar; $tm = @() }
    }
}
function Ts { Get-Date -Format 'yyyyMMdd_HHmmss' }
function Test-Yes { param([string]$Prompt) return ((Read-Host $Prompt) -match '^[YySs]') }

function Test-IsAdmin {
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { return $false }
}

# Collect this machine. Returns the folder with the snapshot, or an empty string if nothing came
# out.
function Invoke-CollectStep {
    if (-not (Test-IsAdmin)) {
        Write-Host "Not running as administrator: the snapshot will have gaps (listed as 'not evaluated' in the report). Start an elevated PowerShell for full coverage." -ForegroundColor Yellow
    }
    $dir = Read-Path "Snapshot folder" (Join-Path $PWD.Path 'snapshots')
    $p = @{ OutDir = $dir }
    if (Test-Yes "Skip file ACLs (faster, but the writable-program checks are not evaluated)? (y/N)") { $p['SkipAcl'] = $true }
    # The one network call the collector can make, so it is asked about and the address is named.
    $wuSource = 'Microsoft Update (HTTPS to *.update.microsoft.com)'
    try {
        $wuPol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop
        $wuAu = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        if ($wuPol.WUServer -and $wuAu -and $wuAu.UseWUServer -eq 1) { $wuSource = "the WSUS server $($wuPol.WUServer)" }
    }
    catch { }
    Write-Host "`nOptional: ask Windows Update which updates are still missing. The Windows Update service of this machine contacts $wuSource; the collector itself sends nothing. Without it, pending updates are simply not in the snapshot." -ForegroundColor DarkGray
    if (Test-Yes "Search for missing updates online? (y/N)") { $p['CheckUpdates'] = $true }
    $before = @(Get-ChildItem -LiteralPath $dir -Filter 'hostsnapshot_*' -ErrorAction SilentlyContinue).Count
    Invoke-Sub 'Collect-HostSnapshot.ps1' $p
    $after = @(Get-ChildItem -LiteralPath $dir -Filter 'hostsnapshot_*' -ErrorAction SilentlyContinue).Count
    if ($after -gt $before) {
        Write-Host "Snapshot ready in $dir. It describes this machine: handle it as confidential and never commit it." -ForegroundColor Green
        return $dir
    }
    Write-Host "No snapshot produced; see messages above." -ForegroundColor Red
    return ''
}

# The snapshots in a folder, read from their file names (hostsnapshot_<host>_<yyyyMMddHHmmss>.zip or
# .json; the time in the name is UTC). Without -Recurse only the folder itself is looked at.
function Get-SnapshotList {
    param([string]$Dir, [switch]$Recurse)
    $args2 = @{ LiteralPath = $Dir; File = $true; ErrorAction = 'SilentlyContinue' }
    if ($Recurse) { $args2['Recurse'] = $true }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem @args2 | Where-Object { $_.Name -match '^hostsnapshot_.+\.(json|zip)$' })) {
        $m = [regex]::Match($f.Name, '^hostsnapshot_(?<host>.+)_(?<ts>\d{14})\.(json|zip)$')
        $name = $f.BaseName -replace '^hostsnapshot_', ''
        $when = $f.LastWriteTimeUtc
        if ($m.Success) {
            $name = $m.Groups['host'].Value
            try { $when = [datetime]::ParseExact($m.Groups['ts'].Value, 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture) } catch { }
        }
        $items.Add([PSCustomObject]@{ Path = $f.FullName; Host = $name; When = $when; Size = $f.Length; Kind = $f.Extension.TrimStart('.') })
    }
    return $items.ToArray()
}

# Looks for snapshots where they usually are (a "snapshots" folder here, this folder, the "snapshots"
# folder next to the scripts) and lets you pick one, take them all, or type a path.
function Select-Snapshot {
    $places = @(
        @{ Dir = (Join-Path $PWD.Path 'snapshots'); Recurse = $true },
        @{ Dir = $PWD.Path; Recurse = $false },
        @{ Dir = (Join-Path $root 'snapshots'); Recurse = $true })
    $seen = @{}
    foreach ($pl in $places) {
        $key = "$($pl.Dir)".ToLower()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if (-not (Test-Path -LiteralPath $pl.Dir)) { continue }
        $found = @(Get-SnapshotList -Dir $pl.Dir -Recurse:([bool]$pl.Recurse) | Sort-Object When -Descending)
        if ($found.Count -eq 0) { continue }
        # The newest snapshot of each host is the one a folder run uses.
        $newest = @{}
        foreach ($f in $found) { $k = $f.Host.ToLower(); if (-not $newest.ContainsKey($k) -or $f.When -gt $newest[$k]) { $newest[$k] = $f.When } }
        Write-Host "`nSnapshots found in $($pl.Dir): $($found.Count) for $($newest.Count) host(s)" -ForegroundColor Cyan
        $show = @($found | Select-Object -First 15)
        for ($i = 0; $i -lt $show.Count; $i++) {
            $f = $show[$i]
            $old = if ($f.When -lt $newest[$f.Host.ToLower()]) { '  (older: a folder run ignores it)' } else { '' }
            Write-Host ("  [{0,2}] {1,-26} {2:yyyy-MM-dd HH:mm} UTC  {3,6:N0} KB  {4}{5}" -f ($i + 1), $f.Host, $f.When, ($f.Size / 1KB), $f.Kind, $old)
        }
        if ($found.Count -gt $show.Count) { Write-Host "       ... and $($found.Count - $show.Count) older one(s)" -ForegroundColor DarkGray }
        Write-Host "  [ A] all of them: the folder, with the newest snapshot of each host" -ForegroundColor White
        $pick = (Read-Path "Pick a number, A for all, or type a path" 'A').Trim()
        if ($pick -match '^\d+$') {
            $n = [int]$pick
            if ($n -ge 1 -and $n -le $show.Count) { return $show[$n - 1].Path }
            Write-Host "There is no snapshot number $n." -ForegroundColor Yellow
            return ''
        }
        if ($pick -ieq 'A') { return $pl.Dir }
        return $pick
    }
    return (Read-Path "Snapshot file, zip or folder (a fleet is a folder)" '')
}

# Ask for the pieces of an analysis. With $WithAi it also asks the Gemini questions.
function Get-AnalysisParams {
    param([string]$Snapshot = '', [bool]$WithAi = $false)
    $ap = @{}
    if (-not $Snapshot) { $Snapshot = Select-Snapshot }
    if (-not $Snapshot -or -not (Test-Path -LiteralPath $Snapshot)) { Write-Host "Snapshot not found." -ForegroundColor Red; return $null }
    $ap['Snapshot'] = $Snapshot
    $ap['OutHtml'] = Read-Path "Report HTML path" ("hostbadger_{0}.html" -f (Ts))
    # Only when the folder holds snapshots of more than one host: one report each, on by default.
    if ((Get-Item -LiteralPath $Snapshot).PSIsContainer) {
        $hostCount = @(Get-SnapshotList -Dir $Snapshot -Recurse | ForEach-Object { $_.Host.ToLower() } | Sort-Object -Unique).Count
        if ($hostCount -gt 1) {
            Write-Host "`n$hostCount hosts found: HostBadger can also write one report per host, next to the fleet report." -ForegroundColor DarkGray
            $ans = "$(Read-Host 'One report per host? (Y/n)')".Trim()
            if ($ans -notmatch '^[Nn]') { $ap['PerHost'] = $true }
        }
    }
    Write-Host "`nThe report also judges about 500 DISA STIG registry rules (Windows 11, Defender, Firewall, Edge, Chrome, Firefox, Office). A host that is not managed against the STIG shows hundreds of 'not configured' findings." -ForegroundColor DarkGray
    $stigAns = "$(Read-Host 'Include the DISA STIG rules? (Y/n)')".Trim()
    if ($stigAns -match '^[Nn]') { $ap['SkipStig'] = $true }
    $cisAns = "$(Read-Host 'Show the CIS-based findings in the report? (Y/n)')".Trim()
    if ($cisAns -match '^[Nn]') { $ap['HideCis'] = $true }
    if (-not $ap.ContainsKey('SkipStig')) {
        $stigShow = "$(Read-Host 'Show the DISA STIG findings in the report? (Y/n)')".Trim()
        if ($stigShow -match '^[Nn]') { $ap['HideStig'] = $true }
    }
    Write-Host "`nCISA KEV: installed software can be compared with the catalog of vulnerabilities known to be exploited. The match is by vendor and product name only (the catalog has no version ranges), so it is a lead to verify. Downloading connects to www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (one HTTPS GET, nothing is sent); a copy is kept next to the report." -ForegroundColor DarkGray
    $kevAns = "$(Read-Host 'CISA KEV catalog: [N]one, [O]nline download, or a [F]ile you already have (N/o/f)')".Trim().ToUpper()
    if ($kevAns -eq 'O') { $ap['KevOnline'] = $true }
    elseif ($kevAns -eq 'F') {
        $kevPath = Read-Path 'Path of known_exploited_vulnerabilities.json'
        if ($kevPath -and (Test-Path -LiteralPath $kevPath)) { $ap['KevFile'] = $kevPath } else { Write-Host "Not found, KEV skipped: $kevPath" -ForegroundColor Yellow }
    }
    if (Test-Yes "Also write JSON Lines for a SIEM? (y/N)") { $ap['OutJsonl'] = Read-Path "JSON Lines path" ($ap['OutHtml'] -replace '\.html?$', '.jsonl') }
    $prev = Read-Path "Findings CSV of an earlier run, to show new and resolved (optional, Enter to skip)"
    if ($prev) { if (Test-Path -LiteralPath $prev) { $ap['CompareTo'] = $prev } else { Write-Host "Not found, comparison skipped: $prev" -ForegroundColor Yellow } }
    $exc = Read-Path "Exceptions file (accepted risks, optional, Enter to skip)"
    if ($exc) { if (Test-Path -LiteralPath $exc) { $ap['ExceptionsFile'] = $exc } else { Write-Host "Not found, exceptions skipped: $exc" -ForegroundColor Yellow } }
    Write-Host "`nLocal administrators: HostBadger reports every member of the local Administrators group that it doesn't expect (Domain Admins and the built-in Administrator are always expected)." -ForegroundColor DarkGray
    Write-Host "If some belong there (for example an IT group), list them as DOMAIN/Name or by SID, comma separated, and they won't be reported." -ForegroundColor DarkGray
    $adm = Read-Host "Allowed local administrators, e.g. CORP/Workstation Admins, CORP/helpdesk (Enter = none)"
    if ($adm.Trim()) { $ap['AllowedAdmins'] = @($adm -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    Write-Host "`nEDR: HostBadger shows which known EDR agent each host runs (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend Micro and others) and flags one that is stopped. Name the one every host should have and a host without it is flagged too." -ForegroundColor DarkGray
    $edr = Read-Host "EDR every host should run, e.g. CrowdStrike or SentinelOne, comma separated (Enter = none)"
    if ($edr.Trim()) { $ap['ExpectedEdr'] = @($edr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    # Option 4 asks about the AI step up front. Options 2 and 3 offer it once the report is written.
    if ($WithAi) { Add-AiParams -Params $ap -Mode (Read-AiMode 'AI summary (Gemini): [D]ry run (write the prompt, send nothing), [S]end, [C]onfirm first after reading the prompt (D/s/c)' -Default 'D') }
    return $ap
}

# Ask which AI mode to use. Returns D, S, C, or N for none.
function Read-AiMode {
    param([string]$Prompt, [string]$Default = 'N')
    Write-Host "`nAI step (Gemini): host names, domains, accounts, groups, SIDs, paths, service/task names and addresses become tokens first; a leak check refuses to send if one survives. The exact text is saved next to the report." -ForegroundColor Cyan
    $m = (Read-Host $Prompt).Trim().ToUpper()
    if (-not $m) { return $Default }
    if ($m -in 'N', 'D', 'S', 'C') { return $m }
    return $Default
}

# Turns the mode into HostBadger parameters. If the mode sends, it asks for a key when there isn't
# one.
function Add-AiParams {
    param([hashtable]$Params, [string]$Mode)
    if ($Mode -eq 'N') { return }
    if (-not $Params.ContainsKey('SkipStig')) {
        Write-Host "`nThe DISA STIG findings can be hundreds per host. Sending them makes the prompt very large and Gemini may time out." -ForegroundColor Yellow
        $sendStig = "$(Read-Host 'Also send the DISA STIG findings to Gemini? (y/N)')".Trim()
        if ($sendStig -match '^[YySs]') { $Params['AiIncludeStig'] = $true }
    }
    if ($Mode -eq 'S' -or $Mode -eq 'C') {
        if (-not $env:GEMINI_API_KEY) {
            $k = Read-Host "GEMINI_API_KEY not set. Paste the key for this session (or Enter to do a dry run instead)"
            if ($k) { $env:GEMINI_API_KEY = $k.Trim() }
        }
        if ($env:GEMINI_API_KEY) {
            $Params['SendToAI'] = $true
            if ($Mode -eq 'C') { $Params['AiConfirm'] = $true }
            $m = Read-Host "Gemini model [gemini-3.7-flash]"
            if ($m.Trim()) { $Params['Model'] = $m.Trim() }
            $r = Read-Host "Gemini attempts on timeout / busy server, 0 = keep trying [3]"
            if ($r -match '^\d+$') { $Params['AiMaxAttempts'] = [int]$r }
            return
        }
        $Mode = 'D'
    }
    $Params['AiDryRun'] = Read-Path "Dry-run output file" ("hostbadger_ai_prompt_{0}.txt" -f (Ts))
}

# After the report, offer the AI summary. It runs the analysis again with the AI step on, so the
# report on disk gets the AI section (or, in a dry run, the prompt file appears).
function Invoke-AiOffer {
    param([hashtable]$Params)
    if (-not (Test-Path -LiteralPath $Params['OutHtml'])) { return }
    Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Report ready: $($Params['OutHtml'])" -ForegroundColor Green
    $mode = Read-AiMode 'Add an AI summary with Gemini?  [N]o, [D]ry run (only write the prompt), [S]end, [C]onfirm after reading the prompt (N/d/s/c)' -Default 'N'
    if ($mode -eq 'N') { return }
    $again = @{}; foreach ($k in $Params.Keys) { $again[$k] = $Params[$k] }
    Add-AiParams -Params $again -Mode $mode
    Invoke-Sub 'HostBadger.ps1' $again
}

Show-Banner
while ($true) {
    Write-Host ""
    Write-Host "  [1] Collect this machine        (read-only snapshot, as administrator for full coverage)" -ForegroundColor White
    Write-Host "  [2] Analyze snapshots           (a file, a zip or a folder of many hosts)" -ForegroundColor White
    Write-Host "  [3] Collect and analyze this machine" -ForegroundColor White
    Write-Host "  [4] Add an AI summary           (Gemini, names tokenized, dry run available)" -ForegroundColor White
    Write-Host "  [5] Safety review               (what the scripts can and cannot do)" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    $choice = (Read-Host "`nChoice").Trim().ToUpper()
    switch ($choice) {
        '1' { [void](Invoke-CollectStep) }
        '2' { $ap = Get-AnalysisParams; if ($ap) { Invoke-Sub 'HostBadger.ps1' $ap; Invoke-AiOffer $ap } }
        '3' {
            $dir = [string](@(Invoke-CollectStep) | Select-Object -Last 1)
            if ($dir) { $ap = Get-AnalysisParams -Snapshot $dir; if ($ap) { Invoke-Sub 'HostBadger.ps1' $ap; Invoke-AiOffer $ap } }
        }
        '4' { $ap = Get-AnalysisParams -WithAi $true; if ($ap) { Invoke-Sub 'HostBadger.ps1' $ap } }
        '5' { Invoke-Sub 'Test-HostBadgerSafety.ps1' }
        'Q' { break }
        default { Write-Host "Pick 1-5 or Q." -ForegroundColor Yellow }
    }
    if ($choice -eq 'Q') { break }
}
Write-Host "Bye." -ForegroundColor DarkYellow
