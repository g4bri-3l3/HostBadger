<#
.SYNOPSIS
    HostBadger launcher: one guided entry point for collection and analysis.

.DESCRIPTION
    A small menu, so nobody has to remember parameters:

      1  Collect this machine            (Collect-HostSnapshot.ps1, read-only)
      2  Analyze snapshots               (HostBadger.ps1: one snapshot, a zip or a folder of them)
      3  Collect and analyze this machine
      4  Analyze with an AI summary      (Gemini; names replaced by tokens first)
      5  Safety review                   (Test-HostBadgerSafety.ps1: what the scripts can do)
      6  Remediate this machine          (collect, analyze, preview the fixes, apply after YES)
      7  Restore a remediation backup    (put back the values a remediation changed)

    Options 1 to 5 change nothing on the machine. Option 6 is the only part of
    HostBadger that changes settings, and only on this machine, as
    administrator: it shows what the fix script would change, asks you to type
    YES, creates a System Restore point where Windows has one, and the script
    writes the previous value of every setting to a rollback file that option 7
    puts back. Removing preinstalled apps is asked one group at a time and
    cannot be rolled back (they come back from the Microsoft Store). The AI step
    sends nothing unless you choose it, and shows you the exact text first when
    you ask for a dry run.

    The answers of a run are saved as you give them (output\hostbadger-wizard-
    state.json, never passwords or keys), so a run stopped halfway can be
    resumed at the next start; a finished run removes the file. At the end of
    an analysis the menu offers to open the report in the default browser.

    Each session is logged in output\hostbadger-menu_<time>.log: the questions,
    the answers typed and what the collection and the analysis printed (each
    analysis also writes <report>.log next to its report). Passwords and the
    Gemini key are typed hidden and never reach a log.

    At the start the menu says whether it runs as administrator. If not, it
    marks the options that need it and, at an interactive console, offers to
    restart itself elevated (Windows asks you to confirm, UAC).

    Catalogs downloaded by an earlier analysis (CISA KEV, LOLDrivers,
    endoflife.date, Chocolatey, NVD/EPSS: <report>_kev.json and the like, next
    to the report or in .\output) are offered again: Enter uses the newest kept
    copy, O downloads a fresh one.

    Double-click use: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-HostBadger.ps1
    (the policy is bypassed for that process only; a policy enforced by GPO still wins).

.EXAMPLE
    .\Start-HostBadger.ps1
#>

[CmdletBinding()]
Param(
    # Set by the restart as administrator: Windows starts an elevated process in System32, so the new
    # window is brought back to the folder the menu was started from.
    [string]$StartIn = ''
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if ($StartIn -and (Test-Path -LiteralPath $StartIn -PathType Container)) { Set-Location -LiteralPath $StartIn }

function Show-Banner {
    $art = @(
        ''
        '    _.--""--._'
        '  .''  |    |  ''.'
        ' /    |    |    \      HostBadger v1.6'
        '|  (o)|    |(o)  |     Windows host hardening'
        '|     |    |     |     collect, analyze, optional AI summary'
        ' \    ''.__.''    /'
        '  ''._   \/   _.'''
        '     ''--..--''          github.com/g4bri-3l3/HostBadger'
        ''
    )
    $width = ($art | Measure-Object -Property Length -Maximum).Maximum + 4
    $edge = ' ' + ('#' * ($width + 2))
    Write-Host $edge -ForegroundColor DarkYellow
    foreach ($line in $art) { Write-Host (' #  ' + $line.PadRight($width - 2) + '#') -ForegroundColor DarkYellow }
    Write-Host $edge -ForegroundColor DarkYellow
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

# ---------------- Saved progress: the answers of an unfinished run, written after every answer (so a
# Ctrl+C or a closed window keeps them) and offered at the next start. Never saved: passwords, the
# Gemini key, the menu choice and the YES of a remediation. HOSTBADGER_NO_RESUME turns it off (tests).
$script:StatePath = Join-Path (Join-Path $PWD.Path 'output') 'hostbadger-wizard-state.json'
$script:State = $null
$script:Resume = @{}
$script:ResumeChoice = ''
function Test-ResumeEnabled { return -not $env:HOSTBADGER_NO_RESUME }
function Save-WizardState {
    if (-not $script:State -or -not (Test-ResumeEnabled)) { return }
    try {
        $dir = Split-Path -Parent $script:StatePath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $script:State['savedUtc'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
        [System.IO.File]::WriteAllText($script:StatePath, (ConvertTo-Json -InputObject $script:State -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    }
    catch { }
}
function Start-WizardState {
    param([string]$Flow)
    $script:State = [ordered]@{ version = 1; flow = $Flow; stage = 'questions'; savedUtc = ''; answers = [ordered]@{} }
    Save-WizardState
}
function Set-WizardStage { param([string]$Stage) if ($script:State) { $script:State['stage'] = $Stage; Save-WizardState } }
function Set-WizardValue { param([string]$Key, $Value) if ($script:State) { $script:State['answers'][$Key] = $Value; Save-WizardState } }
function Clear-WizardState {
    $script:State = $null; $script:Resume = @{}
    if (Test-Path -LiteralPath $script:StatePath) { Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue }
}
# One answer: the saved one when resuming (keyed by the question), else asked; then saved.
function Get-Answer {
    param([string]$Key, [scriptblock]$Ask)
    if ($script:Resume.ContainsKey($Key)) {
        $v = $script:Resume[$Key]; $script:Resume.Remove($Key)
        Write-Host "$Key -> $(if ("$v") { $v } else { '(Enter)' })   (resumed)" -ForegroundColor DarkGray
    }
    else { $v = & $Ask }
    Set-WizardValue $Key "$v"
    return "$v"
}
function Read-Line { param([string]$Prompt) return (Get-Answer $Prompt { Read-Host $Prompt }) }

# Path prompt with Tab completion; falls back to Read-Host when redirected.
function Read-Path {
    param([string]$Prompt, [string]$Default = "")
    return (Get-Answer $Prompt { Read-PathRaw -Prompt $Prompt -Default $Default })
}
function Read-PathRaw {
    param([string]$Prompt, [string]$Default = "")
    $label = "$Prompt" + $(if ($Default) { " [$Default]" } else { "" })
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { $v = Read-Host $label; if ([string]::IsNullOrWhiteSpace($v)) { return $Default } return $v.Trim() }
    # The typing is echoed straight to the console; on Enter the whole line is written again through
    # the host (same text, same place), so the session log gets "prompt: answer" once.
    [Console]::Write("${label}: "); $buf = ''; $tm = @(); $ti = 0
    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') { Write-Host "`r${label}: $buf"; if ([string]::IsNullOrWhiteSpace($buf)) { return $Default } return $buf.Trim() }
        elseif ($key.Key -eq 'Backspace') { if ($buf.Length) { $buf = $buf.Substring(0, $buf.Length - 1); [Console]::Write("`b `b") }; $tm = @() }
        elseif ($key.Key -eq 'Tab') {
            if ($tm.Count -eq 0) {
                $hd = $buf -match '[\\/]'; $dir = if ($hd) { Split-Path $buf -Parent } else { '.' }; $leaf = if ($buf) { Split-Path $buf -Leaf } else { '' }
                try { $tm = @(Get-ChildItem -LiteralPath $dir -Filter ($leaf + '*') -ErrorAction SilentlyContinue | ForEach-Object { $n = if ($_.PSIsContainer) { $_.Name + [IO.Path]::DirectorySeparatorChar } else { $_.Name }; if ($hd) { Join-Path $dir $n } else { $n } }) } catch { $tm = @() }
                $ti = 0
            }
            if ($tm.Count) { $c = $tm[$ti % $tm.Count]; $ti++; if ($buf.Length) { [Console]::Write(("`b" * $buf.Length) + (" " * $buf.Length) + ("`b" * $buf.Length)) }; $buf = $c; [Console]::Write($buf) }
        }
        elseif ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) { $buf += $key.KeyChar; [Console]::Write($key.KeyChar); $tm = @() }
    }
}
function Ts { Get-Date -Format 'yyyyMMdd_HHmmss' }

# ---------------- Session log: the whole menu session (the questions and the answers typed, and what the
# collector and the analysis print) in output\hostbadger-menu_<time>.log, a PowerShell transcript. An
# analysis also writes its own log next to its report. Passwords and the Gemini key are asked with
# hidden input and never reach either file.
$script:SessionLog = ''
function Start-SessionLog {
    try {
        $dir = Join-Path $PWD.ProviderPath 'output'
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $path = Join-Path $dir "hostbadger-menu_$(Ts).log"
        $head = @("HostBadger guided menu session log", "Started:    $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) ($((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC)",
            "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))", "Folder:     $($PWD.ProviderPath)")
        [System.IO.File]::WriteAllText($path, (($head -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
        Start-Transcript -LiteralPath $path -Append | Out-Null
        $script:SessionLog = $path
    }
    catch { Write-Warning "Session log not written: $($_.Exception.Message)" }
}
function Stop-SessionLog {
    if (-not $script:SessionLog) { return }
    try { Stop-Transcript | Out-Null } catch { }
    Write-Host "Session log: $($script:SessionLog)" -ForegroundColor DarkGray
    $script:SessionLog = ''
}
function Test-Yes { param([string]$Prompt) return ((Read-Line $Prompt) -match '^[YySs]') }

# At the end of an analysis: open the report with the program Windows uses for .html (the default
# browser). Asked only at an interactive console.
function Open-Report {
    param([string]$Path)
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected -or -not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    if ("$(Read-Host 'Open the report in your browser? (Y/n)')".Trim() -notmatch '^[Nn]') { Invoke-Item -LiteralPath $Path }
}

function Test-IsAdmin {
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { return $false }
}

# At the start, without administrator rights: offer to open the menu again elevated (only at an
# interactive console). Windows shows its UAC prompt; declined, the menu goes on as it is.
function Request-Elevation {
    $redirected = $true; try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { return }
    if ("$(Read-Host 'Restart this menu as administrator? Windows asks you to confirm (y/N)')".Trim() -notmatch '^[YySs]') { return }
    $exe = (Get-Process -Id $PID).Path
    # A folder ending in "\" would escape the closing quote ("C:\"): "C:\." is the same folder.
    $here = $PWD.ProviderPath; if ($here.EndsWith('\')) { $here += '.' }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-StartIn', ('"{0}"' -f $here))
    try {
        Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        Write-Host 'The menu goes on in the new administrator window.' -ForegroundColor Green
        Stop-SessionLog
        exit 0
    }
    catch { Write-Host "Not restarted ($($_.Exception.Message)): the menu goes on without administrator rights." -ForegroundColor Yellow }
}

# ---------------- Catalogs an analysis can download. Each download is kept next to its report
# (<report>_kev.json ...); the next analysis offers the newest kept copy (next to the new report or in
# .\output) as the default, and asks whether to download a fresh one instead.
$script:CatalogDefs = [ordered]@{
    Kev     = @{ Label = 'CISA KEV catalog'; Suffix = 'kev'; Online = 'KevOnline'; File = 'KevFile'; Site = 'www.cisa.gov'; Off = 'none'; OffPrompt = 'none'
        Prompt = 'CISA KEV catalog: [N]one, [O]nline download, or a [F]ile you already have (N/o/f)' }
    Drivers = @{ Label = 'LOLDrivers catalog'; Suffix = 'drivers'; Online = 'DriversOnline'; File = 'DriversFile'; Site = 'www.loldrivers.io'; Off = 'the copy HostBadger ships'; OffPrompt = 'the copy HostBadger ships'
        Prompt = 'Download a fresh LOLDrivers catalog from www.loldrivers.io? (y/N)' }
    Eol     = @{ Label = 'Software lifecycle'; Suffix = 'eol'; Online = 'EolOnline'; File = 'EolFile'; Site = 'endoflife.date'; Off = 'the table HostBadger ships'; OffPrompt = 'the table HostBadger ships'
        Prompt = 'Download software lifecycle data from endoflife.date? (y/N)' }
    Choco   = @{ Label = 'Program versions'; Suffix = 'choco'; Online = 'ChocoOnline'; File = 'ChocoFile'; Site = 'community.chocolatey.org'; Off = 'no'; OffPrompt = 'skip it'
        Prompt = 'Download program versions from community.chocolatey.org? (y/N)' }
    Cve     = @{ Label = 'CVEs and EPSS'; Suffix = 'cve'; Online = 'CveOnline'; File = 'CveFile'; Site = 'services.nvd.nist.gov, epss.empiricalsecurity.com'; Off = 'no'; OffPrompt = 'skip it'
        Prompt = 'Download CVEs from NVD and EPSS scores from FIRST? (y/N)' }
}

# The newest kept copy of a catalog (<anything>_<suffix>.json), or nothing.
function Find-KeptCatalog {
    param([string]$Suffix, [string]$Report)
    $full = if ([System.IO.Path]::IsPathRooted($Report)) { $Report } else { Join-Path $PWD.ProviderPath $Report }
    $dirs = @((Split-Path -Parent $full), (Join-Path $PWD.ProviderPath 'output')) | Sort-Object -Unique
    $hits = @(foreach ($d in $dirs) {
            if (Test-Path -LiteralPath $d -PathType Container) {
                Get-ChildItem -LiteralPath $d -File -Filter "*_$Suffix.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*_$Suffix.json" -and $_.Length -gt 0 }
            }
        })
    if ($hits.Count -eq 0) { return }
    return ($hits | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
}

function Get-CatalogPrompt {
    param([string]$Name, [bool]$Kept)
    $c = $script:CatalogDefs[$Name]
    if (-not $Kept) { return $c.Prompt }
    if ($Name -eq 'Kev') { return "$($c.Label): [U]se the kept copy, [O]nline download, a [F]ile you already have, or [N]one (U/o/f/n)" }
    return "$($c.Label): [U]se the kept copy, download a fresh one [O]nline, or [N]o, $($c.OffPrompt) (U/o/n)"
}

# Ask about one catalog and set its parameters. With a kept copy, Enter (or U) uses it. -Edit is the
# review screen: asked again, never resumed, and the new answer saved under its question.
function Set-CatalogChoice {
    param([hashtable]$Ap, [string]$Name, [switch]$Edit)
    $c = $script:CatalogDefs[$Name]
    $kept = Find-KeptCatalog -Suffix $c.Suffix -Report $Ap['OutHtml']
    if ($kept) {
        $age = (Get-Date) - $kept.LastWriteTime
        $ageText = if ($age.TotalDays -ge 2) { '{0} days ago' -f [math]::Floor($age.TotalDays) } elseif ($age.TotalHours -ge 2) { '{0} hours ago' -f [math]::Floor($age.TotalHours) } else { 'less than 2 hours ago' }
        $stale = if ($age.TotalDays -gt 7) { ' It is over a week old: a fresh download is advisable.' } else { '' }
        Write-Host ("Kept from an earlier run: {0} ({1:yyyy-MM-dd HH:mm}, {2}).{3}" -f $kept.FullName, $kept.LastWriteTime, $ageText, $stale) -ForegroundColor DarkGray
    }
    $prompt = Get-CatalogPrompt -Name $Name -Kept ([bool]$kept)
    if ($Edit) { $ans = "$(Read-Host $prompt)"; Set-WizardValue $prompt $ans } else { $ans = Read-Line $prompt }
    $ans = $ans.Trim().ToUpper()
    $Ap.Remove($c.Online); $Ap.Remove($c.File)
    if ($ans -match '^[OYS]') { $Ap[$c.Online] = $true }
    elseif ($ans -eq 'F' -and $Name -eq 'Kev') {
        $kp = if ($Edit) { Read-PathRaw 'Path of known_exploited_vulnerabilities.json' '' } else { Read-Path 'Path of known_exploited_vulnerabilities.json' }
        if ($Edit) { Set-WizardValue 'Path of known_exploited_vulnerabilities.json' $kp }
        if ($kp -and (Test-Path -LiteralPath $kp)) { $Ap['KevFile'] = $kp } else { Write-Host "Not found, KEV skipped: $kp" -ForegroundColor Yellow }
    }
    elseif ($kept -and ($ans -eq '' -or $ans -eq 'U')) { $Ap[$c.File] = $kept.FullName }
}

# How a catalog choice reads on the review screen.
function Get-CatalogSummary {
    param([hashtable]$Ap, [string]$Name)
    $c = $script:CatalogDefs[$Name]
    if ($Ap[$c.Online]) { return "download ($($c.Site))" }
    if ($Ap[$c.File]) { return "file $($Ap[$c.File])" }
    return $c.Off
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
    # Encryption of the snapshot (.hbx): nothing is written in clear. The password goes to the collector
    # in this process, never on a command line.
    Write-Host "`nThe snapshot describes this machine in detail. Encrypt it: with a password (asked again when you analyze it), or to a certificate (a .cer file or a thumbprint; only the holder of the private key can read it)." -ForegroundColor DarkGray
    $encAns = "$(Read-Line 'Encrypt the snapshot? [P]assword, [C]ertificate, [N]o (p/c/N)')".Trim().ToUpper()
    if ($encAns -eq 'C') {
        $cert = Read-Path 'Certificate (.cer file or thumbprint)'
        if ($cert) { $p['EncryptCertificate'] = $cert } else { Write-Host 'No certificate given: the snapshot is not encrypted.' -ForegroundColor Yellow }
    }
    elseif ($encAns -eq 'P') {
        $pw1 = Read-Host 'Password' -AsSecureString
        $pw2 = Read-Host 'Password again' -AsSecureString
        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1); $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2)
        try { $t1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1); $t2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
        if (-not $t1 -or $t1 -cne $t2) { Write-Host 'The passwords are empty or do not match: nothing collected.' -ForegroundColor Red; return '' }
        $p['EncryptPassword'] = $t1
        $script:CollectPassword = $pw1
    }
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

# The snapshots in a folder, read from their file names (hostsnapshot_<host>_<yyyyMMddHHmmss>.zip, .hbx or
# .json; the time in the name is UTC). Without -Recurse only the folder itself is looked at.
function Get-SnapshotList {
    param([string]$Dir, [switch]$Recurse)
    $args2 = @{ LiteralPath = $Dir; File = $true; ErrorAction = 'SilentlyContinue' }
    if ($Recurse) { $args2['Recurse'] = $true }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem @args2 | Where-Object { $_.Name -match '^hostsnapshot_.+\.(json|zip|hbx)$' })) {
        $m = [regex]::Match($f.Name, '^hostsnapshot_(?<host>.+)_(?<ts>\d{14})\.(json|zip|hbx)$')
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
    # The snapshot is saved as the path it resolved to, not as the number picked in the list.
    if (-not $Snapshot) { $Snapshot = Get-Answer 'Snapshot' { Select-Snapshot } }
    if (-not $Snapshot -or -not (Test-Path -LiteralPath $Snapshot)) { Write-Host "Snapshot not found." -ForegroundColor Red; return $null }
    $ap['Snapshot'] = $Snapshot
    # Encrypted snapshots: the password is asked once here, so the AI re-run does not ask again.
    # A folder is searched; a single file is just looked at (Get-ChildItem -Recurse on a file walks far more).
    $hbx = if ((Get-Item -LiteralPath $Snapshot).PSIsContainer) { @(Get-ChildItem -LiteralPath $Snapshot -Recurse -File -Filter 'hostsnapshot_*.hbx' -ErrorAction SilentlyContinue) }
    else { @(Get-Item -LiteralPath $Snapshot | Where-Object { $_.Extension -eq '.hbx' }) }
    if ($hbx.Count -gt 0 -and -not $script:CollectPassword) {
        $pw = Read-Host "Password of the $($hbx.Count) encrypted snapshot(s) (Enter if they are encrypted to a certificate)" -AsSecureString
        if ($pw.Length -gt 0) { $ap['SnapshotPassword'] = $pw }
    }
    elseif ($hbx.Count -gt 0) { $ap['SnapshotPassword'] = $script:CollectPassword }
    $ap['OutHtml'] = Read-Path "Report HTML path" ("output\hostbadger_{0}.html" -f (Ts))
    # Only when the folder holds snapshots of more than one host: one report each, on by default.
    if ((Get-Item -LiteralPath $Snapshot).PSIsContainer) {
        $hostCount = @(Get-SnapshotList -Dir $Snapshot -Recurse | ForEach-Object { $_.Host.ToLower() } | Sort-Object -Unique).Count
        if ($hostCount -gt 1) {
            Write-Host "`n$hostCount hosts found: HostBadger can also write one report per host, next to the fleet report." -ForegroundColor DarkGray
            $ans = "$(Read-Line 'One report per host? (Y/n)')".Trim()
            if ($ans -notmatch '^[Nn]') { $ap['PerHost'] = $true }
        }
    }
    Write-Host "`nThe report also judges about 500 DISA STIG registry rules (Windows 11, Defender, Firewall, Edge, Chrome, Firefox, Office). A host that is not managed against the STIG shows hundreds of 'not configured' findings." -ForegroundColor DarkGray
    $stigAns = "$(Read-Line 'Include the DISA STIG rules? (Y/n)')".Trim()
    if ($stigAns -match '^[Nn]') { $ap['SkipStig'] = $true }
    $cisAns = "$(Read-Line 'Show the CIS-based findings in the report? (Y/n)')".Trim()
    if ($cisAns -match '^[Nn]') { $ap['HideCis'] = $true }
    if (-not $ap.ContainsKey('SkipStig')) {
        $stigShow = "$(Read-Line 'Show the DISA STIG findings in the report? (Y/n)')".Trim()
        if ($stigShow -match '^[Nn]') { $ap['HideStig'] = $true }
    }
    Write-Host "`nCatalogs: each download is kept next to its report, and the next analysis offers the newest kept copy (Enter) or a fresh download (O)." -ForegroundColor DarkGray
    Write-Host "`nCISA KEV: installed software can be compared with the catalog of vulnerabilities known to be exploited. The match is by vendor and product name only (the catalog has no version ranges), so it is a lead to verify. Downloading connects to www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (one HTTPS GET, nothing is sent); a copy is kept next to the report." -ForegroundColor DarkGray
    Set-CatalogChoice -Ap $ap -Name 'Kev'
    Write-Host "`nVulnerable drivers: the driver files on the hosts are compared, by SHA-256, with the LOLDrivers catalog of known vulnerable and malicious drivers. HostBadger ships a copy of it; a fresh one is a download from www.loldrivers.io/api/drivers.json (one HTTPS GET of about 30 MB, nothing is sent), kept next to the report." -ForegroundColor DarkGray
    Set-CatalogChoice -Ap $ap -Name 'Drivers'
    Write-Host "`nSoftware lifecycle: without a download, programs past their end of support are found with the table HostBadger ships. With current data from endoflife.date the dates are up to date and programs that missed a newer release of their line are flagged too (Python, Node.js, .NET, Office, Exchange, Java, Firefox, Chrome, Notepad++, PowerShell, VirtualBox, Wireshark). Downloading connects to endoflife.date/api/v1/products/full (one HTTPS GET of about 3 MB, nothing is sent); a copy is kept next to the report." -ForegroundColor DarkGray
    Set-CatalogChoice -Ap $ap -Name 'Eol'
    Write-Host "`nOther programs (7-Zip, VLC, Git, GIMP, WinSCP, PuTTY, FileZilla, KeePass, Audacity, Mullvad VPN, OBS Studio, AnyDesk) are compared with the versions published on the Chocolatey community repository. Downloading connects to community.chocolatey.org/api/v2/ (a few HTTPS GETs per program, the same list whatever the hosts have, nothing is sent); a copy is kept next to the report." -ForegroundColor DarkGray
    Set-CatalogChoice -Ap $ap -Name 'Choco'
    Write-Host "`nKnown vulnerabilities: the installed versions of Python, Node.js, .NET, Notepad++, PowerShell 7, VirtualBox, Wireshark, 7-Zip, VLC, Git, GIMP, WinSCP, PuTTY, FileZilla, KeePass, Audacity, Mullvad VPN and AnyDesk can be checked against their CVEs, with the EPSS probability of exploitation. Downloading connects to services.nvd.nist.gov (the CVEs of each product, never its version: the same list whatever the hosts have; about 2.5 minutes, faster with NVD_API_KEY) and epss.empiricalsecurity.com (one file of about 3 MB). Nothing is sent; a copy is kept next to the report." -ForegroundColor DarkGray
    Set-CatalogChoice -Ap $ap -Name 'Cve'
    if (Test-Yes "Also write JSON Lines for a SIEM? (y/N)") { $ap['OutJsonl'] = Read-Path "JSON Lines path" ($ap['OutHtml'] -replace '\.html?$', '.jsonl') }
    Write-Host "`nRemediation scripts: the report already shows a fix script under each check whose fix is one safe setting. HostBadger can also write one remediate_<host>.ps1 per host with all of that host's fixes in one file, for a scripted rollout. They are text files: HostBadger never runs them, they only preview until run with -Apply, and they write a rollback file. Read them and test on a pilot host first." -ForegroundColor DarkGray
    if (Test-Yes 'Write one remediation script per host? (y/N)') { $ap['OutRemediation'] = Read-Path "Folder for the remediation scripts" ($ap['OutHtml'] -replace '\.html?$', '_remediation') }
    $prev = Read-Path "Findings CSV of an earlier run, to show new and resolved (optional, Enter to skip)"
    if ($prev) { if (Test-Path -LiteralPath $prev) { $ap['CompareTo'] = $prev } else { Write-Host "Not found, comparison skipped: $prev" -ForegroundColor Yellow } }
    $exc = Read-Path "Exceptions file (accepted risks, optional, Enter to skip)"
    if ($exc) { if (Test-Path -LiteralPath $exc) { $ap['ExceptionsFile'] = $exc } else { Write-Host "Not found, exceptions skipped: $exc" -ForegroundColor Yellow } }
    Write-Host "`nLocal administrators: HostBadger reports every member of the local Administrators group that it doesn't expect (Domain Admins and the built-in Administrator are always expected)." -ForegroundColor DarkGray
    Write-Host "If some belong there (for example an IT group), list them as DOMAIN/Name or by SID, comma separated, and they won't be reported." -ForegroundColor DarkGray
    $adm = Read-Line "Allowed local administrators, e.g. CORP/Workstation Admins, CORP/helpdesk (Enter = none)"
    if ($adm.Trim()) { $ap['AllowedAdmins'] = @($adm -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    Write-Host "`nEDR: HostBadger shows which known EDR agent each host runs (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend Micro and others) and flags one that is stopped. Name the one every host should have and a host without it is flagged too." -ForegroundColor DarkGray
    $edr = Read-Line "EDR every host should run, e.g. CrowdStrike or SentinelOne, comma separated (Enter = none)"
    if ($edr.Trim()) { $ap['ExpectedEdr'] = @($edr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    # Everything asked: show it, and let any answer be changed before the run.
    $ap = Edit-AnalysisParams $ap
    if (-not $ap) { Write-Host 'Cancelled: nothing was run.' -ForegroundColor Yellow; return $null }
    # Option 4 asks about the AI step up front. Options 2 and 3 offer it once the report is written.
    if ($WithAi) { Add-AiParams -Params $ap -Mode (Read-AiMode 'AI summary (Gemini): [D]ry run (write the prompt, send nothing), [S]end, [C]onfirm first after reading the prompt (D/s/c)' -Default 'D') }
    return $ap
}

# The answers of an analysis, numbered, before it runs: Enter runs it, a number changes that answer (a
# yes/no flips, a path or a list is typed again, "-" clears it), Q cancels. A change also updates the
# saved answer under its question, so a resumed run gets it.
function Edit-AnalysisParams {
    param([hashtable]$Ap)
    $q = @{
        PerHost = 'One report per host? (Y/n)'; Stig = 'Include the DISA STIG rules? (Y/n)'; Cis = 'Show the CIS-based findings in the report? (Y/n)'
        StigShow = 'Show the DISA STIG findings in the report? (Y/n)'; Jsonl = 'Also write JSON Lines for a SIEM? (y/N)'; JsonlPath = 'JSON Lines path'
        Rem = 'Write one remediation script per host? (y/N)'; RemPath = 'Folder for the remediation scripts'
        Compare = 'Findings CSV of an earlier run, to show new and resolved (optional, Enter to skip)'; Exceptions = 'Exceptions file (accepted risks, optional, Enter to skip)'
        Admins = 'Allowed local administrators, e.g. CORP/Workstation Admins, CORP/helpdesk (Enter = none)'
        Edr = 'EDR every host should run, e.g. CrowdStrike or SentinelOne, comma separated (Enter = none)'
    }
    $flag = { param($k, $on, [string]$Key, [string]$OnText, [string]$OffText) if ($on) { $Ap[$k] = $true } else { $Ap.Remove($k) }; Set-WizardValue $Key $(if ($on) { $OnText } else { $OffText }) }
    $yn = { param($b) if ($b) { 'yes' } else { 'no' } }
    while ($true) {
        $isDir = (Test-Path -LiteralPath $Ap['Snapshot']) -and (Get-Item -LiteralPath $Ap['Snapshot']).PSIsContainer
        $multi = $isDir -and @(Get-SnapshotList -Dir $Ap['Snapshot'] -Recurse | ForEach-Object { $_.Host.ToLower() } | Sort-Object -Unique).Count -gt 1
        $items = New-Object System.Collections.Generic.List[object]
        $items.Add(@('Snapshot', 'Snapshot', $Ap['Snapshot'])); $items.Add(@('OutHtml', 'Report', $Ap['OutHtml']))
        if ($multi) { $items.Add(@('PerHost', 'One report per host', (& $yn $Ap['PerHost']))) }
        $items.Add(@('Stig', 'DISA STIG rules', (& $yn (-not $Ap['SkipStig']))))
        $items.Add(@('Cis', 'Show CIS-based findings', (& $yn (-not $Ap['HideCis']))))
        if (-not $Ap['SkipStig']) { $items.Add(@('StigShow', 'Show DISA STIG findings', (& $yn (-not $Ap['HideStig'])))) }
        foreach ($cn in $script:CatalogDefs.Keys) { $items.Add(@($cn, $script:CatalogDefs[$cn].Label, (Get-CatalogSummary -Ap $Ap -Name $cn))) }
        $items.Add(@('Jsonl', 'JSON Lines', $(if ($Ap['OutJsonl']) { $Ap['OutJsonl'] } else { 'no' })))
        $items.Add(@('Rem', 'Remediation scripts', $(if ($Ap['OutRemediation']) { $Ap['OutRemediation'] } else { 'no' })))
        $items.Add(@('Compare', 'Compare with', $(if ($Ap['CompareTo']) { $Ap['CompareTo'] } else { 'no' })))
        $items.Add(@('Exceptions', 'Exceptions file', $(if ($Ap['ExceptionsFile']) { $Ap['ExceptionsFile'] } else { 'no' })))
        $items.Add(@('Admins', 'Allowed administrators', $(if ($Ap['AllowedAdmins']) { @($Ap['AllowedAdmins']) -join ', ' } else { 'none' })))
        $items.Add(@('Edr', 'Expected EDR', $(if ($Ap['ExpectedEdr']) { @($Ap['ExpectedEdr']) -join ', ' } else { 'none' })))
        Write-Host "`nSettings for this run:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $items.Count; $i++) { Write-Host ("  [{0,2}] {1,-24} {2}" -f ($i + 1), $items[$i][1], $items[$i][2]) }
        $pick = "$(Read-Host 'Run with these settings? Enter = run, a number = change it, Q = cancel')".Trim()
        if (-not $pick) { return $Ap }
        if ($pick -match '^[Qq]') { return $null }
        if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $items.Count) { Write-Host "Pick 1-$($items.Count), Enter or Q." -ForegroundColor Yellow; continue }
        switch ($items[[int]$pick - 1][0]) {
            'Snapshot' {
                $v = Read-PathRaw 'Snapshot file, zip or folder' $Ap['Snapshot']
                if ($v -and (Test-Path -LiteralPath $v)) {
                    $Ap['Snapshot'] = $v; Set-WizardValue 'Snapshot' $v
                    $hbx = if ((Get-Item -LiteralPath $v).PSIsContainer) { @(Get-ChildItem -LiteralPath $v -Recurse -File -Filter 'hostsnapshot_*.hbx' -ErrorAction SilentlyContinue) } else { @(Get-Item -LiteralPath $v | Where-Object { $_.Extension -eq '.hbx' }) }
                    if ($hbx.Count -gt 0 -and -not $Ap['SnapshotPassword']) {
                        $pw = Read-Host "Password of the $($hbx.Count) encrypted snapshot(s) (Enter if they are encrypted to a certificate)" -AsSecureString
                        if ($pw.Length -gt 0) { $Ap['SnapshotPassword'] = $pw }
                    }
                }
                else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'OutHtml' { $v = Read-PathRaw 'Report HTML path' $Ap['OutHtml']; if ($v) { $Ap['OutHtml'] = $v; Set-WizardValue 'Report HTML path' $v } }
            'PerHost' { & $flag 'PerHost' (-not $Ap['PerHost']) $q.PerHost '' 'n' }
            'Stig' { $skip = -not $Ap['SkipStig']; & $flag 'SkipStig' $skip $q.Stig 'n' ''; if ($skip) { $Ap.Remove('HideStig') } }
            'Cis' { & $flag 'HideCis' (-not $Ap['HideCis']) $q.Cis 'n' '' }
            'StigShow' { & $flag 'HideStig' (-not $Ap['HideStig']) $q.StigShow 'n' '' }
            { $script:CatalogDefs.Contains($_) } { Set-CatalogChoice -Ap $Ap -Name $_ -Edit }
            'Jsonl' {
                $v = Read-PathRaw 'JSON Lines path ("-" for none)' $(if ($Ap['OutJsonl']) { $Ap['OutJsonl'] } else { $Ap['OutHtml'] -replace '\.html?$', '.jsonl' })
                if ($v -eq '-') { $Ap.Remove('OutJsonl'); Set-WizardValue $q.Jsonl '' } else { $Ap['OutJsonl'] = $v; Set-WizardValue $q.Jsonl 'y'; Set-WizardValue $q.JsonlPath $v }
            }
            'Rem' {
                $v = Read-PathRaw 'Folder for the remediation scripts ("-" for none)' $(if ($Ap['OutRemediation']) { $Ap['OutRemediation'] } else { $Ap['OutHtml'] -replace '\.html?$', '_remediation' })
                if ($v -eq '-') { $Ap.Remove('OutRemediation'); Set-WizardValue $q.Rem '' } else { $Ap['OutRemediation'] = $v; Set-WizardValue $q.Rem 'y'; Set-WizardValue $q.RemPath $v }
            }
            'Compare' {
                $v = Read-PathRaw 'Findings CSV of an earlier run ("-" for none)' $Ap['CompareTo']
                if ($v -eq '-' -or -not $v) { $Ap.Remove('CompareTo'); Set-WizardValue $q.Compare '' } elseif (Test-Path -LiteralPath $v) { $Ap['CompareTo'] = $v; Set-WizardValue $q.Compare $v } else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'Exceptions' {
                $v = Read-PathRaw 'Exceptions file ("-" for none)' $Ap['ExceptionsFile']
                if ($v -eq '-' -or -not $v) { $Ap.Remove('ExceptionsFile'); Set-WizardValue $q.Exceptions '' } elseif (Test-Path -LiteralPath $v) { $Ap['ExceptionsFile'] = $v; Set-WizardValue $q.Exceptions $v } else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'Admins' {
                $v = "$(Read-Host 'Allowed local administrators, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('AllowedAdmins'); Set-WizardValue $q.Admins '' } elseif ($v) { $Ap['AllowedAdmins'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Set-WizardValue $q.Admins $v }
            }
            'Edr' {
                $v = "$(Read-Host 'EDR every host should run, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('ExpectedEdr'); Set-WizardValue $q.Edr '' } elseif ($v) { $Ap['ExpectedEdr'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Set-WizardValue $q.Edr $v }
            }
        }
    }
}

# Ask which AI mode to use. Returns D, S, C, or N for none.
function Read-AiMode {
    param([string]$Prompt, [string]$Default = 'N')
    Write-Host "`nAI step (Gemini): host names, domains, accounts, groups, SIDs, paths, service/task names and addresses become tokens first; a leak check refuses to send if one survives. The exact text is saved next to the report." -ForegroundColor Cyan
    $m = (Read-Line $Prompt).Trim().ToUpper()
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
        $sendStig = "$(Read-Line 'Also send the DISA STIG findings to Gemini? (y/N)')".Trim()
        if ($sendStig -match '^[YySs]') { $Params['AiIncludeStig'] = $true }
    }
    if ($Mode -eq 'S' -or $Mode -eq 'C') {
        if (-not $env:GEMINI_API_KEY) {
            # Hidden input: the key is not echoed and does not reach the session log.
            $ks = Read-Host "GEMINI_API_KEY not set. Paste the key for this session (or Enter to do a dry run instead)" -AsSecureString
            $k = if ($ks -and $ks.Length) { (New-Object System.Net.NetworkCredential('', $ks)).Password } else { '' }
            if ($k) { $env:GEMINI_API_KEY = $k.Trim() }
        }
        if ($env:GEMINI_API_KEY) {
            $Params['SendToAI'] = $true
            if ($Mode -eq 'C') { $Params['AiConfirm'] = $true }
            $m = Read-Line "Gemini model [gemini-3.8-flash]"
            if ($m.Trim()) { $Params['Model'] = $m.Trim() }
            $r = Read-Line "Gemini attempts on timeout / busy server, 0 = keep trying [3]"
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
    # The catalogs downloaded for the report are kept next to it: the AI run reuses those copies, so it
    # downloads nothing again and works on the same data as the report.
    $stem = [System.IO.Path]::GetFullPath($Params['OutHtml']) -replace '\.html?$', ''
    if ($again['KevOnline'] -and (Test-Path -LiteralPath "${stem}_kev.json")) { $again.Remove('KevOnline'); $again['KevFile'] = "${stem}_kev.json" }
    if ($again['DriversOnline'] -and (Test-Path -LiteralPath "${stem}_drivers.json")) { $again.Remove('DriversOnline'); $again['DriversFile'] = "${stem}_drivers.json" }
    if ($again['EolOnline'] -and (Test-Path -LiteralPath "${stem}_eol.json")) { $again.Remove('EolOnline'); $again['EolFile'] = "${stem}_eol.json" }
    if ($again['ChocoOnline'] -and (Test-Path -LiteralPath "${stem}_choco.json")) { $again.Remove('ChocoOnline'); $again['ChocoFile'] = "${stem}_choco.json" }
    if ($again['CveOnline'] -and (Test-Path -LiteralPath "${stem}_cve.json")) { $again.Remove('CveOnline'); $again['CveFile'] = "${stem}_cve.json" }
    Add-AiParams -Params $again -Mode $mode
    Invoke-Sub 'HostBadger.ps1' $again
}

# ---------------- Remediation of this machine: the only part of HostBadger that changes anything.
# Each run gets a folder with its snapshot, report, fix script and rollback file.
$script:RemediationRoot = Join-Path (Join-Path $PWD.Path 'output') 'remediation'

function New-HbRestorePoint {
    # A System Restore point before the changes, where Windows has one (not on servers, not in
    # PowerShell 7, and Windows makes at most one a day).
    try {
        Checkpoint-Computer -Description 'HostBadger: before remediation' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Host 'System Restore point created (Windows skips it if one was made in the last 24 hours).' -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "No System Restore point: $($_.Exception.Message)" -ForegroundColor Yellow
        return (Test-Yes 'Go on without it? The rollback file still records every value changed (y/N)')
    }
}

function Invoke-BloatwareStep {
    # Preinstalled apps from the curated list in lib\Checks.ps1, removed only on an explicit yes, one
    # group at a time, for every user and from the provisioned list (new profiles).
    param([string]$Run)
    . (Join-Path $root 'lib\Common.ps1'); . (Join-Path $root 'lib\Checks.ps1')
    $installed = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
    $removed = @()
    foreach ($b in @($script:BloatwareApps | Where-Object { $_.Appx })) {
        $names = @(@($installed | ForEach-Object { "$($_.Name)" }) + @($provisioned | ForEach-Object { "$($_.DisplayName)" }) | Where-Object { $_ -match $b.Appx } | Sort-Object -Unique)
        if ($names.Count -eq 0) { continue }
        if (-not (Test-Yes "Remove $($b.Label) ($($names -join ', ')) for every user and from new profiles? It comes back only from the Microsoft Store (y/N)")) { continue }
        foreach ($n in $names) {
            try {
                $installed | Where-Object { "$($_.Name)" -eq $n } | Remove-AppxPackage -AllUsers -ErrorAction Stop
                $provisioned | Where-Object { "$($_.DisplayName)" -eq $n } | Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
                Write-Host "  removed $n" -ForegroundColor Green
                $removed += $n
            }
            catch { Write-Host "  $n not removed: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
    foreach ($b in @($script:BloatwareApps | Where-Object { $_.Program })) {
        $progs = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { "$((Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName)" } | Where-Object { $_ -match $b.Program } | Sort-Object -Unique)
        if ($progs.Count) { Write-Host "$($b.Label): $($progs -join ', '). Uninstall it from Settings > Apps (its own uninstaller)." -ForegroundColor Yellow }
    }
    if ($removed.Count) { [System.IO.File]::WriteAllText((Join-Path $Run 'removed_apps.json'), (ConvertTo-Json -InputObject @($removed)), (New-Object System.Text.UTF8Encoding($false))) }
}

function Invoke-RemediateStep {
    if (-not (Test-IsAdmin)) { Write-Host 'Remediation changes system settings: start an elevated PowerShell (Run as administrator), or restart the menu as administrator, and choose it again.' -ForegroundColor Yellow; return }
    Write-Host "`nRemediate this machine: HostBadger collects and analyzes this machine, then shows what its fix script would change. Only settings with a safe, reversible fix are in it (one value, the one the baseline expects, no organizational choice). Nothing changes until you type YES; a System Restore point comes first where Windows has one, and the script writes every previous value to a rollback file (menu 7 puts them back). Group Policy or Intune may set a value back on managed machines." -ForegroundColor DarkGray
    if (-not (Test-Yes 'Continue? (y/N)')) { return }
    $run = Join-Path $script:RemediationRoot (Ts)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    # Never resumed: an interrupted run is only explained at the next start (and option 7 offered).
    Start-WizardState 'remediate'; Set-WizardValue 'run' $run
    Invoke-Sub 'Collect-HostSnapshot.ps1' @{ OutDir = $run }
    $snap = @(Get-ChildItem -LiteralPath $run -Filter 'hostsnapshot_*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($snap.Count -eq 0) { Write-Host 'No snapshot produced; nothing changed.' -ForegroundColor Red; return }
    Invoke-Sub 'HostBadger.ps1' @{ Snapshot = $snap[0].FullName; OutHtml = (Join-Path $run 'report.html'); OutRemediation = $run }
    $fix = @(Get-ChildItem -LiteralPath $run -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($fix.Count -eq 0) { Write-Host 'No setting on this machine has a safe fix script.' -ForegroundColor Green }
    else {
        Write-Host "`nWhat the fix script would change (nothing changed yet):" -ForegroundColor Cyan
        try { & $fix[0].FullName | Out-Host } catch { Write-Host "Preview failed: $($_.Exception.Message)" -ForegroundColor Red; return }
        if ((Read-Host 'Apply these changes to this machine? Type YES to apply') -cne 'YES') { Write-Host 'Nothing changed.' -ForegroundColor Yellow }
        elseif (New-HbRestorePoint) {
            $rb = Join-Path $run 'rollback.json'
            Set-WizardStage 'applying'
            try { & $fix[0].FullName -Apply -RollbackFile $rb | Out-Host } catch { Write-Host "The fix script stopped: $($_.Exception.Message)" -ForegroundColor Red }
            if (Test-Path -LiteralPath $rb) { Write-Host "Previous values saved in $rb. Menu 7 puts them back." -ForegroundColor Green }
        }
    }
    Write-Host "`nPreinstalled apps: games, consumer apps and trials from HostBadger's list. Each group is asked separately." -ForegroundColor DarkGray
    if (Test-Yes 'Look for preinstalled apps to remove? (y/N)') { Invoke-BloatwareStep -Run $run }
    Write-Host "Report of this run: $(Join-Path $run 'report.html')" -ForegroundColor Green
}

function Invoke-RestoreStep {
    $runs = @(Get-ChildItem -LiteralPath $script:RemediationRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'rollback.json') } | Sort-Object Name -Descending)
    if ($runs.Count -eq 0) { Write-Host "No remediation backup found in $($script:RemediationRoot)." -ForegroundColor Yellow; return }
    for ($i = 0; $i -lt $runs.Count; $i++) {
        $n = @(Get-Content -LiteralPath (Join-Path $runs[$i].FullName 'rollback.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }).Count
        Write-Host ("  [{0}] {1}  ({2} value(s) changed)" -f ($i + 1), $runs[$i].Name, $n)
    }
    $pick = "$(Read-Host 'Which run to undo? (Enter = the newest)')".Trim()
    $idx = if ($pick -match '^\d+$') { [int]$pick - 1 } else { 0 }
    if ($idx -lt 0 -or $idx -ge $runs.Count) { Write-Host 'No such run.' -ForegroundColor Yellow; return }
    $run = $runs[$idx].FullName; $rb = Join-Path $run 'rollback.json'
    $fix = @(Get-ChildItem -LiteralPath $run -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($fix.Count -eq 0) { Write-Host "The fix script of that run is missing from $run." -ForegroundColor Red; return }
    Write-Host "`nWhat the restore would put back (nothing changed yet):" -ForegroundColor Cyan
    try { & $fix[0].FullName -Restore $rb | Out-Host } catch { Write-Host "Preview failed: $($_.Exception.Message)" -ForegroundColor Red; return }
    if (Test-Path -LiteralPath (Join-Path $run 'removed_apps.json')) { Write-Host 'Apps removed in that run are not reinstalled: get them back from the Microsoft Store.' -ForegroundColor Yellow }
    if (-not (Test-IsAdmin)) { Write-Host 'Restoring changes system settings: start an elevated PowerShell and choose it again.' -ForegroundColor Yellow; return }
    if ((Read-Host 'Put these values back? Type YES to restore') -cne 'YES') { Write-Host 'Nothing changed.' -ForegroundColor Yellow; return }
    try { & $fix[0].FullName -Restore $rb -Apply | Out-Host } catch { Write-Host "The restore stopped: $($_.Exception.Message)" -ForegroundColor Red }
}

Start-SessionLog
# The menu in try/finally: the session log is closed on Q, on an error and on Ctrl+C.
try {
    Show-Banner
    # Administrator or not, said up front: it decides what a collection sees and whether 6 and 7 can run.
    $script:IsAdmin = Test-IsAdmin
    if ($script:IsAdmin) { Write-Host '  Running as administrator: full collection, remediation and restore available.' -ForegroundColor Green }
    else {
        Write-Host "  Not running as administrator: a collection of this machine (1, 3) has gaps, listed as 'not evaluated' in the report, and remediation and restore (6, 7) cannot change anything. Analysis (2, 4) and the safety review (5) work as they are." -ForegroundColor Yellow
        Request-Elevation
    }
    # An unfinished run from last time: offered again (a remediation is only explained, never resumed).
    if ((Test-ResumeEnabled) -and (Test-Path -LiteralPath $script:StatePath)) {
        $st = $null; try { $st = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json } catch { }
        $flowNames = @{ collect = 'Collect this machine'; analyze = 'Analyze snapshots'; 'collect-analyze' = 'Collect and analyze this machine'; ai = 'Analyze with an AI summary'; remediate = 'Remediate this machine' }
        $flowChoice = @{ collect = '1'; analyze = '2'; 'collect-analyze' = '3'; ai = '4' }
        if ($st -and $flowNames.ContainsKey("$($st.flow)")) {
            Write-Host "`nUnfinished run, saved $($st.savedUtc): $($flowNames["$($st.flow)"])" -ForegroundColor Cyan
            if ("$($st.flow)" -eq 'remediate') {
                if ("$($st.stage)" -eq 'applying') { Write-Host "It stopped while applying fixes: some settings may have changed. The previous values are in $($st.answers.run)\rollback.json; option 7 puts them back." -ForegroundColor Yellow }
                else { Write-Host 'It stopped before anything was applied: nothing changed. Choose 6 to start again.' -ForegroundColor Yellow }
                Clear-WizardState
            }
            else {
                $saved = @{}; foreach ($pp in @($st.answers.PSObject.Properties)) { $saved[$pp.Name] = "$($pp.Value)" }
                foreach ($k in @('Snapshot', 'Report HTML path', 'Snapshot folder', 'collectedDir')) { if ($saved.ContainsKey($k) -and $saved[$k]) { Write-Host "  $k`: $($saved[$k])" -ForegroundColor DarkGray } }
                Write-Host "  $($saved.Count) answer(s) saved$(if ("$($st.stage)" -eq 'running') { '; it stopped while the analysis was running' }). Passwords and keys are asked again." -ForegroundColor DarkGray
                if ("$(Read-Host 'Resume it? (Y/n)')".Trim() -notmatch '^[Nn]') { $script:Resume = $saved; $script:ResumeChoice = $flowChoice["$($st.flow)"] }
                else { Clear-WizardState }
            }
        }
        else { Clear-WizardState }
    }
    while ($true) {
        Write-Host ""
        # Without administrator rights the options that need them say so.
        $na = -not $script:IsAdmin
        $gapColor = if ($na) { 'DarkYellow' } else { 'White' }
        Write-Host "  [1] Collect this machine        (read-only snapshot$(if ($na) { '; not administrator: with gaps' }))" -ForegroundColor $gapColor
        Write-Host "  [2] Analyze snapshots           (a file, a zip or a folder of many hosts)" -ForegroundColor White
        Write-Host "  [3] Collect and analyze this machine$(if ($na) { '   (not administrator: with gaps)' })" -ForegroundColor $gapColor
        Write-Host "  [4] Analyze with an AI summary  (Gemini, names tokenized, dry run available)" -ForegroundColor White
        Write-Host "  [5] Safety review               (what the scripts can and cannot do)" -ForegroundColor White
        if ($na) {
            Write-Host "  [6] Remediate this machine      (needs administrator)" -ForegroundColor DarkGray
            Write-Host "  [7] Restore a remediation backup (preview only; restoring needs administrator)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  [6] Remediate this machine      (preview, apply after YES, restore point and rollback)" -ForegroundColor White
            Write-Host "  [7] Restore a remediation backup" -ForegroundColor White
        }
        Write-Host "  [Q] Quit" -ForegroundColor White
        if ($script:ResumeChoice) { $choice = $script:ResumeChoice; $script:ResumeChoice = ''; Write-Host "`nChoice: $choice   (resumed)" -ForegroundColor DarkGray }
        else { $choice = (Read-Host "`nChoice").Trim().ToUpper() }
        switch ($choice) {
            '1' {
                Start-WizardState 'collect'
                if ([string](@(Invoke-CollectStep) | Select-Object -Last 1)) { Write-Host 'To analyze it: option 2 lists it.' -ForegroundColor DarkGray }
                Clear-WizardState
            }
            '2' {
                Start-WizardState 'analyze'
                $ap = Get-AnalysisParams
                if ($ap) {
                    Set-WizardStage 'running'
                    Invoke-Sub 'HostBadger.ps1' $ap
                    # Kept when the report did not come out, so the same answers can be tried again.
                    if (Test-Path -LiteralPath $ap['OutHtml']) { Clear-WizardState }
                    Invoke-AiOffer $ap; Open-Report $ap['OutHtml']
                }
                else { Clear-WizardState }
            }
            '3' {
                Start-WizardState 'collect-analyze'
                # A run that stopped after the collection resumes with the analysis.
                $dir = Get-Answer 'collectedDir' { [string](@(Invoke-CollectStep) | Select-Object -Last 1) }
                # The password just typed for the collection opens the snapshot without asking again
                # (Get-AnalysisParams passes $script:CollectPassword on).
                $ap = if ($dir) { Get-AnalysisParams -Snapshot $dir } else { $null }
                if ($ap) {
                    Set-WizardStage 'running'
                    Invoke-Sub 'HostBadger.ps1' $ap
                    if (Test-Path -LiteralPath $ap['OutHtml']) { Clear-WizardState }
                    Invoke-AiOffer $ap; Open-Report $ap['OutHtml']
                }
                else { Clear-WizardState }
            }
            '4' {
                Start-WizardState 'ai'
                $ap = Get-AnalysisParams -WithAi $true
                if ($ap) {
                    Set-WizardStage 'running'
                    Invoke-Sub 'HostBadger.ps1' $ap
                    if (Test-Path -LiteralPath $ap['OutHtml']) { Clear-WizardState }
                    Open-Report $ap['OutHtml']
                }
                else { Clear-WizardState }
            }
            '5' { Invoke-Sub 'Test-HostBadgerSafety.ps1' }
            '6' { Invoke-RemediateStep; Clear-WizardState }
            '7' { Invoke-RestoreStep }
            'Q' { break }
            default { Write-Host "Pick 1-7 or Q." -ForegroundColor Yellow }
        }
        if ($choice -eq 'Q') { break }
    }
    Write-Host "Bye." -ForegroundColor DarkYellow
}
finally { Stop-SessionLog }
