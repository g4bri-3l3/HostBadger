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
      8  Global settings                 (the answers a run asks every time, saved)

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

    Global settings (menu 8) keep the answers that are the same at every run
    (output\hostbadger-settings.json: report folder, STIG and CIS, catalogs,
    JSON Lines, remediation scripts, exceptions, allowed administrators, EDR,
    the AI step, and for a collection: snapshot folder, ACLs, missing updates
    and encryption). When the file exists, each run asks once whether to use
    them; with yes those questions are skipped, and the analysis lists every
    answer before it runs, still changeable for that run. Passwords and the
    Gemini key are never saved.

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
        ' /    |    |    \      HostBadger v2.0'
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
    # Windows cannot elevate a window that is already open. Best first: Windows 11 sudo in inline mode
    # (Settings > System > For developers > Enable sudo, "Inline") runs the menu in this same window and
    # comes back here; from Windows Terminal, an elevated Terminal window with the same shell; otherwise a
    # new console. -NoExit keeps the new window at a prompt in this folder when the menu ends.
    $sudo = Join-Path $env:SystemRoot 'System32\sudo.exe'
    $sudoMode = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    $wt = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wt.exe'
    if (-not $env:WT_SESSION -or -not (Test-Path -LiteralPath $wt)) { $wt = '' }
    try {
        if ("$sudoMode" -eq '3' -and (Test-Path -LiteralPath $sudo)) {
            Write-Host 'The menu goes on in this window as administrator (Windows sudo, inline).' -ForegroundColor Green
            Stop-SessionLog
            Start-Process -FilePath $sudo -ArgumentList (@(('"{0}"' -f $exe)) + $argList) -NoNewWindow -Wait -ErrorAction Stop
            exit 0
        }
        elseif ($wt) {
            Start-Process -FilePath $wt -ArgumentList (@('-d', ('"{0}"' -f $here), ('"{0}"' -f $exe), '-NoExit') + $argList) -Verb RunAs -ErrorAction Stop
            Write-Host 'The menu goes on in a new administrator Windows Terminal window (it stays open at a prompt when the menu ends).' -ForegroundColor Green
        }
        else {
            Start-Process -FilePath $exe -ArgumentList (@('-NoExit') + $argList) -Verb RunAs -ErrorAction Stop
            Write-Host 'The menu goes on in the new administrator window (it stays open at a prompt when the menu ends).' -ForegroundColor Green
        }
        Write-Host 'Tip: with Windows 11 sudo in inline mode (Settings > System > For developers) the menu stays in this window.' -ForegroundColor DarkGray
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
    Ext     = @{ Label = 'Malicious browser extensions'; Suffix = 'extensions'; Online = 'ExtensionsOnline'; File = 'ExtensionsFile'; Site = 'raw.githubusercontent.com'; Off = 'the copy HostBadger ships'; OffPrompt = 'the copy HostBadger ships'
        Prompt = 'Download the current list of browser extensions removed from the stores (malext.io)? (y/N)' }
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

# ---------------- Global settings (menu 8): the answers that are the same at every run, in
# output\hostbadger-settings.json (relative to the folder the menu runs in, like the saved progress).
# When the file exists, a collection or an analysis asks once whether to use them: with yes, those
# questions are skipped and the review screen lists the saved answers, still changeable for that run.
# Never saved: passwords, the Gemini key, the snapshot of a run and the CSV it is compared with.
$script:SettingsPath = Join-Path (Join-Path $PWD.Path 'output') 'hostbadger-settings.json'
$script:Global = $null
$script:UseGlobal = $null
$script:RunAi = ''
$script:AiModes = [ordered]@{ A = 'ask after the report'; N = 'no'; D = 'dry run (write the prompt, send nothing)'; S = 'send to Gemini'; C = 'send after reading the prompt' }
$script:AiModePrompt = 'AI summary (Gemini): [A]sk after the report, [N]o, [D]ry run, [S]end, [C]onfirm after reading the prompt (A/n/d/s/c)'

# Catalogs: kept (the newest kept copy, else as without a download), auto (the kept copy if it is at most
# a week old, else a download), online (a download every run), off, file (KEV only: KevFile). Ai is a
# letter of $script:AiModes. Lists are comma separated text (an empty array would be written "{}" by 5.1).
function New-GlobalSettings {
    return [ordered]@{
        version = 1; savedUtc = ''
        SnapshotDir = ''; SkipAcl = $false; CheckUpdates = $false; Encrypt = 'ask'; Certificate = ''
        ReportDir = 'output'; PerHost = $true; SkipStig = $false; HideCis = $false; HideStig = $false; Nis2Acn = $false
        Kev = 'kept'; KevFile = ''; Drivers = 'kept'; Eol = 'kept'; Choco = 'kept'; Cve = 'kept'
        Jsonl = $false; Remediation = $false; RemediationProfile = ''; RemediationDebloat = $false
        ExceptionsFile = ''; PolicyFile = ''; AllowedAdmins = ''; ExpectedEdr = ''; AllowedRemoteTools = ''; AllowedExtensions = ''
        Ai = 'A'; AiIncludeStig = $false; Model = ''; AiMaxAttempts = ''
    }
}

function Read-GlobalSettings {
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return }
    $s = New-GlobalSettings
    try { $j = [System.IO.File]::ReadAllText($script:SettingsPath) | ConvertFrom-Json }
    catch { Write-Host "Global settings not read ($($_.Exception.Message)): the questions are asked." -ForegroundColor Yellow; return }
    foreach ($p in @($j.PSObject.Properties)) { if ($s.Contains($p.Name) -and $null -ne $p.Value) { $s[$p.Name] = $p.Value } }
    if (-not $script:AiModes.Contains("$($s.Ai)")) { $s['Ai'] = 'A' }
    return $s
}

function Save-GlobalSettings {
    param($S)
    $S['savedUtc'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $dir = Split-Path -Parent $script:SettingsPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($script:SettingsPath, (ConvertTo-Json -InputObject $S), (New-Object System.Text.UTF8Encoding($false)))
}

# Asked once per menu choice (a collection followed by its analysis asks once), and only when settings
# are saved: without the file no question is added. The answer is saved like any other, so a resumed
# run gets it.
function Test-UseGlobal {
    if ($null -ne $script:UseGlobal) { return $script:UseGlobal }
    $script:UseGlobal = $false
    $script:Global = Read-GlobalSettings
    if ($script:Global) {
        Write-Host "`nGlobal settings saved $($script:Global.savedUtc) (menu 8): with them the usual questions are skipped, and an analysis still lists every answer before it runs." -ForegroundColor DarkGray
        $script:UseGlobal = ("$(Read-Line 'Use the global settings? (Y/n)')".Trim() -notmatch '^[Nn]')
    }
    return $script:UseGlobal
}

function Get-CatalogModeText {
    param([string]$Name, $S)
    $c = $script:CatalogDefs[$Name]
    switch ("$($S[$Name])") {
        'auto' { return "kept copy under a week old, else download ($($c.Site))" }
        'online' { return "download ($($c.Site))" }
        'off' { return $c.Off }
        'file' { return "file $($S.KevFile)" }
        default { return "kept copy, else $($c.Off)" }
    }
}

# The saved analysis answers as the parameters of a run. Kept catalogs are looked for next to this run's
# report, as the questions do; a saved file that is gone is skipped with a warning.
function Set-GlobalAnalysisParams {
    param([hashtable]$Ap, $S, [bool]$Multi)
    if ($Multi -and $S.PerHost) { $Ap['PerHost'] = $true }
    if ($S.SkipStig) { $Ap['SkipStig'] = $true } elseif ($S.HideStig) { $Ap['HideStig'] = $true }
    if ($S.HideCis) { $Ap['HideCis'] = $true }
    if ($S.Nis2Acn) { $Ap['Nis2Acn'] = $true }
    foreach ($cn in $script:CatalogDefs.Keys) {
        $c = $script:CatalogDefs[$cn]; $mode = "$($S[$cn])"
        if ($mode -eq 'online') { $Ap[$c.Online] = $true }
        elseif ($mode -eq 'file' -and $cn -eq 'Kev') {
            if ($S.KevFile -and (Test-Path -LiteralPath $S.KevFile)) { $Ap['KevFile'] = "$($S.KevFile)" } else { Write-Host "Saved KEV file not found, KEV skipped: $($S.KevFile)" -ForegroundColor Yellow }
        }
        elseif ($mode -eq 'kept' -or $mode -eq 'auto') {
            $kept = Find-KeptCatalog -Suffix $c.Suffix -Report $Ap['OutHtml']
            if ($kept -and ($mode -eq 'kept' -or ((Get-Date) - $kept.LastWriteTime).TotalDays -le 7)) { $Ap[$c.File] = $kept.FullName }
            elseif ($mode -eq 'auto') { $Ap[$c.Online] = $true }
        }
    }
    if ($S.Jsonl) { $Ap['OutJsonl'] = $Ap['OutHtml'] -replace '\.html?$', '.jsonl' }
    if ($S.Remediation) {
        $Ap['OutRemediation'] = $Ap['OutHtml'] -replace '\.html?$', '_remediation'
        if ("$($S.RemediationProfile)" -in $script:ProfileNames) { Set-ProfileParams $Ap "$($S.RemediationProfile)" }
        if ($S.RemediationDebloat) { $Ap['RemediationDebloat'] = $true }
    }
    if ("$($S.ExceptionsFile)".Trim()) {
        if (Test-Path -LiteralPath $S.ExceptionsFile) { $Ap['ExceptionsFile'] = "$($S.ExceptionsFile)" } else { Write-Host "Saved exceptions file not found, exceptions skipped: $($S.ExceptionsFile)" -ForegroundColor Yellow }
    }
    if ("$($S.PolicyFile)".Trim()) {
        if (Test-Path -LiteralPath $S.PolicyFile) { $Ap['PolicyFile'] = "$($S.PolicyFile)" } else { Write-Host "Saved policy file not found, no policy applied: $($S.PolicyFile)" -ForegroundColor Yellow }
    }
    $adm = @("$($S.AllowedAdmins)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($adm.Count) { $Ap['AllowedAdmins'] = $adm }
    $edr = @("$($S.ExpectedEdr)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($edr.Count) { $Ap['ExpectedEdr'] = $edr }
    $rat = @("$($S.AllowedRemoteTools)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($rat.Count) { $Ap['AllowedRemoteTools'] = $rat }
    $ext = @("$($S.AllowedExtensions)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($ext.Count) { $Ap['AllowedExtensions'] = $ext }
}

# Menu 8: the saved answers, numbered, as on the review screen of an analysis. Enter saves, a number
# changes one (a yes/no flips), D deletes the file, Q goes back without saving.
function Edit-GlobalSettings {
    $s = Read-GlobalSettings
    $exists = [bool]$s
    if (-not $exists) { $s = New-GlobalSettings }
    Write-Host "`nGlobal settings: the answers a collection or an analysis asks every time. Once saved, each run asks whether to use them (Enter = yes); the analysis still lists every answer before it runs, so one can be changed for that run. Never saved: passwords, the Gemini key, the snapshot and the CSV to compare with." -ForegroundColor DarkGray
    Write-Host "File: $($script:SettingsPath)$(if (-not $exists) { ' (not saved yet: these are the defaults)' })" -ForegroundColor DarkGray
    $yn = { param($b) if ($b) { 'yes' } else { 'no' } }
    $orElse = { param($v, [string]$Else) if ("$v".Trim()) { "$v" } else { $Else } }
    $encText = @{ ask = 'ask at each collection'; none = 'no'; password = 'password, typed at each collection'; certificate = 'certificate' }
    while ($true) {
        $items = New-Object System.Collections.Generic.List[object]
        $items.Add(@('SnapshotDir', 'Snapshot folder', (& $orElse $s.SnapshotDir 'snapshots, in the folder the menu runs in'), 'Collection of this machine'))
        $items.Add(@('SkipAcl', 'Skip file ACLs', (& $yn $s.SkipAcl), ''))
        $items.Add(@('CheckUpdates', 'Search missing updates', $(if ($s.CheckUpdates) { "yes (Windows Update contacts $(Get-WuSource))" } else { 'no' }), ''))
        $items.Add(@('Encrypt', 'Encrypt the snapshot', $(if ($s.Encrypt -eq 'certificate') { "certificate $($s.Certificate)" } else { $encText["$($s.Encrypt)"] }), ''))
        $items.Add(@('ReportDir', 'Report folder', (& $orElse $s.ReportDir 'output'), 'Analysis'))
        $items.Add(@('PerHost', 'One report per host', "$(& $yn $s.PerHost) (folders with several hosts)", ''))
        $items.Add(@('SkipStig', 'DISA STIG rules', (& $yn (-not $s.SkipStig)), ''))
        $items.Add(@('HideCis', 'Show CIS-based findings', (& $yn (-not $s.HideCis)), ''))
        $items.Add(@('HideStig', 'Show DISA STIG findings', (& $yn (-not $s.HideStig)), ''))
        $items.Add(@('Nis2Acn', 'NIS2 ACN measures (Italy)', (& $yn $s.Nis2Acn), ''))
        foreach ($cn in $script:CatalogDefs.Keys) { $items.Add(@($cn, $script:CatalogDefs[$cn].Label, (Get-CatalogModeText -Name $cn -S $s), '')) }
        $items.Add(@('Jsonl', 'JSON Lines', "$(& $yn $s.Jsonl)$(if ($s.Jsonl) { ', next to the report' })", ''))
        $items.Add(@('Remediation', 'Remediation scripts', "$(& $yn $s.Remediation)$(if ($s.Remediation) { ', next to the report' })", ''))
        $items.Add(@('RemediationProfile', 'Remediation profile', $(if ("$($s.RemediationProfile)" -in $script:ProfileNames) { "$(if ($s.RemediationProfile -eq 'DebloatTelemetry') { 'Debloat and telemetry only' } else { $s.RemediationProfile }) (scripts and menu 6)" } else { 'none: only the safe fixes of the findings' }), ''))
        $items.Add(@('RemediationDebloat', 'Debloat (apps, unused services and components)', "$(& $yn $s.RemediationDebloat) (in the scripts; menu 6 asks per group)", ''))
        $items.Add(@('ExceptionsFile', 'Exceptions file', (& $orElse $s.ExceptionsFile 'no'), ''))
        $items.Add(@('PolicyFile', 'Policy file', (& $orElse $s.PolicyFile 'no'), ''))
        $items.Add(@('AllowedAdmins', 'Allowed administrators', (& $orElse $s.AllowedAdmins 'none'), ''))
        $items.Add(@('ExpectedEdr', 'Expected EDR', (& $orElse $s.ExpectedEdr 'none'), ''))
        $items.Add(@('AllowedRemoteTools', 'Approved remote tools', (& $orElse $s.AllowedRemoteTools 'none'), ''))
        $items.Add(@('AllowedExtensions', 'Approved browser extensions', (& $orElse $s.AllowedExtensions 'none'), ''))
        $items.Add(@('Ai', 'AI summary (Gemini)', $script:AiModes["$($s.Ai)"], 'AI summary'))
        $items.Add(@('AiIncludeStig', 'Send STIG findings', (& $yn $s.AiIncludeStig), ''))
        $items.Add(@('Model', 'Gemini model', (& $orElse $s.Model 'the default'), ''))
        $items.Add(@('AiMaxAttempts', 'Gemini attempts', (& $orElse $s.AiMaxAttempts 'the default (3)'), ''))
        for ($i = 0; $i -lt $items.Count; $i++) {
            if ($items[$i][3]) { Write-Host "`n $($items[$i][3])" -ForegroundColor Cyan }
            Write-Host ("  [{0,2}] {1,-24} {2}" -f ($i + 1), $items[$i][1], $items[$i][2])
        }
        $pick = "$(Read-Host "`nEnter = save, a number = change it, D = delete the saved settings, Q = back without saving")".Trim()
        if (-not $pick) { Save-GlobalSettings $s; Write-Host "Saved: $($script:SettingsPath)" -ForegroundColor Green; return }
        if ($pick -match '^[Qq]') { Write-Host 'Not saved.' -ForegroundColor Yellow; return }
        if ($pick -match '^[Dd]') {
            if ($exists) { Remove-Item -LiteralPath $script:SettingsPath -Force; Write-Host 'Global settings deleted: every run asks its questions again.' -ForegroundColor Green }
            else { Write-Host 'Nothing saved, nothing to delete.' -ForegroundColor Yellow }
            return
        }
        if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $items.Count) { Write-Host "Pick 1-$($items.Count), Enter, D or Q." -ForegroundColor Yellow; continue }
        $k = $items[[int]$pick - 1][0]
        switch ($k) {
            { $_ -in 'SkipAcl', 'PerHost', 'SkipStig', 'HideCis', 'HideStig', 'Nis2Acn', 'Jsonl', 'Remediation', 'RemediationDebloat', 'AiIncludeStig' } { $s[$k] = -not $s[$k] }
            'RemediationProfile' { $s[$k] = Read-RemediationProfile "$($s.RemediationProfile)" }
            'CheckUpdates' {
                $s[$k] = -not $s[$k]
                if ($s[$k]) { Write-Host "Every collection that uses these settings asks Windows Update for the missing updates: the Windows Update service of this machine contacts $(Get-WuSource); the collector itself sends nothing." -ForegroundColor Yellow }
            }
            'SnapshotDir' { $v = Read-PathRaw 'Snapshot folder ("-" for the default)' $s.SnapshotDir; $s[$k] = if ($v -eq '-') { '' } else { "$v" } }
            'ReportDir' { $v = Read-PathRaw 'Report folder ("-" for output)' $s.ReportDir; $s[$k] = if ($v -eq '-' -or -not $v) { 'output' } else { "$v" } }
            'Encrypt' {
                $v = "$(Read-Host 'Encrypt the snapshot: [A]sk at each collection, [N]o, [P]assword (typed at each collection), [C]ertificate (A/n/p/c)')".Trim().ToUpper()
                if ($v -eq 'C') {
                    $cert = Read-PathRaw 'Certificate (.cer file or thumbprint)' $s.Certificate
                    if ($cert) { $s['Encrypt'] = 'certificate'; $s['Certificate'] = "$cert" } else { Write-Host 'No certificate given: unchanged.' -ForegroundColor Yellow }
                }
                elseif ($v -eq 'N') { $s['Encrypt'] = 'none' } elseif ($v -eq 'P') { $s['Encrypt'] = 'password' } elseif ($v -eq 'A' -or -not $v) { $s['Encrypt'] = 'ask' }
            }
            { $script:CatalogDefs.Contains($_) } {
                $c = $script:CatalogDefs[$k]
                $v = "$(Read-Host "$($c.Label): [K]ept copy, else $($c.Off); [A]uto: the kept copy if under a week old, else download; [O]nline download every run; [N]o, $($c.OffPrompt)$(if ($k -eq 'Kev') { '; a [F]ile you have' }) (K/a/o/n$(if ($k -eq 'Kev') { '/f' }))")".Trim().ToUpper()
                if ($v -eq 'F' -and $k -eq 'Kev') {
                    $kp = Read-PathRaw 'Path of known_exploited_vulnerabilities.json' $s.KevFile
                    if ($kp -and (Test-Path -LiteralPath $kp)) { $s['Kev'] = 'file'; $s['KevFile'] = "$kp" } else { Write-Host "Not found, unchanged: $kp" -ForegroundColor Yellow }
                }
                elseif ($v -eq 'A') { $s[$k] = 'auto' } elseif ($v -eq 'O') { $s[$k] = 'online' } elseif ($v -eq 'N') { $s[$k] = 'off' } elseif ($v -eq 'K' -or -not $v) { $s[$k] = 'kept' }
            }
            'ExceptionsFile' {
                $v = Read-PathRaw 'Exceptions file ("-" for none)' $s.ExceptionsFile
                if ($v -eq '-' -or -not $v) { $s[$k] = '' } elseif (Test-Path -LiteralPath $v) { $s[$k] = "$v" } else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'PolicyFile' {
                $v = Read-PathRaw 'Policy file, the checks your organization turns off ("-" for none)' $s.PolicyFile
                if ($v -eq '-' -or -not $v) { $s[$k] = '' } elseif (Test-Path -LiteralPath $v) { $s[$k] = "$v" } else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'AllowedAdmins' { $v = "$(Read-Host 'Allowed local administrators, comma separated ("-" for none)')".Trim(); if ($v -eq '-') { $s[$k] = '' } elseif ($v) { $s[$k] = $v } }
            'ExpectedEdr' { $v = "$(Read-Host 'EDR every host should run, comma separated ("-" for none)')".Trim(); if ($v -eq '-') { $s[$k] = '' } elseif ($v) { $s[$k] = $v } }
            'AllowedRemoteTools' { $v = "$(Read-Host 'Approved remote access tools, comma separated ("-" for none)')".Trim(); if ($v -eq '-') { $s[$k] = '' } elseif ($v) { $s[$k] = $v } }
            'AllowedExtensions' { $v = "$(Read-Host 'Approved browser extensions, ids or names, comma separated ("-" for none)')".Trim(); if ($v -eq '-') { $s[$k] = '' } elseif ($v) { $s[$k] = $v } }
            'Ai' {
                $v = "$(Read-Host $script:AiModePrompt)".Trim().ToUpper()
                if (-not $v) { $v = 'A' }
                if ($script:AiModes.Contains($v)) { $s['Ai'] = $v }
                if ($v -in 'S', 'C') { Write-Host 'Every analysis that uses these settings sends its findings to Gemini (names replaced by tokens first, the leak check before sending). The key is still asked when GEMINI_API_KEY is not set.' -ForegroundColor Yellow }
            }
            'Model' { $v = "$(Read-Host 'Gemini model ("-" for the default)')".Trim(); if ($v -eq '-') { $s[$k] = '' } elseif ($v) { $s[$k] = $v } }
            'AiMaxAttempts' {
                $v = "$(Read-Host 'Gemini attempts on timeout / busy server, 0 = keep trying ("-" for the default)')".Trim()
                if ($v -eq '-') { $s[$k] = '' } elseif ($v -match '^\d+$') { $s[$k] = $v } elseif ($v) { Write-Host 'A number, or "-": unchanged.' -ForegroundColor Yellow }
            }
        }
    }
}

# Collect this machine. Returns the folder with the snapshot, or an empty string if nothing came
# out.
# Where the Windows Update Agent of this machine goes for -CheckUpdates: the WSUS server set by policy,
# else Microsoft Update. Every place that offers it names this address.
function Get-WuSource {
    $wuSource = 'Microsoft Update (HTTPS to *.update.microsoft.com)'
    try {
        $wuPol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop
        $wuAu = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        if ($wuPol.WUServer -and $wuAu -and $wuAu.UseWUServer -eq 1) { $wuSource = "the WSUS server $($wuPol.WUServer)" }
    }
    catch { }
    return $wuSource
}

function Invoke-CollectStep {
    if (-not (Test-IsAdmin)) {
        Write-Host "Not running as administrator: the snapshot will have gaps (listed as 'not evaluated' in the report). Start an elevated PowerShell for full coverage." -ForegroundColor Yellow
    }
    # With the global settings (menu 8) only the password, if one is chosen, is asked.
    $g = if (Test-UseGlobal) { $script:Global } else { $null }
    $defDir = if ($g -and "$($g.SnapshotDir)".Trim()) { "$($g.SnapshotDir)".Trim() } else { Join-Path $PWD.Path 'snapshots' }
    $dir = if ($g) { Get-Answer 'Snapshot folder' { $defDir } } else { Read-Path "Snapshot folder" $defDir }
    $p = @{ OutDir = $dir }
    if ($g) { if ($g.SkipAcl) { $p['SkipAcl'] = $true } }
    elseif (Test-Yes "Skip file ACLs (faster, but the writable-program checks are not evaluated)? (y/N)") { $p['SkipAcl'] = $true }
    # The one network call the collector can make, so it is asked about (or said, when the saved settings
    # turn it on) and the address is named.
    $wuSource = Get-WuSource
    if ($g) {
        if ($g.CheckUpdates) { $p['CheckUpdates'] = $true; Write-Host "`nGlobal settings: Windows Update is asked which updates are still missing. The Windows Update service of this machine contacts $wuSource; the collector itself sends nothing." -ForegroundColor DarkGray }
    }
    else {
        Write-Host "`nOptional: ask Windows Update which updates are still missing. The Windows Update service of this machine contacts $wuSource; the collector itself sends nothing. Without it, pending updates are simply not in the snapshot." -ForegroundColor DarkGray
        if (Test-Yes "Search for missing updates online? (y/N)") { $p['CheckUpdates'] = $true }
    }
    # Encryption of the snapshot (.hbx): nothing is written in clear. The password goes to the collector
    # in this process, never on a command line.
    $savedEnc = @{ none = 'N'; password = 'P'; certificate = 'C' }
    if ($g -and $savedEnc.ContainsKey("$($g.Encrypt)")) { $encAns = $savedEnc["$($g.Encrypt)"] }
    else {
        Write-Host "`nThe snapshot describes this machine in detail. Encrypt it: with a password (asked again when you analyze it), or to a certificate (a .cer file or a thumbprint; only the holder of the private key can read it)." -ForegroundColor DarkGray
        $encAns = "$(Read-Line 'Encrypt the snapshot? [P]assword, [C]ertificate, [N]o (p/c/N)')".Trim().ToUpper()
    }
    if ($encAns -eq 'C') {
        $cert = if ($g -and "$($g.Certificate)".Trim()) { "$($g.Certificate)".Trim() } else { Read-Path 'Certificate (.cer file or thumbprint)' }
        if ($cert) { $p['EncryptCertificate'] = $cert } else { Write-Host 'No certificate given: the snapshot is not encrypted.' -ForegroundColor Yellow }
    }
    elseif ($encAns -eq 'P') {
        if ($g) { Write-Host 'Global settings: the snapshot is encrypted with a password.' -ForegroundColor DarkGray }
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
    # With the global settings (menu 8) the questions below are skipped: the review screen shows the saved
    # answers. The report path is still saved under its question, so a resumed run keeps it.
    $useGlobal = Test-UseGlobal
    if ($useGlobal) {
        $rd = if ("$($script:Global.ReportDir)".Trim()) { "$($script:Global.ReportDir)".Trim() } else { 'output' }
        $ap['OutHtml'] = Get-Answer 'Report HTML path' { Join-Path $rd ("hostbadger_{0}.html" -f (Ts)) }
    }
    else { $ap['OutHtml'] = Read-Path "Report HTML path" ("output\hostbadger_{0}.html" -f (Ts)) }
    $hostCount = 1
    if ((Get-Item -LiteralPath $Snapshot).PSIsContainer) { $hostCount = @(Get-SnapshotList -Dir $Snapshot -Recurse | ForEach-Object { $_.Host.ToLower() } | Sort-Object -Unique).Count }
    if ($useGlobal) {
        Set-GlobalAnalysisParams -Ap $ap -S $script:Global -Multi ($hostCount -gt 1)
        $script:RunAi = "$($script:Global.Ai)"
    }
    else {
        # Only when the folder holds snapshots of more than one host: one report each, on by default.
        if ($hostCount -gt 1) {
            Write-Host "`n$hostCount hosts found: HostBadger can also write one report per host, next to the fleet report." -ForegroundColor DarkGray
            $ans = "$(Read-Line 'One report per host? (Y/n)')".Trim()
            if ($ans -notmatch '^[Nn]') { $ap['PerHost'] = $true }
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
        Write-Host "`nNIS2 in Italy: the report can also list the basic security measures of the Agenzia per la Cybersicurezza Nazionale (Determinazione 379907/2025, D.Lgs. 138/2024) that the hosts show evidence against. Useful only for organizations subject to the Italian NIS2 rules." -ForegroundColor DarkGray
        $acnAns = "$(Read-Line 'Add the NIS2 ACN basic measures (Italy) to the report? (y/N)')".Trim()
        if ($acnAns -match '^[YySs]') { $ap['Nis2Acn'] = $true }
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
        Write-Host "`nBrowser extensions: HostBadger ships a list of about 7,900 extensions removed from the Chrome Web Store and Edge Add-ons (malware, spyware, adware) or documented as malicious. A fresh copy of the store list comes from malicious_extension_sentry (malext.io, updated daily): one HTTPS GET of about 2 MB to raw.githubusercontent.com, nothing is sent; a copy is kept next to the report." -ForegroundColor DarkGray
        Set-CatalogChoice -Ap $ap -Name 'Ext'
        if (Test-Yes "Also write JSON Lines for a SIEM? (y/N)") { $ap['OutJsonl'] = Read-Path "JSON Lines path" ($ap['OutHtml'] -replace '\.html?$', '.jsonl') }
        Write-Host "`nRemediation scripts: the report already shows a fix script under each check whose fix is one safe setting. HostBadger can also write one remediate_<host>.ps1 per host with all of that host's fixes in one file, for a scripted rollout. They are text files: HostBadger never runs them, they only preview until run with -Apply, and they write a rollback file. Read them and test on a pilot host first." -ForegroundColor DarkGray
        if (Test-Yes 'Write one remediation script per host? (y/N)') { $ap['OutRemediation'] = Read-Path "Folder for the remediation scripts" ($ap['OutHtml'] -replace '\.html?$', '_remediation') }
    }
    # Never saved in the global settings: it changes with every run.
    $prev = Read-Path "Findings CSV of an earlier run, to show new and resolved (optional, Enter to skip)"
    if ($prev) { if (Test-Path -LiteralPath $prev) { $ap['CompareTo'] = $prev } else { Write-Host "Not found, comparison skipped: $prev" -ForegroundColor Yellow } }
    if (-not $useGlobal) {
        $exc = Read-Path "Exceptions file (accepted risks, optional, Enter to skip)"
        if ($exc) { if (Test-Path -LiteralPath $exc) { $ap['ExceptionsFile'] = $exc } else { Write-Host "Not found, exceptions skipped: $exc" -ForegroundColor Yellow } }
        Write-Host "`nLocal administrators: HostBadger reports every member of the local Administrators group that it doesn't expect (Domain Admins and the built-in Administrator are always expected)." -ForegroundColor DarkGray
        Write-Host "If some belong there (for example an IT group), list them as DOMAIN/Name or by SID, comma separated, and they won't be reported." -ForegroundColor DarkGray
        $adm = Read-Line "Allowed local administrators, e.g. CORP/Workstation Admins, CORP/helpdesk (Enter = none)"
        if ($adm.Trim()) { $ap['AllowedAdmins'] = @($adm -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        Write-Host "`nEDR: HostBadger shows which known EDR agent each host runs (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black, Cortex XDR, Sophos, Trend Micro and others) and flags one that is stopped. Name the one every host should have and a host without it is flagged too." -ForegroundColor DarkGray
        $edr = Read-Line "EDR every host should run, e.g. CrowdStrike or SentinelOne, comma separated (Enter = none)"
        if ($edr.Trim()) { $ap['ExpectedEdr'] = @($edr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        Write-Host "`nRemote access tools: HostBadger reports AnyDesk, TeamViewer, ScreenConnect, VNC, RustDesk and other remote access tools it finds. Name the ones the organization approves and only the others are reported (as Medium); without a list every one found is Low, to be verified." -ForegroundColor DarkGray
        $rat = Read-Line "Approved remote access tools, e.g. TeamViewer, ScreenConnect, comma separated (Enter = none)"
        if ($rat.Trim()) { $ap['AllowedRemoteTools'] = @($rat -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    }
    # Everything asked: show it, and let any answer be changed before the run.
    $ap = Edit-AnalysisParams $ap
    if (-not $ap) { Write-Host 'Cancelled: nothing was run.' -ForegroundColor Yellow; return $null }
    # Option 4 asks about the AI step up front, and a saved AI mode that writes or sends needs no question.
    # Options 2 and 3 otherwise offer it once the report is written.
    $aiMode = if ($script:RunAi -in 'D', 'S', 'C') { $script:RunAi }
    elseif ($WithAi) { Read-AiMode 'AI summary (Gemini): [D]ry run (write the prompt, send nothing), [S]end, [C]onfirm first after reading the prompt (D/s/c)' -Default 'D' }
    else { '' }
    if ($aiMode) { Add-AiParams -Params $ap -Mode $aiMode }
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
        Acn = 'Add the NIS2 ACN basic measures (Italy) to the report? (y/N)'
        Rem = 'Write one remediation script per host? (y/N)'; RemPath = 'Folder for the remediation scripts'
        Compare = 'Findings CSV of an earlier run, to show new and resolved (optional, Enter to skip)'; Exceptions = 'Exceptions file (accepted risks, optional, Enter to skip)'
        Admins = 'Allowed local administrators, e.g. CORP/Workstation Admins, CORP/helpdesk (Enter = none)'
        Edr = 'EDR every host should run, e.g. CrowdStrike or SentinelOne, comma separated (Enter = none)'
        Rat = 'Approved remote access tools, e.g. TeamViewer, ScreenConnect, comma separated (Enter = none)'
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
        $items.Add(@('Acn', 'NIS2 ACN measures (Italy)', (& $yn $Ap['Nis2Acn'])))
        foreach ($cn in $script:CatalogDefs.Keys) { $items.Add(@($cn, $script:CatalogDefs[$cn].Label, (Get-CatalogSummary -Ap $Ap -Name $cn))) }
        $items.Add(@('Jsonl', 'JSON Lines', $(if ($Ap['OutJsonl']) { $Ap['OutJsonl'] } else { 'no' })))
        $items.Add(@('Rem', 'Remediation scripts', $(if ($Ap['OutRemediation']) { $Ap['OutRemediation'] } else { 'no' })))
        $items.Add(@('Compare', 'Compare with', $(if ($Ap['CompareTo']) { $Ap['CompareTo'] } else { 'no' })))
        $items.Add(@('Exceptions', 'Exceptions file', $(if ($Ap['ExceptionsFile']) { $Ap['ExceptionsFile'] } else { 'no' })))
        $items.Add(@('Policy', 'Policy file', $(if ($Ap['PolicyFile']) { $Ap['PolicyFile'] } else { 'no' })))
        $items.Add(@('Admins', 'Allowed administrators', $(if ($Ap['AllowedAdmins']) { @($Ap['AllowedAdmins']) -join ', ' } else { 'none' })))
        $items.Add(@('Edr', 'Expected EDR', $(if ($Ap['ExpectedEdr']) { @($Ap['ExpectedEdr']) -join ', ' } else { 'none' })))
        $items.Add(@('Rat', 'Approved remote tools', $(if ($Ap['AllowedRemoteTools']) { @($Ap['AllowedRemoteTools']) -join ', ' } else { 'none' })))
        $items.Add(@('Ext', 'Approved extensions', $(if ($Ap['AllowedExtensions']) { @($Ap['AllowedExtensions']) -join ', ' } else { 'none: those that read every site are Low' })))
        # The AI step is listed only with the global settings, which hold a mode for it.
        if ($script:RunAi) { $items.Add(@('Ai', 'AI summary (Gemini)', $script:AiModes[$script:RunAi])) }
        Write-Host "`nSettings for this run$(if ($script:UseGlobal) { ' (from the global settings)' }):" -ForegroundColor Cyan
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
            'Acn' { & $flag 'Nis2Acn' (-not $Ap['Nis2Acn']) $q.Acn 'y' '' }
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
            'Policy' {
                $v = Read-PathRaw 'Policy file, the checks your organization turns off ("-" for none)' $Ap['PolicyFile']
                if ($v -eq '-' -or -not $v) { $Ap.Remove('PolicyFile') } elseif (Test-Path -LiteralPath $v) { $Ap['PolicyFile'] = $v } else { Write-Host "Not found, unchanged: $v" -ForegroundColor Yellow }
            }
            'Admins' {
                $v = "$(Read-Host 'Allowed local administrators, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('AllowedAdmins'); Set-WizardValue $q.Admins '' } elseif ($v) { $Ap['AllowedAdmins'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Set-WizardValue $q.Admins $v }
            }
            'Edr' {
                $v = "$(Read-Host 'EDR every host should run, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('ExpectedEdr'); Set-WizardValue $q.Edr '' } elseif ($v) { $Ap['ExpectedEdr'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Set-WizardValue $q.Edr $v }
            }
            'Rat' {
                $v = "$(Read-Host 'Approved remote access tools, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('AllowedRemoteTools'); Set-WizardValue $q.Rat '' } elseif ($v) { $Ap['AllowedRemoteTools'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Set-WizardValue $q.Rat $v }
            }
            'Ext' {
                $v = "$(Read-Host 'Approved browser extensions, ids or names, comma separated ("-" for none)')".Trim()
                if ($v -eq '-') { $Ap.Remove('AllowedExtensions') } elseif ($v) { $Ap['AllowedExtensions'] = @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            'Ai' { $v = "$(Read-Host $script:AiModePrompt)".Trim().ToUpper(); if (-not $v) { $v = 'A' }; if ($script:AiModes.Contains($v)) { $script:RunAi = $v } }
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
    # With the global settings the STIG, model and attempts answers are the saved ones; the key is still asked.
    $g = if ($script:UseGlobal) { $script:Global } else { $null }
    if (-not $Params.ContainsKey('SkipStig')) {
        if ($g) { if ($g.AiIncludeStig) { $Params['AiIncludeStig'] = $true } }
        else {
            Write-Host "`nThe DISA STIG findings can be hundreds per host. Sending them makes the prompt very large and Gemini may time out." -ForegroundColor Yellow
            $sendStig = "$(Read-Line 'Also send the DISA STIG findings to Gemini? (y/N)')".Trim()
            if ($sendStig -match '^[YySs]') { $Params['AiIncludeStig'] = $true }
        }
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
            $m = if ($g) { "$($g.Model)" } else { Read-Line "Gemini model [gemini-3.8-flash]" }
            if ($m.Trim()) { $Params['Model'] = $m.Trim() }
            $r = if ($g) { "$($g.AiMaxAttempts)" } else { Read-Line "Gemini attempts on timeout / busy server, 0 = keep trying [3]" }
            if ($r -match '^\d+$') { $Params['AiMaxAttempts'] = [int]$r }
            return
        }
        $Mode = 'D'
    }
    # The global settings write the prompt next to the report.
    $Params['AiDryRun'] = if ($g -and $Params['OutHtml']) { $Params['OutHtml'] -replace '\.html?$', '_ai_prompt.txt' } else { Read-Path "Dry-run output file" ("hostbadger_ai_prompt_{0}.txt" -f (Ts)) }
}

# After the report, offer the AI summary. The analysis ran with -AiLater, so it is still in this
# session's memory: -AiContinue runs only the AI step on it (nothing is analyzed or downloaded twice).
function Invoke-AiOffer {
    param([hashtable]$Params)
    try {
        if (-not (Test-Path -LiteralPath $Params['OutHtml'])) { return }
        Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "Report ready: $($Params['OutHtml'])" -ForegroundColor Green
        if (-not $Params['AiLater']) { return }
        $mode = Read-AiMode 'Add an AI summary with Gemini?  [N]o, [D]ry run (only write the prompt), [S]end, [C]onfirm after reading the prompt (N/d/s/c)' -Default 'N'
        if ($mode -eq 'N') { return }
        $ai = @{ OutHtml = $Params['OutHtml'] }
        if ($Params['SkipStig']) { $ai['SkipStig'] = $true }
        Add-AiParams -Params $ai -Mode $mode
        $ai.Remove('OutHtml'); $ai.Remove('SkipStig')
        $ai['AiContinue'] = $true
        Invoke-Sub 'HostBadger.ps1' $ai
    }
    # The kept analysis is not needed any more, whatever the answer.
    finally { $global:HostBadgerAiPending = $null }
}

# The analysis keeps itself in memory for the AI offer, unless the run already has an AI mode (a saved
# one) or the global settings turn the AI step off.
function Add-AiOffer {
    param([hashtable]$Params)
    if ($Params['SendToAI'] -or $Params['AiDryRun'] -or $script:RunAi -eq 'N') { return }
    $Params['AiLater'] = $true
}
# ---------------- Remediation of this machine: the only part of HostBadger that changes anything.
# Each run gets a folder with its snapshot, report, fix script and rollback file.
$script:RemediationRoot = Join-Path (Join-Path $PWD.Path 'output') 'remediation'
$script:ProfileNames = @('Essential', 'Recommended', 'Strict', 'DebloatTelemetry')

# The remediation profile (data\remediation-profiles.json): '' keeps only the safe fixes of the findings,
# 'DebloatTelemetry' is no tier, only the privacy and telemetry settings plus the removal of preinstalled apps.
function Read-RemediationProfile {
    param([string]$Current)
    $now = if ($Current -in $script:ProfileNames) { $Current } else { 'none' }
    Write-Host 'Remediation profile, on top of the safe fixes of the findings: Essential (CIS Level 1 and Essential Eight ML1 settings safe on any machine), Recommended (+ the rest of CIS Level 1, Essential Eight ML2, attack surface reduction rules in block mode), Strict (+ CIS Level 2, Essential Eight ML3, opinionated hardening and the removal of preinstalled apps; some of it is NOT REVERSIBLE), Debloat and telemetry only (the privacy and telemetry settings of every profile, the removal of preinstalled apps and unused consumer services and components, no hardening; the apps are NOT REVERSIBLE).' -ForegroundColor DarkGray
    while ($true) {
        $v = "$(Read-Line "Profile: [N]one, [E]ssential, [R]ecommended, [S]trict, [D]ebloat and telemetry only (Enter = $now)")".Trim().ToUpper()
        switch ($v) {
            '' { return $(if ($now -eq 'none') { '' } else { $now }) }
            { $_ -in 'N', 'NONE' } { return '' }
            { $_ -in 'E', 'ESSENTIAL' } { return 'Essential' }
            { $_ -in 'R', 'RECOMMENDED' } { return 'Recommended' }
            { $_ -in 'S', 'STRICT' } { return 'Strict' }
            { $_ -in 'D', 'DEBLOAT' } { return 'DebloatTelemetry' }
        }
        Write-Host "'$v' is not one of the choices: type N, E, R, S or D." -ForegroundColor Yellow
    }
}

# Turns a menu profile into the HostBadger.ps1 parameters.
function Set-ProfileParams {
    param([hashtable]$Params, [string]$Name)
    if ($Name -eq 'DebloatTelemetry') { $Params['RemediationDebloat'] = $true; $Params['RemediationPrivacy'] = $true; $Params['RemediationOnlyProfile'] = $true }
    elseif ($Name) { $Params['RemediationProfile'] = $Name }
}
function New-HbRestorePoint {
    # A System Restore point before the changes, where Windows has one (not on servers, not in
    # PowerShell 7, and Windows makes at most one a day).
    # With System Protection off (RPSessionInterval 0, the default on many new or virtual machines)
    # Windows answers "service disabled": offer to turn it on for the system drive first.
    $srKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue
    if ($srKey -and $null -ne $srKey.RPSessionInterval -and [int]$srKey.RPSessionInterval -eq 0) {
        Write-Host "System Protection is off on this machine, so Windows cannot make a restore point. Turning it on for $env:SystemDrive keeps restore points there (Windows reserves a few percent of the disk; System Properties > System Protection turns it off again)." -ForegroundColor Yellow
        if (Test-Yes "Turn System Protection on for $env:SystemDrive and make the restore point? (y/N)") {
            try { Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop }
            catch { Write-Host "System Protection not turned on: $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }
    try {
        Checkpoint-Computer -Description 'HostBadger: before remediation' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Host 'System Restore point created (Windows skips it if one was made in the last 24 hours).' -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "No System Restore point: $($_.Exception.Message)" -ForegroundColor Yellow
        # System Restore starts the Volume Shadow Copy service and its provider: name the one that is disabled.
        $off = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='VSS' OR Name='swprv'" -ErrorAction SilentlyContinue | Where-Object { "$($_.StartMode)" -eq 'Disabled' } | ForEach-Object { $_.Name })
        if ($off.Count -gt 0) { Write-Host "Disabled: $($off -join ', '). System Restore needs them on Manual (the Windows default): Set-Service <name> -StartupType Manual, then Enable-ComputerRestore -Drive 'C:\'." -ForegroundColor Yellow }
        return (Test-Yes 'Go on without it? The rollback file still records every value changed (y/N)')
    }
}

function Invoke-BloatwareStep {
    # Preinstalled apps from the curated list in lib\Checks.ps1: only the groups found on this machine are
    # listed; Enter removes them all, C asks group by group, N keeps them. For every user and from the
    # provisioned list (new profiles). Returns the number of apps removed.
    param([string]$Run)
    . (Join-Path $root 'lib\Common.ps1'); . (Join-Path $root 'lib\Checks.ps1')
    $installed = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
    $removed = @()
    $groups = @(foreach ($b in @($script:BloatwareApps | Where-Object { $_.Appx })) {
        $names = @(@($installed | ForEach-Object { "$($_.Name)" }) + @($provisioned | ForEach-Object { "$($_.DisplayName)" }) | Where-Object { $_ -match $b.Appx } | Sort-Object -Unique)
        if ($names.Count) { [PSCustomObject]@{ Label = $b.Label; Names = $names } }
    })
    if ($groups.Count -eq 0) { Write-Host 'None of the preinstalled apps on HostBadger''s list is on this machine.' -ForegroundColor Green }
    else {
        Write-Host 'Preinstalled apps found on this machine (removed for every user and from new profiles; they come back only from the Microsoft Store):' -ForegroundColor Cyan
        foreach ($g in $groups) { Write-Host "  - $($g.Label): $($g.Names -join ', ')" }
    }
    $mode = ''
    while ($groups.Count -and -not $mode) {
        $v = "$(Read-Line 'Remove them: [A]ll, [C]hoose one group at a time, [N]one (Enter = all)')".Trim().ToUpper()
        if ($v -in '', 'A', 'ALL') { $mode = 'all' } elseif ($v -in 'C', 'CHOOSE') { $mode = 'choose' } elseif ($v -in 'N', 'NONE') { $mode = 'none' }
        else { Write-Host "'$v' is not one of the choices: type A, C or N." -ForegroundColor Yellow }
    }
    foreach ($g in @($groups | Where-Object { $mode -ne 'none' })) {
        $names = $g.Names
        if ($mode -eq 'choose' -and -not (Test-Yes "Remove $($g.Label) ($($names -join ', '))? (y/N)")) { continue }
        foreach ($n in $names) {
            # Provisioned list first (new profiles), then every user. Removing for every user can take the
            # provisioned copy away too, and DISM then answers "path not found" for a package that is
            # gone: what counts is what is still there afterwards.
            $err = ''
            foreach ($p in @($provisioned | Where-Object { "$($_.DisplayName)" -eq $n })) { try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null } catch { if (-not $err) { $err = "$($_.Exception.Message)".Trim() } } }
            foreach ($i in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -eq $n })) { try { Remove-AppxPackage -Package $i.PackageFullName -AllUsers -ErrorAction Stop } catch { if (-not $err) { $err = "$($_.Exception.Message)".Trim() } } }
            $still = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -eq $n }).Count + @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -eq $n }).Count
            if ($still -eq 0) { Write-Host "  removed $n" -ForegroundColor Green; $removed += $n }
            else { Write-Host "  $n not removed$(if ($err) { ": $err" })" -ForegroundColor Red }
        }
    }
    foreach ($b in @($script:BloatwareApps | Where-Object { $_.Program })) {
        $progs = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { "$((Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName)" } | Where-Object { $_ -match $b.Program } | Sort-Object -Unique)
        if ($progs.Count) { Write-Host "$($b.Label): $($progs -join ', '). Uninstall it from Settings > Apps (its own uninstaller)." -ForegroundColor Yellow }
    }
    if ($removed.Count) { [System.IO.File]::WriteAllText((Join-Path $Run 'removed_apps.json'), (ConvertTo-Json -InputObject @($removed)), (New-Object System.Text.UTF8Encoding($false))) }
    return $removed.Count
}

# What a remediation run did, for menu 7: the profile chosen (run.json, written by menu 6) and what the
# rollback file and removed_apps.json record. Runs from before run.json still get the counts.
function Get-RemediationRunSummary {
    param([string]$Dir)
    $parts = @()
    $info = $null
    try { $info = Get-Content -LiteralPath (Join-Path $Dir 'run.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    if ($info) {
        $parts += switch ("$($info.profile)") { '' { 'safe fixes only' } 'DebloatTelemetry' { 'debloat and telemetry only' } default { "profile $($info.profile)" } }
    }
    $entries = @()
    try { $entries = @(Get-Content -LiteralPath (Join-Path $Dir 'rollback.json') -Raw -ErrorAction Stop | ConvertFrom-Json | ForEach-Object { $_ }) } catch { }
    $fixes = @($entries | Where-Object { "$($_.kind)" -ne 'appx' -and "$($_.id)" -notmatch '^(essential|recommended|strict)/' }).Count
    $prof = @($entries | Where-Object { "$($_.id)" -match '^(essential|recommended|strict)/' }).Count
    $apps = @($entries | Where-Object { "$($_.kind)" -eq 'appx' } | ForEach-Object { @($_.names) }).Count
    try { $apps += @(Get-Content -LiteralPath (Join-Path $Dir 'removed_apps.json') -Raw -ErrorAction Stop | ConvertFrom-Json | ForEach-Object { $_ }).Count } catch { }
    $counts = @()
    if ($fixes) { $counts += "$fixes finding fix(es)" }
    if ($prof) { $counts += "$prof profile setting(s)" }
    if ($apps) { $counts += "$apps app(s) removed" }
    if (-not $counts) { $counts += 'nothing changed' }
    return "$(if ($parts) { "$($parts -join ', '): " })$($counts -join ', ')"
}

# Snapshots of this machine already taken (by menu 1, an earlier remediation, the global snapshot folder):
# one can be used instead of collecting again. Asked only when there is one, so the answer lists of the
# tests do not shift. Returns Path '' to collect again.
function Select-OwnSnapshot {
    $me = $env:COMPUTERNAME -replace '[^\w\-]', '_'
    $g = Read-GlobalSettings
    $dirs = @((Join-Path $PWD.Path 'snapshots'), (Join-Path $root 'snapshots'), $script:RemediationRoot)
    if ($g -and "$($g.SnapshotDir)".Trim()) { $dirs += "$($g.SnapshotDir)".Trim() }
    $seen = @{}
    $found = @(foreach ($d in $dirs) {
        if ($seen.ContainsKey("$d".ToLower()) -or -not (Test-Path -LiteralPath $d)) { continue }
        $seen["$d".ToLower()] = $true
        Get-SnapshotList -Dir $d -Recurse | Where-Object { $_.Host -ieq $me }
    })
    $found = @($found | Sort-Object Path -Unique | Sort-Object When -Descending | Select-Object -First 5)
    if ($found.Count -eq 0) { return [PSCustomObject]@{ Path = ''; Kind = '' } }
    Write-Host "`nSnapshots of this machine already taken: start from one to skip the collection (the analysis runs again, a few seconds, to write the fix script). The fix script reads the current values before changing anything, so an older snapshot is safe; it only misses what changed since." -ForegroundColor DarkGray
    for ($i = 0; $i -lt $found.Count; $i++) {
        $f = $found[$i]
        $age = [Math]::Floor(((Get-Date).ToUniversalTime() - $f.When).TotalHours)
        $ageText = if ($age -lt 1) { 'less than an hour ago' } elseif ($age -lt 48) { "$age hour(s) ago" } else { "$([Math]::Floor($age / 24)) day(s) ago" }
        Write-Host ("  [{0}] {1:yyyy-MM-dd HH:mm} UTC  ({2})  {3}" -f ($i + 1), $f.When, $ageText, $f.Path)
    }
    $pick = "$(Read-Line 'Pick a number to start from that snapshot, or Enter to collect this machine again')".Trim()
    if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $found.Count) { return $found[[int]$pick - 1] }
    if ($pick) { Write-Host "There is no snapshot number ${pick}: collecting this machine again." -ForegroundColor Yellow }
    return [PSCustomObject]@{ Path = ''; Kind = '' }
}

function Invoke-RemediateStep {
    if (-not (Test-IsAdmin)) { Write-Host 'Remediation changes system settings: start an elevated PowerShell (Run as administrator), or restart the menu as administrator, and choose it again.' -ForegroundColor Yellow; return }
    Write-Host "`nRemediate this machine: HostBadger collects and analyzes this machine (or starts from a snapshot of it already taken), then shows what its fix script would change. Without a profile only settings with a safe, reversible fix are in it (one value, the one the baseline expects, no organizational choice); a profile adds its own list of settings. Nothing changes until you type YES; a System Restore point comes first where Windows has one, and the script writes every previous value to a rollback file (menu 7 puts them back, except what is marked NOT REVERSIBLE). Group Policy or Intune may set a value back on managed machines." -ForegroundColor DarkGray
    if (-not (Test-Yes 'Continue? (y/N)')) { return }
    # The saved profile (menu 8) is the default; the question is always asked, so the answers do not shift.
    $g = Read-GlobalSettings
    $remProfile = Read-RemediationProfile $(if ($g) { "$($g.RemediationProfile)" } else { '' })
    $from = Select-OwnSnapshot
    $run = Join-Path $script:RemediationRoot (Ts)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    # Never resumed: an interrupted run is only explained at the next start (and option 7 offered).
    Start-WizardState 'remediate'; Set-WizardValue 'run' $run
    $hp = @{ OutHtml = (Join-Path $run 'report.html'); OutRemediation = $run }
    if ($remProfile) { Set-ProfileParams $hp $remProfile; Set-WizardValue 'profile' $remProfile }
    # The apps are asked below, from what is on this machine: the script leaves them out.
    $hp['RemediationNoApps'] = $true
    $withApps = $remProfile -in 'Strict', 'DebloatTelemetry'
    [System.IO.File]::WriteAllText((Join-Path $run 'run.json'), (ConvertTo-Json -InputObject ([ordered]@{ profile = "$remProfile"; started = (Get-Date).ToString('yyyy-MM-dd HH:mm') })), (New-Object System.Text.UTF8Encoding($false)))
    if ($from.Path) {
        $hp['Snapshot'] = $from.Path
        if ($from.Kind -eq 'hbx') {
            $pw = Read-Host 'Password of the encrypted snapshot (Enter if it is encrypted to a certificate)' -AsSecureString
            if ($pw.Length -gt 0) { $hp['SnapshotPassword'] = $pw }
        }
    }
    else {
        Invoke-Sub 'Collect-HostSnapshot.ps1' @{ OutDir = $run }
        $snap = @(Get-ChildItem -LiteralPath $run -Filter 'hostsnapshot_*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($snap.Count -eq 0) { Write-Host 'No snapshot produced; nothing changed.' -ForegroundColor Red; return }
        $hp['Snapshot'] = $snap[0].FullName
    }
    Invoke-Sub 'HostBadger.ps1' $hp
    $fix = @(Get-ChildItem -LiteralPath $run -Filter 'remediate_*.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1)
    $applied = $false
    if ($fix.Count -eq 0) { Write-Host 'No setting on this machine has a safe fix script.' -ForegroundColor Green }
    else {
        Write-Host "`nWhat the fix script would change (nothing changed yet):" -ForegroundColor Cyan
        try { & $fix[0].FullName | Out-Host } catch { Write-Host "Preview failed: $($_.Exception.Message)" -ForegroundColor Red; return }
        if ($remProfile) { Write-Host "Profile $(if ($remProfile -eq 'DebloatTelemetry') { 'debloat and telemetry' } else { $remProfile })`: the lines marked NOT REVERSIBLE (in magenta) cannot be put back by menu 7; the System Restore point is the way back for them." -ForegroundColor Magenta }
        if ((Read-Host 'Apply these changes to this machine? Type YES to apply') -cne 'YES') { Write-Host 'Nothing changed.' -ForegroundColor Yellow }
        elseif (New-HbRestorePoint) {
            $rb = Join-Path $run 'rollback.json'
            Set-WizardStage 'applying'
            $applied = $true
            try { & $fix[0].FullName -Apply -RollbackFile $rb -NoRestorePoint | Out-Host } catch { Write-Host "The fix script stopped: $($_.Exception.Message)" -ForegroundColor Red }
            if (Test-Path -LiteralPath $rb) { Write-Host "Previous values saved in $rb. Menu 7 puts them back." -ForegroundColor Green }
        }
    }
    # Strict and "debloat and telemetry" include the apps: the list comes straight away (Enter = all).
    $appsGone = 0
    if ($withApps) { Write-Host ''; $appsGone = Invoke-BloatwareStep -Run $run }
    else {
        Write-Host "`nPreinstalled apps: games, consumer apps and trials from HostBadger's list." -ForegroundColor DarkGray
        if (Test-Yes 'Look for preinstalled apps to remove? (y/N)') { $appsGone = Invoke-BloatwareStep -Run $run }
    }
    Write-Host "Report of this run: $(Join-Path $run 'report.html')" -ForegroundColor Green
    if ($applied -or $appsGone) {
        Write-Host 'Windows applies some of these changes (services, features, policies read at startup) only after a restart.' -ForegroundColor Yellow
        if ((Read-Host 'Restart now? Type YES to restart this machine now (Enter = later)') -ceq 'YES') { Restart-Computer -Force }
        else { Write-Host 'Restart later to finish the changes.' -ForegroundColor Yellow }
    }
}

function Invoke-RestoreStep {
    $runs = @(Get-ChildItem -LiteralPath $script:RemediationRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'rollback.json') } | Sort-Object Name -Descending)
    if ($runs.Count -eq 0) { Write-Host "No remediation backup found in $($script:RemediationRoot)." -ForegroundColor Yellow; return }
    for ($i = 0; $i -lt $runs.Count; $i++) {
        Write-Host ("  [{0}] {1}  {2}" -f ($i + 1), $runs[$i].Name, (Get-RemediationRunSummary $runs[$i].FullName))
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
    if ((Read-Host 'Windows reads some of these values only at startup. Restart now? Type YES to restart this machine now (Enter = later)') -ceq 'YES') { Restart-Computer -Force }
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
        Write-Host "  [8] Global settings             (the usual answers, saved: a run asks whether to use them)" -ForegroundColor White
        Write-Host "  [Q] Quit" -ForegroundColor White
        if ($script:ResumeChoice) { $choice = $script:ResumeChoice; $script:ResumeChoice = ''; Write-Host "`nChoice: $choice   (resumed)" -ForegroundColor DarkGray }
        else { $choice = (Read-Host "`nChoice").Trim().ToUpper() }
        # Whether to use the global settings is asked again by each menu choice.
        $script:UseGlobal = $null; $script:Global = $null; $script:RunAi = ''
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
                    Add-AiOffer $ap; Invoke-Sub 'HostBadger.ps1' $ap
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
                    Add-AiOffer $ap; Invoke-Sub 'HostBadger.ps1' $ap
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
            '8' { Edit-GlobalSettings }
            'Q' { break }
            default { Write-Host "Pick 1-8 or Q." -ForegroundColor Yellow }
        }
        if ($choice -eq 'Q') { break }
    }
    Write-Host "Bye." -ForegroundColor DarkYellow
}
finally { Stop-SessionLog }
