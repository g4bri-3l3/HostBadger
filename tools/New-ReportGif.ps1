<#
.SYNOPSIS
    Turns a HostBadger HTML report into an animated GIF of slides, one per section, each with a
    caption that says what you are looking at (for the README, a ticket, a demo).

.DESCRIPTION
    Windows only, in Windows PowerShell 5.1 (it uses the WPF imaging classes to write the GIF), and
    needs Microsoft Edge (or Chrome): the report is rendered by the browser in headless mode, the
    position of each section is read from the page, and one slide is cut for each of them: the fleet
    cards, the charts, the hosts, the incomplete coverage, the checks (one of them opened), the
    installed software and the findings table. Sections a report doesn't have (no AI summary, no
    coverage gaps) are skipped.

    The browser works on a copy of the report in a temporary folder, with -OpenCheck expanded; the
    report itself is not changed. Each slide stays on screen for -FrameSeconds (default 3).

    A report built from real hosts shows real names. For the README, build the GIF from the
    synthetic demo (examples\demo_report.html).

.PARAMETER Report
    The HTML report.
.PARAMETER OutFile
    GIF to write (default: next to the report, same name).
.PARAMETER OpenCheck
    The check shown opened, with why it matters, the attacks it enables, the fix script and the
    value found against the value required (default smb_server_signing_not_required).
.PARAMETER FrameSeconds
    How long each slide stays (default 3).
.PARAMETER ViewHeight
    Height of the part of the report shown in a slide, in browser pixels (default 640).
.PARAMETER Width
    Browser width in pixels (default 1200). OutWidth is the width of the GIF (default 960).
.PARAMETER MaxHeight
    Lowest point of the report that can start a slide, in pixels from the top (default 100000).

.EXAMPLE
    powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File .\tools\New-ReportGif.ps1 -Report .\examples\demo_report.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$Report,
    [string]$OutFile = '',
    [string]$OpenCheck = 'smb_server_signing_not_required',
    [int]$Width = 1200,
    [int]$ViewHeight = 640,
    [int]$MaxHeight = 100000,
    [double]$FrameSeconds = 3.0,
    [int]$OutWidth = 960,
    [int]$CaptionHeight = 84,
    [string]$Browser = ''
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this in Windows PowerShell 5.1 (powershell.exe -STA ...): the GIF writer uses WPF.' }
Add-Type -AssemblyName System.Drawing, PresentationCore, WindowsBase, System.Web

if (-not (Test-Path -LiteralPath $Report)) { throw "Report not found: $Report" }
$reportFull = (Resolve-Path -LiteralPath $Report).Path
if (-not $OutFile) { $OutFile = [System.IO.Path]::ChangeExtension($reportFull, '.gif') }
$outFull = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location).Path $OutFile }

if (-not $Browser) {
    $Browser = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Browser) { throw 'No Edge or Chrome found. Pass -Browser <path to msedge.exe or chrome.exe>.' }

# What each slide shows. Sel is a CSS selector (Idx picks the n-th match), Text narrows it by its text.
$plan = @(
    @{ Sel = '.dash-hero'; Idx = 0; Text = ''; Caption = 'Dashboard: the hardening score of the fleet, findings by severity and how many have a fix script; a selector switches to one host.' }
    @{ Sel = '.dash-grid'; Idx = 0; Text = ''; Caption = 'DISA STIG compliance by product and release, CIS-based compliance, and the ACSC Essential Eight strategies the checks bear on.' }
    @{ Sel = '.dash-cats'; Idx = 0; Text = ''; Caption = 'Hardening categories, then the top risks, each with the attacks it enables.' }
    @{ Sel = '.chart-row'; Idx = 0; Text = ''; Caption = 'DISA STIG and CIS compliance, findings by severity and category, administrators vs standard users, software, missing updates, hosts by grade.' }
    @{ Sel = 'summary h2'; Idx = 0; Text = 'Hosts'; Caption = 'Every host: role, operating system, grade and score, findings by severity, checks not evaluated and the EDR agent it runs.' }
    @{ Sel = 'blockquote.warn'; Idx = 0; Text = ''; Caption = 'Incomplete coverage: checks that could not be evaluated (here, a host collected as a standard user) are listed, never counted as clean.' }
    @{ Sel = '.ai-section'; Idx = 0; Text = ''; Caption = 'Optional Gemini summary and remediation plan. Names were replaced by tokens before anything was sent.' }
    @{ Sel = 'summary h2'; Idx = 0; Text = 'Summary by category'; Caption = 'Findings by category and severity.' }
    @{ Sel = 'summary h2'; Idx = 0; Text = 'Findings by check'; Caption = 'Findings by check, worst first: one block per triggered check, with how many findings on how many hosts.' }
    @{ Sel = 'details.check[open]'; Idx = 0; Text = ''; Caption = 'An opened check: why it matters, the attacks it enables, MITRE and CIS rules, each finding with the value found and required, and a fix script that previews until $Apply.' }
    @{ Sel = 'summary h2'; Idx = 0; Text = 'Installed software'; Caption = 'Installed software of every host; with endoflife.date, Chocolatey or NVD data, programs out of support, behind their line or with known CVEs are flagged.' }
    @{ Sel = 'summary h2'; Idx = 0; Text = 'All findings'; Caption = 'Every finding in one filterable table, also written as CSV and JSON Lines for a SIEM.' }
)

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hostbadger_gif_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $profileDir = Join-Path $tmp 'profile'
    $html = [System.IO.File]::ReadAllText($reportFull)
    # The copy the browser renders: every section open (Installed software and All findings start
    # closed) and the chosen check opened.
    $html = $html.Replace('<details><summary><h2>', '<details open><summary><h2>')
    # The Details tab is hidden until clicked: shown under the dashboard in the copy.
    $html = $html.Replace('<div data-tab="details" hidden>', '<div data-tab="details">')
    if ($OpenCheck) {
        $at = $html.IndexOf("check-id`">$OpenCheck ")
        $start = if ($at -ge 0) { $html.LastIndexOf('<details class="check">', $at) } else { -1 }
        if ($start -lt 0) { Write-Warning "Check $OpenCheck is not in the report: no check is shown opened." }
        else { $html = $html.Remove($start, '<details class="check">'.Length).Insert($start, '<details class="check" open>') }
    }
    $page = Join-Path $tmp 'report.html'
    [System.IO.File]::WriteAllText($page, $html, (New-Object System.Text.UTF8Encoding($false)))

    # ---- 1. Ask the browser where each section is (the copy with a small script added) ----
    $planJson = ($plan | ForEach-Object { @{ sel = $_.Sel; idx = $_.Idx; text = $_.Text } } | ConvertTo-Json -Compress)
    $probeJs = @'
<script>
(function () {
  var plan = __PLAN__; var out = [];
  plan.forEach(function (p, n) {
    var all = Array.prototype.slice.call(document.querySelectorAll(p.sel));
    if (p.text) { all = all.filter(function (e) { return (e.textContent || '').replace(/\s+/g, ' ').trim() === p.text; }); }
    var e = all[p.idx];
    if (e) { out.push({ n: n, y: Math.round(e.getBoundingClientRect().top + window.pageYOffset) }); }
  });
  var pre = document.createElement('pre');
  pre.textContent = 'HBPLAN:' + JSON.stringify({ h: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight), slides: out }) + ':ENDPLAN';
  document.body.appendChild(pre);
})();
</script>
'@.Replace('__PLAN__', $planJson)
    $probe = Join-Path $tmp 'probe.html'
    $idx = $html.LastIndexOf('</body>', [System.StringComparison]::OrdinalIgnoreCase)
    $probeHtml = if ($idx -ge 0) { $html.Insert($idx, $probeJs) } else { $html + $probeJs }
    [System.IO.File]::WriteAllText($probe, $probeHtml, (New-Object System.Text.UTF8Encoding($false)))
    $ErrorActionPreference = 'Continue'
    $dom = & $Browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 "--user-data-dir=$profileDir-probe" "--window-size=$Width,$ViewHeight" --virtual-time-budget=4000 --dump-dom ([System.Uri]$probe).AbsoluteUri 2>$null | Out-String
    $ErrorActionPreference = 'Stop'
    $m = [regex]::Match($dom, 'HBPLAN:(\{.*?\}):ENDPLAN', 'Singleline')
    if (-not $m.Success) { throw 'Could not read the section positions from the page.' }
    $found = [System.Web.HttpUtility]::HtmlDecode($m.Groups[1].Value) | ConvertFrom-Json
    $pageH = [int]$found.h
    $slides = @($found.slides | Where-Object { $_.y -lt $MaxHeight } | Sort-Object { [int]$_.y })
    if ($slides.Count -eq 0) { throw 'No known section found in the report.' }

    # ---- 2. One slide per section: a window-sized screenshot of the copy moved up to the section (a
    # single screenshot of a page this tall comes out partly blank), and the caption under it ----
    $frames = New-Object System.Collections.Generic.List[object]
    $delays = New-Object System.Collections.Generic.List[int]   # in hundredths of a second
    $outH = [int][Math]::Round($ViewHeight * $OutWidth / $Width)
    Write-Host "Report height $pageH px, $($slides.Count) slides of $OutWidth x $($outH + $CaptionHeight), $FrameSeconds s each."
    $captionFont = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $counterFont = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $bandBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#23262A'))
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#F1F3F5'))
    $dimBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#9AA0A6'))
    $headAt = $html.IndexOf('</head>', [System.StringComparison]::OrdinalIgnoreCase)
    $i = 0
    foreach ($s in $slides) {
        $i++
        $top = if ($i -eq 1) { 0 } else { [Math]::Max(0, [int]$s.y - 24) }
        $top = [Math]::Min($top, [Math]::Max(0, $pageH - $ViewHeight))
        # The page moves itself to the section once it is laid out (positions measured in another
        # browser run drift by a few dozen pixels on a long report); the measured top is the fallback.
        $p = $plan[[int]$s.n]
        $target = if ($i -eq 1) { 'null' } else { (@{ sel = $p.Sel; idx = $p.Idx; text = $p.Text } | ConvertTo-Json -Compress) }
        $shift = @'
<style>html { overflow: hidden; } body { transform: translateY(-__TOP__px); }</style>
<script>
// After the report's own scripts have run (they fill the table filters and counters).
window.addEventListener('load', function () { setTimeout(function () {
  var p = __TARGET__; if (!p) { return; }
  var all = Array.prototype.slice.call(document.querySelectorAll(p.sel));
  if (p.text) { all = all.filter(function (e) { return (e.textContent || '').replace(/\s+/g, ' ').trim() === p.text; }); }
  var e = all[p.idx]; if (!e) { return; }
  document.body.style.transform = 'none';
  // Hide what comes before the section: far down a long page, headless rendering without a GPU draws
  // shifted or blank, so the section is brought near the top instead of the page moved a long way.
  for (var n = e; n && n !== document.body; n = n.parentElement) {
    for (var s = n.previousElementSibling; s; s = s.previousElementSibling) { if (s.tagName !== 'SCRIPT' && s.tagName !== 'STYLE') { s.style.display = 'none'; } }
  }
  var y = e.getBoundingClientRect().top + window.pageYOffset - 24;
  document.body.style.transform = 'translateY(-' + Math.max(0, y) + 'px)';
}, 500); });
</script>
'@.Replace('__TOP__', "$top").Replace('__TARGET__', $target)
        $slidePage = Join-Path $tmp "slide$i.html"
        [System.IO.File]::WriteAllText($slidePage, $(if ($headAt -ge 0) { $html.Insert($headAt, $shift) } else { $shift + $html }), (New-Object System.Text.UTF8Encoding($false)))
        $png = Join-Path $tmp "slide$i.png"
        $ErrorActionPreference = 'Continue'
        & $Browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 "--user-data-dir=$profileDir" "--window-size=$Width,$ViewHeight" --virtual-time-budget=4000 "--screenshot=$png" ([System.Uri]$slidePage).AbsoluteUri 2>&1 | Out-Null
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path $png)) { throw "The browser produced no screenshot ($Browser)." }
        $shot = New-Object System.Drawing.Bitmap($png)
        $bmp = New-Object System.Drawing.Bitmap($OutWidth, ($outH + $CaptionHeight))
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.DrawImage($shot, (New-Object System.Drawing.Rectangle(0, 0, $OutWidth, $outH)), (New-Object System.Drawing.Rectangle(0, 0, $Width, [Math]::Min($ViewHeight, $shot.Height))), [System.Drawing.GraphicsUnit]::Pixel)
        $shot.Dispose()
        $g.FillRectangle($bandBrush, 0, $outH, $OutWidth, $CaptionHeight)
        $fmt = New-Object System.Drawing.StringFormat
        $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisWord
        $g.DrawString([string]$plan[[int]$s.n].Caption, $captionFont, $textBrush, (New-Object System.Drawing.RectangleF(18, ($outH + 12), ($OutWidth - 36), ($CaptionHeight - 28))), $fmt)
        $fmtR = New-Object System.Drawing.StringFormat; $fmtR.Alignment = [System.Drawing.StringAlignment]::Far
        $g.DrawString("$i / $($slides.Count)", $counterFont, $dimBrush, (New-Object System.Drawing.RectangleF(18, ($outH + $CaptionHeight - 20), ($OutWidth - 36), 18)), $fmtR)
        $g.Dispose()
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
        $ms.Position = 0
        $dec = New-Object System.Windows.Media.Imaging.PngBitmapDecoder($ms, [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat, [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad)
        $src = $dec.Frames[0]; $src.Freeze()
        $delays.Add([int][Math]::Min(65535, [int]($FrameSeconds * 100)))
        $frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($src))
    }

    # ---- 4. Write the GIF, then add the "loop forever" block WPF doesn't write ----
    $enc = New-Object System.Windows.Media.Imaging.GifBitmapEncoder
    foreach ($f in $frames) { $enc.Frames.Add($f) }
    $ms = New-Object System.IO.MemoryStream
    $enc.Save($ms)
    $bytes = $ms.ToArray()
    $gctSize = if (($bytes[10] -band 0x80) -ne 0) { 3 * [Math]::Pow(2, ($bytes[10] -band 0x07) + 1) } else { 0 }
    $insertAt = 13 + [int]$gctSize
    $loop = [byte[]](0x21, 0xFF, 0x0B) + [System.Text.Encoding]::ASCII.GetBytes('NETSCAPE2.0') + [byte[]](0x03, 0x01, 0x00, 0x00, 0x00)
    $final = New-Object byte[] ($bytes.Length + $loop.Length)
    [Array]::Copy($bytes, 0, $final, 0, $insertAt)
    [Array]::Copy($loop, 0, $final, $insertAt, $loop.Length)
    [Array]::Copy($bytes, $insertAt, $final, $insertAt + $loop.Length, $bytes.Length - $insertAt)
    # WPF writes every frame's delay as 0 whatever the metadata says: set them in the graphic control blocks,
    # walking the blocks so the bytes of the picture data are never mistaken for one.
    $p = $insertAt + $loop.Length; $k = 0
    while ($p -lt $final.Length) {
        $t = $final[$p]
        if ($t -eq 0x3B) { break }
        elseif ($t -eq 0x21) {
            if ($final[$p + 1] -eq 0xF9 -and $k -lt $delays.Count) { $final[$p + 4] = [byte]($delays[$k] -band 0xFF); $final[$p + 5] = [byte](($delays[$k] -shr 8) -band 0xFF); $k++ }
            $p += 2; while ($final[$p] -ne 0) { $p += $final[$p] + 1 }; $p++
        }
        elseif ($t -eq 0x2C) {
            $ipk = $final[$p + 9]; $p += 10
            if (($ipk -band 0x80) -ne 0) { $p += 3 * [int][Math]::Pow(2, ($ipk -band 0x07) + 1) }
            $p++; while ($final[$p] -ne 0) { $p += $final[$p] + 1 }; $p++
        }
        else { throw "Unexpected byte 0x{0:X2} in the GIF at $p" -f $t }
    }
    if ($k -ne $delays.Count) { Write-Warning "Set the delay of $k of $($delays.Count) frames." }
    [System.IO.File]::WriteAllBytes($outFull, $final)
    Write-Host ("GIF written: {0} ({1:N1} MB, {2} slides, {3:N0} s per loop)" -f $outFull, ($final.Length / 1MB), $frames.Count, ($frames.Count * $FrameSeconds))
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
