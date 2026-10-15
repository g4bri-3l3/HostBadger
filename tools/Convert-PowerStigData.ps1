<#
.SYNOPSIS
    Builds data\stig-catalog.json (and the registry list embedded in the
    collector) from the processed DISA STIG files of Microsoft PowerSTIG.

.DESCRIPTION
    Developer tool, not part of a HostBadger run: it only reads local XML, it
    does not download anything. Get the files yourself from
    https://github.com/microsoft/PowerSTIG (MIT license), folder
    source/StigData/Processed, and point -InputDir at them. The STIG content
    is published by DISA (public).

    Only RegistryRule entries are used. A rule becomes a catalog entry when
    its expected value is fixed, or when the organization value has a test
    string this script understands (a number, a list of numbers, a range).
    Rules that need a decision (an approved URL list, a banner text) are
    counted and left out: the script lists them at the end.

    The registry values the collector has to read are written between the
    STIG-REGISTRY markers of Collect-HostSnapshot.ps1.
.PARAMETER InputDir
    Folder with the PowerSTIG processed XML files.
.PARAMETER Files
    Product tag -> file name. The defaults are the releases HostBadger ships with.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDir,
    [string]$OutCatalog = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\stig-catalog.json'),
    [string]$Collector = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Collect-HostSnapshot.ps1'),
    [hashtable]$Files = @{
        win10    = 'WindowsClient-10-3.6.xml'
        win11    = 'WindowsClient-11-2.7.xml'
        defender = 'WindowsDefender-All-2.8.xml'
        firewall = 'WindowsFirewall-All-2.2.xml'
        edge     = 'MS-Edge-2.5.xml'
        chrome   = 'Google-Chrome-2.11.xml'
        firefox  = 'FireFox-All-6.7.xml'
        office   = 'Office-365ProPlus-3.5.xml'
        srv2016dc = 'WindowsServer-2016-DC-2.10.xml'
        srv2016ms = 'WindowsServer-2016-MS-2.10.xml'
        srv2019dc = 'WindowsServer-2019-DC-3.8.xml'
        srv2019ms = 'WindowsServer-2019-MS-3.8.xml'
        srv2022dc = 'WindowsServer-2022-DC-2.8.xml'
        srv2022ms = 'WindowsServer-2022-MS-2.8.xml'
        srv2025dc = 'WindowsServer-2025-DC-1.1.xml'
        srv2025ms = 'WindowsServer-2025-MS-1.1.xml'
        adobereader = 'Adobe-AcrobatReader-2.1.xml'
        adobepro  = 'Adobe-AcrobatPro-2.1.xml'
    }
)
$ErrorActionPreference = 'Stop'

function ConvertTo-StigExpect {
    # The expected value from the organization test string. $null = needs a human decision.
    param([string]$Test)
    $t = "$Test".Trim()
    if (-not $t) { return $null }
    $absentOk = $t -match 'DoesNotExist|ShouldBeAbsent'
    # -match 'a|b|c' and -eq '1|2'
    $m = [regex]::Match($t, "-(?:match|eq)\s+'(?<v>[\d|]*(?:\|?(?:ShouldBeAbsent|DoesNotExist))?[\d|]*)'")
    if ($m.Success -and $t -notmatch '-(ge|le|gt|lt)') {
        $vals = @($m.Groups['v'].Value -split '\|' | Where-Object { $_ -match '^\d+$' })
        if ($vals.Count -gt 0) { return [ordered]@{ op = 'in'; v = $vals; absentOk = [bool]$absentOk } }
    }
    # {0} is 2|3|4   /   {0} is 1 or 2 or 3   /   {0} is 6
    if ($t -match '\((\d+)\) or greater\s*$') { return [ordered]@{ op = 'range'; min = [int64]$Matches[1]; max = $null; absentOk = $false } }
    $m = [regex]::Match($t, '^\{0\} is (?<v>[\d|]+(?:\s+or\s+\d+)*(?:\|DoesNotExist)?)\s*$')
    if ($m.Success) {
        $vals = @($m.Groups['v'].Value -split '\||\s+or\s+' | Where-Object { $_ -match '^\d+$' })
        if ($vals.Count -gt 0) { return [ordered]@{ op = 'in'; v = $vals; absentOk = [bool]$absentOk } }
    }
    if ($t -match '^\{0\} is (\d+) or greator\s*$') { return [ordered]@{ op = 'range'; min = [int64]$Matches[1]; max = $null; absentOk = $false } }
    # '{0}' -ge '32768'   /   {0} -ge '1' -and {0} -le '7'
    $cmp = [regex]::Matches($t, "-(ge|le|gt|lt)\s+'?(\d+)'?")
    if ($cmp.Count -gt 0 -and $t -notmatch '-(match|eq)\s') {
        $min = $null; $max = $null
        foreach ($c in $cmp) {
            $n = [int64]$c.Groups[2].Value
            switch ($c.Groups[1].Value) { 'ge' { $min = $n } 'gt' { $min = $n + 1 } 'le' { $max = $n } 'lt' { $max = $n - 1 } }
        }
        return [ordered]@{ op = 'range'; min = $min; max = $max; absentOk = $false }
    }
    return $null
}

function Get-ShortWhy {
    param([string]$Description)
    $d = [System.Net.WebUtility]::HtmlDecode("$Description")
    $m = [regex]::Match($d, '(?s)<VulnDiscussion>(.*?)</VulnDiscussion>')
    $txt = if ($m.Success) { $m.Groups[1].Value } else { $d }
    $txt = ($txt -replace '\s+', ' ').Trim()
    $cut = [regex]::Match($txt, '^.{40,220}?[.!?](\s|$)')
    if ($cut.Success) { return $cut.Value.Trim() }
    if ($txt.Length -gt 200) { return $txt.Substring(0, 200).TrimEnd() + '...' }
    return $txt
}

$catalog = New-Object System.Collections.Generic.List[object]
$skipped = New-Object System.Collections.Generic.List[string]
$kindMap = @{ Dword = 'D'; String = 'S'; MultiString = 'M'; None = 'N'; '' = 'N' }
foreach ($prod in $Files.Keys | Sort-Object) {
    $path = Join-Path $InputDir $Files[$prod]
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing $path" }
    [xml]$x = [System.IO.File]::ReadAllText($path)
    foreach ($r in @($x.SelectNodes('/DISASTIG/RegistryRule/Rule'))) {
        $key = "$($r.Key)"
        $scope = if ($key -match '^HKEY_CURRENT_USER\\') { 'U' } elseif ($key -match '^HKEY_LOCAL_MACHINE\\') { 'M' } else { $null }
        if (-not $scope) { $skipped.Add("$prod $($r.id): hive not supported ($key)"); continue }
        $sub = $key -replace '^HKEY_(CURRENT_USER|LOCAL_MACHINE)\\', ''
        # A few rules carry a sentence instead of a value name, or a stray word before it.
        $vname = "$($r.ValueName)" -replace '^for ', ''
        if ($vname.Length -gt 60) { $skipped.Add("$prod $($r.id): the value name is a sentence"); continue }
        $ensure = if ("$($r.Ensure)" -eq 'Absent') { 'A' } else { 'P' }
        $kind = $kindMap["$($r.ValueType)"]; if (-not $kind) { $kind = 'S' }
        $expect = $null
        if ($ensure -eq 'A') { $expect = [ordered]@{ op = 'absent' } }
        elseif ($r.OrganizationValueRequired -eq 'True') { $expect = ConvertTo-StigExpect $r.OrganizationValueTestString }
        elseif ("$($r.ValueData)" -ne '') {
            if ($kind -eq 'M') { $skipped.Add("$prod $($r.id): multi-string value"); continue }
            $expect = [ordered]@{ op = 'eq'; v = "$($r.ValueData)" }
        }
        if (-not $expect) { $skipped.Add("$prod $($r.id): needs an organization value ($($r.OrganizationValueTestString.Trim()))"); continue }
        $sev = switch ("$($r.severity)") { 'high' { 'H' } 'low' { 'L' } default { 'M' } }
        $catalog.Add([ordered]@{ id = "$($r.id)"; p = $prod; s = $sev; h = $scope; k = $sub; n = $vname; t = $kind; e = $ensure; x = $expect; d = (Get-ShortWhy $r.Description) })
    }
}
$sorted = @($catalog | Sort-Object { $_.p }, { $_.id })
$dir = Split-Path $OutCatalog -Parent
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$json = ConvertTo-Json -InputObject $sorted -Depth 6 -Compress
[System.IO.File]::WriteAllText($OutCatalog, $json, (New-Object System.Text.UTF8Encoding($false)))

# The values the collector reads: one line per (scope, key, name), case-insensitive unique.
$seen = @{}; $lines = New-Object System.Collections.Generic.List[string]
foreach ($e in $sorted) {
    $id = "$($e.h)|$($e.k)|$($e.n)".ToLower()
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    $lines.Add("    '$($e.h)|$($e.k.Replace("'", "''"))|$($e.n.Replace("'", "''"))'")
}
$block = "# BEGIN STIG-REGISTRY (generated by tools\Convert-PowerStigData.ps1; do not edit)`r`n`$stigRegistryList = @(`r`n" + ($lines -join "`r`n") + "`r`n)`r`n# END STIG-REGISTRY"
$src = [System.IO.File]::ReadAllText($Collector)
$pattern = '(?s)# BEGIN STIG-REGISTRY.*?# END STIG-REGISTRY'
if ($src -notmatch $pattern) { throw "Markers STIG-REGISTRY not found in $Collector" }
$src = [regex]::Replace($src, $pattern, { param($mm) $block })
[System.IO.File]::WriteAllText($Collector, $src, (New-Object System.Text.UTF8Encoding($false)))

"{0} catalog entries, {1} registry values for the collector, {2} rules left out." -f $sorted.Count, $lines.Count, $skipped.Count
$sorted | Group-Object { $_.p } | ForEach-Object { "  {0,-9} {1}" -f $_.Name, $_.Count }
$skipped | ForEach-Object { "  skipped: $_" }
