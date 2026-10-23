<#
.SYNOPSIS
    Builds data\malicious-extensions.json: the ids of browser extensions removed
    from the Chrome Web Store or Edge Add-ons, or documented as malicious.

.DESCRIPTION
    Developer tool, not part of a HostBadger run: it only reads local files, it
    does not download anything. Two sources, downloaded by you:

    -SentryCsv: malicious_extensions_detailed.csv from malicious_extension_sentry
    (malext.io, by toborrm9, https://github.com/toborrm9/malicious_extension_sentry,
    data under CC BY 4.0, updated daily): one row per extension removed from the
    store, with its name, the reason and the date it was listed.

    -PalantList: list.txt from Wladimir Palant's malicious-extensions-list
    (https://codeberg.org/palant/malicious-extensions-list, CC0, archived in
    2026): "# <article>" lines followed by the extension ids it documents.

    A HostBadger run can use a fresh sentry list instead of this file:
    HostBadger.ps1 -ExtensionsOnline downloads it and converts it the same way
    (ConvertFrom-ExtensionSentryCsv in lib\Checks.ps1), keeping the Palant entries
    of this file.
.PARAMETER SentryCsv
    malicious_extensions_detailed.csv from the malicious_extension_sentry repository.
.PARAMETER PalantList
    list.txt from the malicious-extensions-list repository.
.PARAMETER Retrieved
    The date the files were downloaded (yyyy-MM-dd), written into the catalog.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SentryCsv,
    [Parameter(Mandatory)][string]$PalantList,
    [Parameter(Mandatory)][ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved,
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
# Here, not as the default: Windows PowerShell 5.1 has no $PSScriptRoot while it binds parameters.
if (-not $OutFile) { $OutFile = Join-Path $root 'data\malicious-extensions.json' }
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'lib\Checks.ps1')
$entries = New-Object System.Collections.Generic.List[object]
$seen = @{}
foreach ($e in @(ConvertFrom-ExtensionSentryCsv ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $SentryCsv))))) { $seen[$e.i] = $true; $entries.Add($e) }
$sentry = $entries.Count
$ref = ''
foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $PalantList))) {
    $l = $line.Trim()
    if (-not $l) { continue }
    if ($l -match '^#\s*(\S+)') { $ref = $Matches[1]; continue }
    if ($l -notmatch '^[a-p]{32}$') { throw "Not an extension id: '$l'" }
    # An id on both lists keeps the sentry entry, which has the store's reason.
    if ($seen.ContainsKey($l)) { continue }
    $seen[$l] = $true
    $entries.Add([ordered]@{ i = $l; n = ''; r = 'Potentially malicious'; s = $ref; d = ''; f = 'palant' })
}
$catalog = [ordered]@{
    sources   = @(
        'malicious_extension_sentry (malext.io, by toborrm9), https://github.com/toborrm9/malicious_extension_sentry, CC BY 4.0. Modified from: extension IOC data from malext.io (malicious_extension_sentry), licensed under CC BY 4.0 (reduced to id, name, reason, source, date).',
        'malicious-extensions-list by Wladimir Palant, https://codeberg.org/palant/malicious-extensions-list, CC0 1.0.')
    retrieved = $Retrieved
    note      = 'Rebuild with tools\Convert-MaliciousExtensions.ps1. Fields: i id, n name, r reason, s source, d date listed, f feed.'
    count     = $entries.Count
    entries   = $entries.ToArray()
}
[System.IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject $catalog -Depth 4 -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $($entries.Count) extension ids to $OutFile ($sentry from malicious_extension_sentry, $($entries.Count - $sentry) from Palant's list)"
