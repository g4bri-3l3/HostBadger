<#
.SYNOPSIS
    Builds data\acn-nis2-measures.json: the basic security measures that the
    Italian National Cybersecurity Agency (ACN) sets for NIS entities.

.DESCRIPTION
    Developer tool, not part of a HostBadger run: it only reads local files, it
    does not download anything. The source is the two spreadsheets ACN publishes
    with Determinazione 379907/2025 (the basic obligations of D.Lgs. 138/2024,
    which transposes the NIS2 directive), on
    https://www.acn.gov.it/portale/nis/modalita-specifiche-base, downloaded by you:

    -Important: "Modalita e specifiche di base NIS - soggetti importanti"
    (the measures of Allegato 1).
    -Essential: "Modalita e specifiche di base NIS - soggetti essenziali"
    (the measures of Allegato 2).

    Each row is one requirement (code of the Framework Nazionale per la
    Cybersecurity e la Data Protection, point, text). The text is kept as ACN
    wrote it, in Italian. lib\Checks.ps1 ($script:AcnRequirements) ties the
    requirements a host can show to the HostBadger checks; the texts come from
    this file.
.PARAMETER Important
    The .xlsx of the measures for soggetti importanti.
.PARAMETER Essential
    The .xlsx of the measures for soggetti essenziali.
.PARAMETER Retrieved
    The date the files were downloaded (yyyy-MM-dd), written into the file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Important,
    [Parameter(Mandatory)][string]$Essential,
    [Parameter(Mandatory)][ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved,
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
# Here, not as the default: Windows PowerShell 5.1 has no $PSScriptRoot while it binds parameters.
if (-not $OutFile) { $OutFile = Join-Path $root 'data\acn-nis2-measures.json' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-ZipXml {
    param($Zip, [string]$Name)
    $e = $Zip.GetEntry($Name)
    if (-not $e) { return $null }
    $r = New-Object System.IO.StreamReader($e.Open(), [System.Text.Encoding]::UTF8)
    # Keep whitespace: a rich-text run can be a single space between two words.
    $x = New-Object System.Xml.XmlDocument
    $x.PreserveWhitespace = $true
    try { $x.LoadXml($r.ReadToEnd()); return $x } finally { $r.Dispose() }
}

function Get-CellText {
    # A cell's text: shared string, inline string or plain value.
    param($Cell, $Strings)
    if ($Cell.t -eq 's') { return $Strings[[int]$Cell.v] }
    if ($Cell.t -eq 'inlineStr') { return (@($Cell.is.SelectNodes('.//*[local-name()="t"]') | ForEach-Object { $_.InnerText }) -join '') }
    return "$($Cell.v)"
}

function Read-AcnSheet {
    # The requirement rows of the first worksheet, by column letter (empty cells are absent from the XML):
    # A Funzione, B Categoria, C Codice, D Descrizione, E Punto, F Requisito, G Ambiti politiche.
    param([string]$Path)
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    try {
        $strings = @()
        $ss = Read-ZipXml $zip 'xl/sharedStrings.xml'
        if ($ss) { $strings = @(foreach ($si in $ss.sst.si) { (@($si.SelectNodes('.//*[local-name()="t"]') | ForEach-Object { $_.InnerText }) -join '') }) }
        $sheet = Read-ZipXml $zip 'xl/worksheets/sheet1.xml'
        foreach ($row in @($sheet.worksheet.sheetData.row)) {
            $cols = @{}
            foreach ($c in @($row.c)) { if ($c.r -match '^([A-Z]+)\d+$') { $cols[$Matches[1]] = (Get-CellText $c $strings) } }
            if ("$($cols['C'])" -notmatch '^[A-Z]{2}\.[A-Z]{2}-\d{2}$' -or "$($cols['E'])" -notmatch '^\d+$') { continue }
            # One line per requirement: the spreadsheet breaks lists into lines and pads with spaces.
            $text = (("$($cols['F'])" -replace '\s*\r?\n\s*', ' ' -replace '\t', ' ' -replace ' {2,}', ' ') -replace '\s+([.,;:])', '$1').Trim()
            [ordered]@{ code = $cols['C']; point = [int]$cols['E']; area = ("$($cols['G'])" -replace '\s+', ' ').Trim(); text = $text }
        }
    } finally { $zip.Dispose() }
}

$imp = @(Read-AcnSheet $Important)
$ess = @(Read-AcnSheet $Essential)
if ($imp.Count -lt 50 -or $ess.Count -lt $imp.Count) { throw "Unexpected spreadsheets: $($imp.Count) requirement(s) for soggetti importanti, $($ess.Count) for soggetti essenziali." }
$impKeys = @{}; foreach ($r in $imp) { $impKeys["$($r.code) $($r.point)"] = $r }
$measures = foreach ($r in $ess) {
    $k = "$($r.code) $($r.point)"
    # The essential text is the reference; a requirement both lists have but word differently is kept twice.
    $m = [ordered]@{ code = $r.code; point = $r.point; area = $r.area; essential = $r.text }
    if ($impKeys.ContainsKey($k)) { $m['important'] = $impKeys[$k].text }
    $m
}
foreach ($r in $imp) { if (-not (@($ess | Where-Object { $_.code -eq $r.code -and $_.point -eq $r.point }).Count)) { throw "$($r.code) point $($r.point) is in the soggetti importanti list only." } }
$out = [ordered]@{
    source    = 'Agenzia per la Cybersicurezza Nazionale (ACN), Determinazione 379907/2025, Allegato 1 (soggetti importanti) and Allegato 2 (soggetti essenziali): modalita e specifiche di base NIS, D.Lgs. 138/2024. https://www.acn.gov.it/portale/nis/modalita-specifiche-base'
    retrieved = $Retrieved
    note      = 'Requirement texts as published by ACN (Italian). "important" is absent when the requirement applies to soggetti essenziali only.'
    count     = @($measures).Count
    measures  = @($measures)
}
[System.IO.File]::WriteAllText($OutFile, ($out | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
"Wrote $OutFile ($(@($measures).Count) requirements, $($imp.Count) for soggetti importanti)."
