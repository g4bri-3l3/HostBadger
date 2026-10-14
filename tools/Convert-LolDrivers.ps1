<#
.SYNOPSIS
    Builds data\vulnerable-drivers.json from the LOLDrivers catalog: one entry per
    known vulnerable or malicious Windows driver file, by SHA-256.

.DESCRIPTION
    Developer tool, not part of a HostBadger run: it only reads a local file, it
    does not download anything. Get drivers.json yourself from
    https://www.loldrivers.io/api/drivers.json (the LOLDrivers project,
    https://github.com/magicsword-io/LOLDrivers, Apache License 2.0) and point
    -InputFile at it. The full catalog (~30 MB) is reduced to the fields the
    check uses (hash, LOLDrivers id, vulnerable or malicious, file name,
    verified, CVE ids, loads despite HVCI), about 2,300 entries.

    A HostBadger run can also use a fresh copy instead of this file:
    HostBadger.ps1 -DriversOnline downloads the same catalog and converts it
    the same way (ConvertFrom-LolDrivers in lib\Checks.ps1).
.PARAMETER InputFile
    The drivers.json downloaded from www.loldrivers.io.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputFile,
    [string]$OutFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\vulnerable-drivers.json')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\Common.ps1')
. (Join-Path $root 'lib\Checks.ps1')

$entries = @(ConvertFrom-LolDrivers ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $InputFile).Path)) | Sort-Object { $_.h })
$out = [ordered]@{
    source  = 'LOLDrivers (https://www.loldrivers.io, https://github.com/magicsword-io/LOLDrivers), Apache License 2.0; built by tools\Convert-LolDrivers.ps1'
    count   = $entries.Count
    entries = $entries
}
[System.IO.File]::WriteAllText($OutFile, ($out | ConvertTo-Json -Depth 5 -Compress), (New-Object System.Text.UTF8Encoding $false))
"{0} driver files ({1} malicious, {2} vulnerable; {3} not verified by LOLDrivers). Wrote {4}" -f $entries.Count, @($entries | Where-Object { $_.c -eq 'M' }).Count, @($entries | Where-Object { $_.c -eq 'V' }).Count, @($entries | Where-Object { -not $_.v }).Count, $OutFile
