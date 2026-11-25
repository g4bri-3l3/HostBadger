<#
.SYNOPSIS
    Builds the HostBadger module that is published to the PowerShell Gallery.

.DESCRIPTION
    HostBadger is a set of scripts, not a module: HostBadger.ps1 dot-sources lib\*.ps1 and the
    catalogs live in data\. The Gallery wants a module, so this tool writes one beside the
    repository instead of turning the repository into one.

    What it writes: the scripts, lib\, data\ and a few examples copied unchanged, a generated
    HostBadger.psm1 that gives each entry point a function, and HostBadger.psd1. Each function runs
    that very script file, in process, with the parameters it was handed, so $PSScriptRoot inside
    the script still points at the folder holding lib\ and data\ and nothing about the scripts
    changes. The param block, its attributes and the comment based help of each function are copied
    from the script's own source with the PowerShell parser: the parameters of HostBadger.ps1 are
    never written down twice, and a new one reaches the module by building it again.

    A SecureString parameter works better here than on the command line: the function runs the
    script in process, so -SnapshotPassword does not have to cross a new PowerShell.

    Nothing is published and nothing in the repository is changed. The build folder is under
    output\, which is not committed. Run tests\Run-Regression.ps1 first: this tool only packages.

.PARAMETER OutDir
    Where to build. Default <repo>\output\module. The module lands in <OutDir>\HostBadger, so the
    folder name is the module name, as Publish-PSResource wants it.
.PARAMETER Root
    The repository. Default the folder above this tool.
.EXAMPLE
    .\tools\New-HostBadgerModule.ps1
    Builds output\module\HostBadger, ready for Test-ModuleManifest and Publish-PSResource.
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [string]$Root = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'

$moduleName = 'HostBadger'
# The Gallery ties every version of the module to this GUID. It never changes.
$moduleGuid = 'b70f2e8a-3b7c-4473-86ba-fc3841d7b41d'
$projectUri = 'https://github.com/g4bri-3l3/HostBadger'

# Script -> exported function. The verb has to be an approved one (the Gallery runs PSScriptAnalyzer
# and shows what it says), so the collector is New-HostSnapshot with its name on disk as an alias.
$entries = @(
    @{ Script = 'HostBadger.ps1'; Function = 'Invoke-HostBadger'; Alias = '' }
    @{ Script = 'Collect-HostSnapshot.ps1'; Function = 'New-HostSnapshot'; Alias = 'Collect-HostSnapshot' }
    @{ Script = 'Start-HostBadger.ps1'; Function = 'Start-HostBadger'; Alias = '' }
    @{ Script = 'Start-HostBadgerGui.ps1'; Function = 'Start-HostBadgerGui'; Alias = '' }
    @{ Script = 'Test-HostBadgerSafety.ps1'; Function = 'Test-HostBadgerSafety'; Alias = '' }
    @{ Script = 'tests\New-SyntheticHostSnapshot.ps1'; Function = 'New-SyntheticHostSnapshot'; Alias = '' }
)

# Copied unchanged. The demo report, the GIF and the developer tools stay out: megabytes a run does
# not read. examples\fleet is kept because it is the first thing the README analyzes.
$rootFiles = @('HostBadger.ps1', 'Collect-HostSnapshot.ps1', 'Start-HostBadger.ps1', 'Start-HostBadgerGui.ps1',
    'Test-HostBadgerSafety.ps1', 'LICENSE', 'README.md', 'CHANGELOG.md', 'COVERAGE.md', 'SECURITY.md')
$treeFiles = @('lib\*.ps1', 'data\*.json', 'tests\New-SyntheticHostSnapshot.ps1',
    'examples\policy.example.json', 'examples\exceptions.example.json', 'examples\fleet\*')

function Get-HbVersion {
    param([string]$Path)
    $text = [System.IO.File]::ReadAllText($Path)
    if ($text -notmatch "\`$script:HostBadgerVersion = '([^']+)'") { throw "$Path does not say its version" }
    $Matches[1]
}

function Get-HbScriptParts {
    param([string]$Path, [string]$Function)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) { throw "$Path does not parse: $($errors[0].Message)" }
    $pb = $ast.ParamBlock
    if (-not $pb) { throw "$Path has no script level param block, so no function can be generated from it" }
    $help = ''
    foreach ($t in $tokens) {
        if ("$($t.Kind)" -eq 'Comment' -and $t.Text.StartsWith('<#') -and $t.Extent.StartOffset -lt $pb.Extent.StartOffset) {
            $help = $t.Text
            break
        }
    }
    # The help tells the reader to run .\HostBadger.ps1; as a function it is Invoke-HostBadger.
    $leaf = Split-Path $Path -Leaf
    if ($help) { $help = $help -replace ('(?i)\.\\(?:tests\\)?' + [regex]::Escape($leaf)), $Function }
    [PSCustomObject]@{
        Help     = $help
        Attrs    = @($pb.Attributes | ForEach-Object { $_.Extent.Text })
        Param    = $pb.Extent.Text
        Advanced = @($pb.Attributes | Where-Object { $_.TypeName.Name -match '^CmdletBinding' }).Count -gt 0
    }
}

function Add-HbIndent {
    param([string]$Text)
    (($Text -split "`r?`n") | ForEach-Object { if ($_.Trim()) { '    ' + $_ } else { '' } }) -join "`r`n"
}

$version = Get-HbVersion (Join-Path $Root 'HostBadger.ps1')
if (-not $OutDir) { $OutDir = Join-Path $Root 'output\module' }
$dest = Join-Path $OutDir $moduleName

if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
[void](New-Item -ItemType Directory -Path $dest -Force)
Write-Host "HostBadger $version -> $dest" -ForegroundColor Cyan

# -- the files ---------------------------------------------------------------------------------
$fileList = New-Object System.Collections.Generic.List[string]
$copy = {
    param($relative)
    $to = Join-Path $dest $relative
    $parent = Split-Path $to -Parent
    if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
    Copy-Item -LiteralPath (Join-Path $Root $relative) -Destination $to -Force
    $fileList.Add($relative)
}
foreach ($f in $rootFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root $f))) { throw "missing from the repository: $f" }
    & $copy $f
}
foreach ($pattern in $treeFiles) {
    $folder = Split-Path $pattern -Parent
    $found = @(Get-ChildItem -LiteralPath (Join-Path $Root $folder) -File -Filter (Split-Path $pattern -Leaf))
    if ($found.Count -eq 0) { throw "nothing matched $pattern" }
    foreach ($f in $found) { & $copy (Join-Path $folder $f.Name) }
}

# -- HostBadger.psm1 ---------------------------------------------------------------------------
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# HostBadger $version - the module face of the scripts next to this file.")
[void]$sb.AppendLine('#')
[void]$sb.AppendLine('# GENERATED by tools\New-HostBadgerModule.ps1 from the scripts themselves. Do not edit: a change')
[void]$sb.AppendLine('# here is lost at the next build, and the parameters belong to the scripts. Each function runs')
[void]$sb.AppendLine('# its script in process, so the script keeps its own $PSScriptRoot and finds lib\ and data\.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('$script:HbCommon = @([System.Management.Automation.PSCmdlet]::CommonParameters) +')
[void]$sb.AppendLine('    @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine(@'
function Get-HostBadgerPath {
<#
.SYNOPSIS
    The folder this module was installed in, where the scripts, lib\, data\ and the examples are.
.DESCRIPTION
    Use it to reach a file of the module from your own script: the collector to copy to a host, the
    example policy, the synthetic fleet the README analyzes.
.PARAMETER ChildPath
    A path inside the module folder. Optional.
.EXAMPLE
    Copy-Item (Get-HostBadgerPath 'Collect-HostSnapshot.ps1') \\deploy\scripts
    Takes the collector out of the module: one self-contained file to run on the hosts.
.EXAMPLE
    Invoke-HostBadger -Snapshot (Get-HostBadgerPath 'examples\fleet')
    Analyzes the synthetic fleet that ships with the module.
#>
    param([string]$ChildPath = '')
    if ($ChildPath) { Join-Path $PSScriptRoot $ChildPath } else { $PSScriptRoot }
}
'@)
[void]$sb.AppendLine('')

$exported = New-Object System.Collections.Generic.List[string]
$aliases = New-Object System.Collections.Generic.List[string]
foreach ($e in $entries) {
    $path = Join-Path $Root $e.Script
    if (-not (Test-Path -LiteralPath $path)) { throw "missing from the repository: $($e.Script)" }
    $parts = Get-HbScriptParts -Path $path -Function $e.Function
    [void]$sb.AppendLine("function $($e.Function) {")
    if ($parts.Help) { [void]$sb.AppendLine($parts.Help) }
    foreach ($a in $parts.Attrs) { [void]$sb.AppendLine((Add-HbIndent $a)) }
    [void]$sb.AppendLine((Add-HbIndent $parts.Param))
    [void]$sb.AppendLine("    `$hbScript = Join-Path `$PSScriptRoot '$($e.Script)'")
    if ($parts.Advanced) {
        [void]$sb.AppendLine('    & $hbScript @PSBoundParameters')
    }
    else {
        # The script is not an advanced one: -Verbose and the rest are not parameters it has, and
        # splatting one would fail. An attribute on one of its parameters can still make this
        # function advanced, so the common parameters are dropped here.
        [void]$sb.AppendLine('    $hbArgs = @{}')
        [void]$sb.AppendLine('    foreach ($k in $PSBoundParameters.Keys) { if ($script:HbCommon -notcontains $k) { $hbArgs[$k] = $PSBoundParameters[$k] } }')
        [void]$sb.AppendLine('    & $hbScript @hbArgs')
    }
    [void]$sb.AppendLine('}')
    [void]$sb.AppendLine('')
    $exported.Add($e.Function)
    if ($e.Alias) {
        [void]$sb.AppendLine("Set-Alias -Name $($e.Alias) -Value $($e.Function)")
        [void]$sb.AppendLine('')
        $aliases.Add($e.Alias)
    }
}
$exported.Add('Get-HostBadgerPath')
$exportLine = "Export-ModuleMember -Function @('" + (($exported | Sort-Object) -join "', '") + "')"
if ($aliases.Count -gt 0) { $exportLine += " -Alias @('" + (($aliases | Sort-Object) -join "', '") + "')" }
[void]$sb.AppendLine($exportLine)

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText((Join-Path $dest "$moduleName.psm1"), $sb.ToString(), $utf8Bom)
$fileList.Add("$moduleName.psm1")

# -- HostBadger.psd1 ---------------------------------------------------------------------------
$changelog = [System.IO.File]::ReadAllText((Join-Path $Root 'CHANGELOG.md'))
$m = [regex]::Match($changelog, "(?ms)^## \[" + [regex]::Escape($version) + "\].*?(?=^## \[)")
if (-not $m.Success) { throw "CHANGELOG.md has no section for $version, so the release notes would be empty" }
$notes = $m.Value.TrimEnd()
if ($notes.Length -gt 3500) {
    $notes = $notes.Substring(0, 3500).TrimEnd() + "`r`n...`r`nFull changelog: $projectUri/blob/main/CHANGELOG.md"
}
$notes = $notes.Replace("'", "''")

$tags = @('Security', 'Hardening', 'Audit', 'Compliance', 'Windows', 'CIS', 'STIG', 'EssentialEight',
    'NIS2', 'Defender', 'BlueTeam', 'IncidentResponse', 'PSEdition_Desktop', 'PSEdition_Core')

# The check count comes from the catalog through COVERAGE.md, never from memory.
$coverage = [System.IO.File]::ReadAllText((Join-Path $Root 'COVERAGE.md'))
if ($coverage -notmatch '(\d+)\s+checks') { throw 'COVERAGE.md does not say how many checks there are' }
$checkCount = $Matches[1]

$psdTemplate = @'
#
# GENERATED by tools\New-HostBadgerModule.ps1. Do not edit: build it again instead.
#
@{
    RootModule           = 'HostBadger.psm1'
    ModuleVersion        = '@VERSION@'
    GUID                 = '@GUID@'
    Author               = 'Gabriele Piccini'
    CompanyName          = 'Gabriele Piccini'
    Copyright            = '(c) 2026 Gabriele Piccini. MIT licence.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    Description          = 'Windows host hardening auditor. Collect once on each host with a read-only snapshot (as SYSTEM through an EDR, an RMM, Intune, a startup script or PowerShell remoting), then analyze anywhere: @CHECKS@ checks plus about 500 DISA STIG registry rules, mapped to MITRE ATT&CK, the CIS Windows benchmarks, the ASD Essential Eight and NIS2 / ACN. One HTML report for the whole fleet, a findings CSV, JSON Lines for a SIEM, and a generated reversible remediation script. Pure PowerShell, Windows PowerShell 5.1 and PowerShell 7, no agent, and no network unless you ask for a catalog download or the optional AI summary. A check whose data could not be collected is listed as not evaluated, never as clean.'

    FunctionsToExport    = @(@FUNCTIONS@)
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @(@ALIASES@)

    FileList             = @(@FILELIST@)

    PrivateData          = @{
        PSData = @{
            Tags         = @(@TAGS@)
            LicenseUri   = '@PROJECT@/blob/main/LICENSE'
            ProjectUri   = '@PROJECT@'
            ReleaseNotes = '@NOTES@'
        }
    }
}
'@

$quoted = {
    param($items, $indent)
    if (@($items).Count -eq 0) { return '' }
    $pad = ' ' * $indent
    "`r`n$pad'" + ($items -join "',`r`n$pad'") + "'`r`n" + (' ' * ($indent - 4))
}

$psd = $psdTemplate.
Replace('@VERSION@', $version).
Replace('@GUID@', $moduleGuid).
Replace('@CHECKS@', $checkCount).
Replace('@FUNCTIONS@', (& $quoted @($exported | Sort-Object) 8)).
Replace('@ALIASES@', (& $quoted @($aliases | Sort-Object) 8)).
Replace('@FILELIST@', (& $quoted @($fileList | Sort-Object) 8)).
Replace('@TAGS@', (& $quoted $tags 16)).
Replace('@PROJECT@', $projectUri).
Replace('@NOTES@', $notes)
[System.IO.File]::WriteAllText((Join-Path $dest "$moduleName.psd1"), $psd, $utf8Bom)

# -- what was built ----------------------------------------------------------------------------
$built = @(Get-ChildItem -LiteralPath $dest -Recurse -File)
$size = ($built | Measure-Object -Property Length -Sum).Sum
Write-Host ("{0} files, {1:N1} MB" -f $built.Count, ($size / 1MB)) -ForegroundColor Green
Write-Host ("exports: " + (@($exported | Sort-Object) -join ', '))
if ($aliases.Count -gt 0) { Write-Host ("alias:   " + ($aliases -join ', ')) }
Write-Host ''
Write-Host 'Next:' -ForegroundColor Cyan
Write-Host ("  Test-ModuleManifest '{0}'" -f (Join-Path $dest "$moduleName.psd1"))
Write-Host ("  Publish-PSResource -Path '{0}' -Repository PSGallery -ApiKey <key>" -f $dest)
