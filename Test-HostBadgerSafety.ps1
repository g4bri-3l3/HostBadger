<#
.SYNOPSIS
    Reads the HostBadger scripts (without running them) and shows everything
    they can do: every command they call, every file they write, every web
    address in them. Fails if anything falls outside the reviewed list.

.DESCRIPTION
    This is for whoever has to approve running Collect-HostSnapshot.ps1 on
    endpoints as SYSTEM. It uses the PowerShell parser, so it sees every
    command that is called, not just the ones a text search would find.

    It fails (exit code 1) when it finds:
      - a command that is not on the reviewed list below, so that a new one
        can't slip in unnoticed;
      - a command that changes the system, such as Set-, New-, Remove-, Add-,
        Enable-, Disable-, Start- or Stop- on Defender, the firewall, services,
        tasks, the registry, accounts, BitLocker or SMB. The only exceptions
        are New-Item, Remove-Item and Set-Content on HostBadger's own files;
      - auditpol with anything other than /get or /backup;
      - secedit with anything other than /export. /configure, /import,
        /analyze, /generaterollback and /validate change or rebuild policy;
      - ADSI or COM used for more than reading (InvokeMember with anything
        other than GetProperty, or a COM object other than
        Microsoft.Update.Session);
      - tricks that hide code at run time: Invoke-Expression, encoded
        commands, Base64, downloads, compiled C#, starting processes, CIM
        method calls;
      - a web address other than the MITRE ATT&CK links in the report and, in
        lib\AI.ps1 only, the Gemini endpoint of the optional AI step;
      - HTTP or socket code outside lib\AI.ps1. The collector and the checks
        never touch the network. Gemini is called only after -SendToAI, from
        HostBadger.ps1, once names have been replaced by tokens;
      - Start-Sleep outside lib\AI.ps1, or Read-Host outside the two entry
        points (HostBadger.ps1 and Start-HostBadger.ps1).

    It also prints the SHA-256 of every script, so you can compare them with a
    release.
.PARAMETER Path
    HostBadger folder. Default: the folder of this script.
.PARAMETER Quiet
    Print only the verdict.
#>
[CmdletBinding()]
param([string]$Path = '', [switch]$Quiet)

$ErrorActionPreference = 'Stop'
if (-not $Path) { $Path = Split-Path -Parent $MyInvocation.MyCommand.Path }

$allowed = [ordered]@{
    'Read host configuration (no write cmdlet in this list)' = @(
        'Get-ItemProperty', 'Get-Item', 'Get-CimInstance', 'Get-MpComputerStatus', 'Get-MpPreference', 'Get-BitLockerVolume',
        'Get-SmbServerConfiguration', 'Get-SmbClientConfiguration', 'Get-NetFirewallProfile', 'Get-NetTCPConnection', 'Get-NetUDPEndpoint',
        'Get-Process', 'Get-LocalUser', 'Get-ScheduledTask', 'Get-Acl', 'Get-WinEvent', 'auditpol.exe', 'secedit.exe')
    'Files: read snapshots, write the snapshot / report' = @('Get-Content', 'Set-Content', 'Export-Csv', 'Import-Csv', 'Get-ChildItem', 'Test-Path', 'Resolve-Path',
        'Join-Path', 'Split-Path', 'New-Item', 'Remove-Item', 'Compress-Archive')
    'Environment' = @('Add-Type', 'Get-Date')
    'Console' = @('Write-Host', 'Write-Warning', 'Out-Null', 'Out-Host')
    'Optional AI step only (lib\AI.ps1 waits between retries; the entry points ask questions)' = @('Start-Sleep', 'Read-Host')
    'Data handling' = @('ConvertTo-Json', 'ConvertFrom-Json', 'Select-Object', 'Where-Object', 'ForEach-Object', 'Sort-Object', 'Group-Object', 'Measure-Object', 'New-Object', 'Add-Member')
}
$allowedSet = @{}; foreach ($k in $allowed.Keys) { foreach ($c in $allowed[$k]) { $allowedSet[$c.ToLower()] = $k } }

$changeVerbs = '^(Set|New|Remove|Add|Enable|Disable|Clear|Start|Stop|Restart|Suspend|Resume|Update|Install|Uninstall|Register|Unregister|Reset|Rename|Move|Grant|Revoke|Lock|Unlock|Invoke)-'
# The only "changing" commands we allow, and why: they touch HostBadger's own files.
$ownFileCommands = @('new-item', 'remove-item', 'set-content', 'new-object', 'add-member', 'add-type')
# Commands that exist only for the optional AI step, and the one file each of them may appear in.
$restrictedCommands = @{ 'start-sleep' = @('lib/AI.ps1'); 'read-host' = @('HostBadger.ps1', 'Start-HostBadger.ps1') }
$bannedCommands = @('Invoke-Expression', 'iex', 'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'curl', 'wget', 'Start-Job',
    'Invoke-CimMethod', 'Invoke-WmiMethod', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-MpPreference', 'Add-MpPreference',
    'reg', 'reg.exe', 'net', 'net.exe', 'sc', 'sc.exe', 'schtasks', 'schtasks.exe', 'Enter-PSSession', 'Invoke-Command', 'New-PSSession')
$bannedText = [ordered]@{
    'Base64 decoding'         = 'FromBase64String'
    'Encoded command'         = '(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}'
    'Download helper'         = '(?i)DownloadString|DownloadFile|Net\.WebClient'
    'Compiled C# at run time' = '(?i)Add-Type\s+-TypeDefinition|Add-Type\s+-MemberDefinition'
    'Hidden window'           = '(?i)-WindowStyle\s+Hidden'
    'Registry write (.NET)'   = '(?i)\.(SetValue|DeleteValue|DeleteSubKey\w*|CreateSubKey)\('
}
$allowedHosts = @('attack.mitre.org')
# The optional AI step is the only code that may reach the network, and only this endpoint.
$aiFile = 'lib/AI.ps1'
$aiHosts = @('generativelanguage.googleapis.com')
$networkText = '(?i)System\.Net\.Http|HttpClient|PostAsync|GetAsync|TcpClient|UdpClient|System\.Net\.Sockets|\[Net\.WebRequest\]|\[System\.Net\.WebRequest\]'

$root = (Resolve-Path -LiteralPath $Path).Path
# What HostBadger runs: the scripts in the folder itself and in lib\. A script in some other
# subfolder (another tool copied next to it, a leftover) is never loaded by HostBadger, so it is
# listed as "not reviewed" instead of being mixed into the verdict.
$files = @(Get-ChildItem -LiteralPath $root -File -Filter *.ps1 | Where-Object { $_.Name -ne 'Test-HostBadgerSafety.ps1' }) +
@(Get-ChildItem -LiteralPath (Join-Path $root 'lib') -File -Filter *.ps1 -ErrorAction SilentlyContinue)
$reviewedPaths = @{}; foreach ($f in $files) { $reviewedPaths[$f.FullName] = $true }
$outside = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter *.ps1 | Where-Object { -not $reviewedPaths.ContainsKey($_.FullName) -and $_.FullName -notmatch '\\(tests|examples)\\' -and $_.Name -ne 'Test-HostBadgerSafety.ps1' })
$problems = New-Object System.Collections.Generic.List[string]
$used = @{}
$writes = New-Object System.Collections.Generic.List[string]

$internal = @{}
$asts = @{}
foreach ($f in $files) {
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
    if ($errs.Count) { $problems.Add("$($f.Name): does not parse ($($errs[0].Message))") }
    $asts[$f.FullName] = $ast
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $internal[$fn.Name.ToLower()] = $true }
}

foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
    $text = [System.IO.File]::ReadAllText($f.FullName)
    foreach ($k in $bannedText.Keys) { if ($text -match $bannedText[$k]) { $problems.Add("${rel}: $k") } }
    $codeOnly = [regex]::Replace($text, '(?s)<#.*?#>', '')
    $codeOnly = [regex]::Replace($codeOnly, '(?m)^\s*#.*$', '')
    $relUnix = $rel.Replace('\', '/')
    foreach ($m in [regex]::Matches($codeOnly, 'https?://([A-Za-z0-9.\-]+)')) {
        $wh = $m.Groups[1].Value.ToLower()
        if ($allowedHosts -contains $wh) { continue }
        if ($relUnix -eq $aiFile -and $aiHosts -contains $wh) { continue }
        $problems.Add("${rel}: unexpected web address $wh")
    }
    if ($relUnix -ne $aiFile -and $codeOnly -match $networkText) { $problems.Add("${rel}: network code outside $aiFile") }
    foreach ($m in [regex]::Matches($codeOnly, "InvokeMember\(\s*'([^']+)'\s*,\s*'([^']+)'")) {
        if ($m.Groups[2].Value -ne 'GetProperty') { $problems.Add("${rel}: ADSI/COM InvokeMember '$($m.Groups[1].Value)' with '$($m.Groups[2].Value)' (only GetProperty is read-only)") }
    }
    foreach ($m in [regex]::Matches($codeOnly, "\.Invoke\(\s*'([^']+)'")) {
        if ($m.Groups[1].Value -ne 'Members') { $problems.Add("${rel}: ADSI method '$($m.Groups[1].Value)' (only Members is allowed)") }
    }
    foreach ($m in [regex]::Matches($codeOnly, "(?i)-ComObject\s+'?""?([\w\.]+)")) {
        if ($m.Groups[1].Value -ne 'Microsoft.Update.Session') { $problems.Add("${rel}: COM object $($m.Groups[1].Value)") }
    }

    foreach ($c in $asts[$f.FullName].FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        if (-not $name) { continue }
        $lc = $name.ToLower()
        if ($internal.ContainsKey($lc)) { continue }
        if (-not $used.ContainsKey($name)) { $used[$name] = New-Object System.Collections.Generic.List[string] }
        if (-not $used[$name].Contains($rel)) { $used[$name].Add($rel) }
        $line = $c.Extent.StartLineNumber
        if ($restrictedCommands.ContainsKey($lc)) {
            if ($restrictedCommands[$lc] -notcontains $relUnix) { $problems.Add("${rel}:${line}: $name is only allowed in $($restrictedCommands[$lc] -join ', ')") }
        }
        elseif ($bannedCommands -contains $lc) { $problems.Add("${rel}:${line}: $name is not allowed") }
        elseif ($name -match $changeVerbs -and $ownFileCommands -notcontains $lc) { $problems.Add("${rel}:${line}: $name changes the system") }
        elseif (-not $allowedSet.ContainsKey($lc)) { $problems.Add("${rel}:${line}: $name is not on the reviewed list") }
        if ($lc -eq 'secedit.exe') {
            $argText = ($c.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join ' '
            if ($argText -notmatch '^/export\b' -or $argText -match '(?i)/(configure|import|analyze|generaterollback|validate|db)\b') { $problems.Add("${rel}:${line}: secedit $argText (only /export reads the policy)") }
        }
        if ($lc -eq 'auditpol.exe') {
            $argText = ($c.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join ' '
            if ($argText -notmatch '^/(get|backup)\b') { $problems.Add("${rel}:${line}: auditpol $argText (only /get and /backup read the policy)") }
        }
        if ($lc -in 'set-content', 'export-csv', 'new-item', 'remove-item', 'compress-archive') { $writes.Add("${rel}:${line}: $($c.Extent.Text.Split("`n")[0].Trim())") }
    }
    foreach ($m in [regex]::Matches($text, '\[(System\.)?IO\.File\]::(Write\w+|Delete|Move|Copy)')) {
        $writes.Add("${rel}:$(($text.Substring(0, $m.Index) -split "`n").Count): $($m.Value)")
    }
}

if (-not $Quiet) {
    Write-Host "HostBadger safety review of $root" -ForegroundColor Cyan
    Write-Host "$($files.Count) files read, nothing executed.`n"
    Write-Host 'External commands used, by purpose:' -ForegroundColor Cyan
    foreach ($k in $allowed.Keys) {
        $here = @($allowed[$k] | Where-Object { $used.ContainsKey($_) })
        if ($here.Count) { Write-Host "  $k"; foreach ($c in $here) { Write-Host ("    {0,-28} {1}" -f $c, ($used[$c] -join ', ')) -ForegroundColor DarkGray } }
    }
    Write-Host "`nWhere it writes (all local files: snapshot, its zip, the temporary audit policy CSV, the report):" -ForegroundColor Cyan
    foreach ($w in $writes) { Write-Host "  $w" -ForegroundColor DarkGray }
    Write-Host "`nSHA-256 of every script:" -ForegroundColor Cyan
    foreach ($f in @($files) + @(Get-Item -LiteralPath (Join-Path $root 'Test-HostBadgerSafety.ps1') -ErrorAction SilentlyContinue) | Sort-Object FullName) {
        Write-Host "  $((Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLower())  $($f.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/'))" -ForegroundColor DarkGray
    }
    Write-Host ''
}
if ($outside.Count -gt 0) {
    $folders = @($outside | ForEach-Object { $_.DirectoryName.Substring($root.Length).TrimStart('\').Split('\')[0] } | Select-Object -Unique)
    Write-Host "Not reviewed: $($outside.Count) script(s) in $($folders -join ', '). HostBadger never loads them; the verdict below covers the scripts it runs." -ForegroundColor Yellow
}
if ($problems.Count) {
    Write-Host "FAILED: $($problems.Count) problem(s)" -ForegroundColor Red
    foreach ($p in $problems) { Write-Host "  $p" -ForegroundColor Red }
    exit 1
}
Write-Host 'PASSED: read-only commands only, no system change, no hidden code; network only in lib/AI.ps1 (Gemini, after -SendToAI).' -ForegroundColor Green
exit 0
