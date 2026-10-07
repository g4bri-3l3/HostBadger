# Shared helpers: dates, loading snapshots, and the Windows lifecycle table.

$script:SeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }

# --------------------------------------------------------------------------
# Dates are ISO 8601 in UTC. PowerShell 7 parses them into [datetime] and 5.1 leaves strings, and
# both work. Ages are counted at the time of collection ($script:RefDate), never today, so the same
# snapshot always gives the same findings.
# --------------------------------------------------------------------------
function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
    }
    catch { return $null }
}

function Get-AgeDays {
    param($Value)
    $d = ConvertTo-UtcDate $Value
    if ($null -eq $d) { return $null }
    return [int][Math]::Floor(($script:RefDate - $d).TotalDays)
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

# --------------------------------------------------------------------------
# Loading snapshots: files, zips (read in memory, nothing is extracted) and folders (every
# hostsnapshot_*.json and .zip in them, searched recursively).
# --------------------------------------------------------------------------
function Get-SnapshotFiles {
    param([string[]]$Paths)
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { throw "Not found: $p" }
        $item = Get-Item -LiteralPath $p
        if ($item.PSIsContainer) {
            foreach ($f in @(Get-ChildItem -LiteralPath $item.FullName -Recurse -File | Where-Object { $_.Name -match '^hostsnapshot_.*\.(json|zip)$' } | Sort-Object FullName)) {
                $files.Add($f.FullName)
            }
        }
        else { $files.Add($item.FullName) }
    }
    return $files.ToArray()
}

function Read-SnapshotText {
    param([string]$Path)
    if ($Path -match '(?i)\.zip$') {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $entry = @($zip.Entries | Where-Object { $_.Name -match '(?i)^hostsnapshot_.*\.json$' }) | Select-Object -First 1
            if (-not $entry) { throw "no hostsnapshot_*.json inside $Path" }
            $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
            try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        finally { $zip.Dispose() }
    }
    return [System.IO.File]::ReadAllText($Path)
}

function Import-HostSnapshot {
    param([string]$Path)
    $raw = (Read-SnapshotText $Path).TrimStart([char]0xFEFF, ' ', "`t", "`r", "`n")
    if (-not $raw.StartsWith('{')) { throw "$Path is not a HostBadger snapshot (not JSON)." }
    # Older collectors on PS 5.1 wrote an empty list as {}.
    $raw = [regex]::Replace($raw, '(?<=[^\\]"):\s*\{\s*\}', ': []')
    $snap = $raw | ConvertFrom-Json
    if (-not $snap.meta -or "$($snap.meta.tool)" -ne 'HostBadger') { throw "$Path is not a HostBadger snapshot (missing meta.tool)." }
    $snap | Add-Member -NotePropertyName _path -NotePropertyValue $Path -Force
    return $snap
}

function Get-SnapshotHostName {
    param($Snapshot)
    if ($Snapshot.host -and $Snapshot.host.name) { return "$($Snapshot.host.name)" }
    return "$($Snapshot.meta.computerName)"
}

function Get-SnapshotRole {
    # workstation, server or dc; unknown when the host section failed.
    param($Snapshot)
    if ($Snapshot.host -and $Snapshot.host.role) { return "$($Snapshot.host.role)" }
    return 'unknown'
}

# --------------------------------------------------------------------------
# Windows lifecycle: the end of servicing per build, from Microsoft's lifecycle pages. Check a date
# before relying on it, and extend the table as new releases ship. Editions: 'consumer' is Home, Pro
# and Pro for Workstations; 'enterprise' is Enterprise, Education and IoT Enterprise; 'ltsc' is the
# Long-Term Servicing editions (EditionID ending in S).
# --------------------------------------------------------------------------
$script:WindowsLifecycle = @(
    # Windows 10
    @{ Build = 19045; Kind = 'client'; Name = 'Windows 10 22H2'; consumer = '2025-10-14'; enterprise = '2025-10-14' }
    @{ Build = 19044; Kind = 'client'; Name = 'Windows 10 21H2'; consumer = '2023-06-13'; enterprise = '2024-06-11'; ltsc = '2027-01-12' }
    @{ Build = 19043; Kind = 'client'; Name = 'Windows 10 21H1'; consumer = '2022-12-13'; enterprise = '2022-12-13' }
    @{ Build = 17763; Kind = 'client'; Name = 'Windows 10 1809'; consumer = '2020-11-10'; enterprise = '2021-05-11'; ltsc = '2029-01-09' }
    @{ Build = 14393; Kind = 'client'; Name = 'Windows 10 1607'; consumer = '2018-04-10'; enterprise = '2019-04-09'; ltsc = '2026-10-13' }
    @{ Build = 10240; Kind = 'client'; Name = 'Windows 10 1507'; consumer = '2017-05-09'; enterprise = '2017-05-09'; ltsc = '2025-10-14' }
    # Windows 11
    @{ Build = 22000; Kind = 'client'; Name = 'Windows 11 21H2'; consumer = '2023-10-10'; enterprise = '2024-10-08' }
    @{ Build = 22621; Kind = 'client'; Name = 'Windows 11 22H2'; consumer = '2024-10-08'; enterprise = '2025-10-14' }
    @{ Build = 22631; Kind = 'client'; Name = 'Windows 11 23H2'; consumer = '2025-11-11'; enterprise = '2026-11-10' }
    @{ Build = 26100; Kind = 'client'; Name = 'Windows 11 24H2'; consumer = '2026-10-13'; enterprise = '2027-10-12'; ltsc = '2029-10-09' }
    @{ Build = 26200; Kind = 'client'; Name = 'Windows 11 25H2'; consumer = '2027-10-12'; enterprise = '2028-10-10' }
    # Windows Server (extended support end)
    @{ Build = 9200; Kind = 'server'; Name = 'Windows Server 2012'; server = '2023-10-10' }
    @{ Build = 9600; Kind = 'server'; Name = 'Windows Server 2012 R2'; server = '2023-10-10' }
    @{ Build = 14393; Kind = 'server'; Name = 'Windows Server 2016'; server = '2027-01-12' }
    @{ Build = 17763; Kind = 'server'; Name = 'Windows Server 2019'; server = '2029-01-09' }
    @{ Build = 20348; Kind = 'server'; Name = 'Windows Server 2022'; server = '2031-10-14' }
    @{ Build = 26100; Kind = 'server'; Name = 'Windows Server 2025'; server = '2034-10-10' }
)

function Get-OsSupport {
    # Returns @{ Name; EndUtc; Known } for the OS of the host. Builds below 9200 (Windows 7, Server
    # 2008 R2 and older) are long out of support.
    param($Os)
    $build = [int]$Os.build
    $isServer = [int]$Os.productType -ne 1
    $kind = if ($isServer) { 'server' } else { 'client' }
    if ($build -gt 0 -and $build -lt 9200) {
        return [PSCustomObject]@{ Name = "$($Os.caption) (build $build)"; EndUtc = (ConvertTo-UtcDate '2020-01-14'); Known = $true; Edition = '' }
    }
    $row = $script:WindowsLifecycle | Where-Object { $_.Build -eq $build -and $_.Kind -eq $kind } | Select-Object -First 1
    if (-not $row) { return [PSCustomObject]@{ Name = "$($Os.caption) (build $build)"; EndUtc = $null; Known = $false; Edition = '' } }
    $ed = "$($Os.editionId)"
    $edition = if ($isServer) { 'server' }
    elseif ($ed -match '(?i)S$' -and $ed -match '(?i)^(Enterprise|IoTEnterprise)') { 'ltsc' }
    elseif ($ed -match '(?i)^(Enterprise|Education|IoTEnterprise)') { 'enterprise' }
    else { 'consumer' }
    $end = $row[$edition]
    if (-not $end -and $edition -eq 'ltsc') { $edition = 'enterprise'; $end = $row['enterprise'] }
    $label = if ($edition -eq 'ltsc') { "$($row.Name) LTSC" } elseif ($edition -eq 'enterprise') { "$($row.Name) Enterprise/Education" } elseif ($edition -eq 'consumer') { "$($row.Name) Home/Pro" } else { $row.Name }
    return [PSCustomObject]@{ Name = $label; EndUtc = (ConvertTo-UtcDate $end); Known = $true; Edition = $edition }
}
