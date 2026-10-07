# Fix scripts, generated from the findings. They come in two forms: a plain PowerShell snippet under
# each check in the report, and, if you ask for it, one file per host. What we promise, and why it
# is safe to offer: We only offer fixes that are one setting, set to the value the benchmark or
# Microsoft expects. They can be undone, they leave no choice to the organization (no banner text,
# no list of allowed admins), and they don't depend on hardware or firewall rules. A generated
# script changes nothing unless you set $Apply (the per-host file: run it with -Apply). The per-host
# file also records the old value of every setting in a rollback file, which -Restore puts back, and
# it refuses to run on a computer whose name is not the one in the snapshot. HostBadger never runs
# any of this. We only write text. Fixes that need a decision (banner text, allowed administrators,
# password policy, services to disable, BitLocker, Credential Guard, LAPS, user rights...) are left
# out on purpose.

function ConvertTo-PsLiteral {
    param([string]$Text)
    return "'" + ($Text -replace "'", "''") + "'"
}

# Check types that have a script, with a short label for the report.
$script:FixTypes = @{}
foreach ($k in @(
        'wdigest_cleartext', 'lm_hash_stored', 'ntlm_weak_lmcompat', 'anonymous_sam_enum', 'anonymous_shares_enum', 'everyone_includes_anonymous',
        'blank_password_network_logon', 'force_guest_sharing_model', 'smb_plaintext_password', 'smb_insecure_guest_auth', 'ldap_client_signing_off',
        'ntlm_min_session_security_weak', 'lsa_weak_auth_options', 'null_session_access', 'secure_channel_unprotected', 'winrm_insecure_auth',
        'smb1_client_driver_enabled', 'smb1_server_enabled', 'smb_server_signing_not_required', 'smb_client_signing_not_required', 'llmnr_enabled',
        'autoplay_enabled', 'interactive_logon_gaps', 'inactivity_lock_missing', 'uac_hardening_gaps', 'uac_disabled', 'uac_admin_no_prompt',
        'remote_uac_token_filter_off', 'always_install_elevated', 'wu_auto_updates_disabled', 'smartscreen_off', 'event_logs_small', 'security_log_small',
        'powershell_scriptblock_logging_off', 'powershell_transcription_off', 'cmdline_audit_off', 'sehop_disabled', 'safe_dll_search_off',
        'ip_stack_hardening_gaps', 'rdp_policy_gaps', 'rdp_nla_disabled', 'cached_logons_high', 'guest_enabled', 'defender_realtime_off',
        'defender_pua_off', 'defender_network_protection_off', 'firewall_profile_disabled', 'firewall_default_inbound_allow', 'firewall_drop_logging_off',
        'powershell_v2_enabled', 'spooler_on_dc')) { $script:FixTypes[$k] = $true }

# The fixes for one finding, as data. Kind is reg, smb, mp, fw, feature, user or service. Two
# renderings come from it: the lines of the per-host script (with rollback) and the plain PowerShell
# snippets under each check in the report.
function Get-RemediationActions {
    param($Finding, [string]$Role, $Config)
    $t = "$($Finding.Type)"
    $o = "$($Finding.Object)"
    $why = "$($Finding.Title)" + $(if ($Finding.Cis) { " - CIS $($Finding.Cis)" } else { '' })
    $out = New-Object System.Collections.Generic.List[object]
    $reg = {
        param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [switch]$Restart)
        $out.Add(@{ Kind = 'reg'; Id = $t; Why = $why; Path = $Path; Name = $Name; Value = $Value; Type = $Type; Restart = [bool]$Restart })
    }
    $smb = { param([string]$Side, [string]$Setting, [bool]$Value) $out.Add(@{ Kind = 'smb'; Id = $t; Why = $why; Side = $Side; Setting = $Setting; Value = $Value }) }
    $mp = { param([string]$Setting, $Value) $out.Add(@{ Kind = 'mp'; Id = $t; Why = $why; Setting = $Setting; Value = $Value }) }
    $fw = { param([string]$ProfileName, [string]$Setting, [string]$Value) $out.Add(@{ Kind = 'fw'; Id = $t; Why = $why; ProfileName = $ProfileName; Setting = $Setting; Value = $Value }) }
    $feat = { param([string]$Name) $out.Add(@{ Kind = 'feature'; Id = $t; Why = $why; Name = $Name }) }
    $usr = { param([string]$Name) $out.Add(@{ Kind = 'user'; Id = $t; Why = $why; Name = $Name }) }
    $svc = { param([string]$Name) $out.Add(@{ Kind = 'service'; Id = $t; Why = $why; Name = $Name }) }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $ts = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $wrmC = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    $wrmS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $evt = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog'
    $psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $tcp4 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $tcp6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    switch ($t) {
        'wdigest_cleartext' { & $reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }
        'lm_hash_stored' { & $reg $lsa 'NoLMHash' 1 }
        'ntlm_weak_lmcompat' { & $reg $lsa 'LmCompatibilityLevel' 5 }
        'anonymous_sam_enum' { & $reg $lsa 'RestrictAnonymousSAM' 1 }
        'anonymous_shares_enum' { & $reg $lsa 'RestrictAnonymous' 1 }
        'everyone_includes_anonymous' { & $reg $lsa 'EveryoneIncludesAnonymous' 0 }
        'blank_password_network_logon' { & $reg $lsa 'LimitBlankPasswordUse' 1 }
        'force_guest_sharing_model' { & $reg $lsa 'ForceGuest' 0 }
        'smb_plaintext_password' { & $reg $wks 'EnablePlainTextPassword' 0 }
        'smb_insecure_guest_auth' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0 }
        'ldap_client_signing_off' { & $reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 }
        'ntlm_min_session_security_weak' {
            if ($o -eq 'NTLM client') { & $reg "$lsa\MSV1_0" 'NTLMMinClientSec' 537395200 }
            elseif ($o -eq 'NTLM server') { & $reg "$lsa\MSV1_0" 'NTLMMinServerSec' 537395200 }
        }
        'lsa_weak_auth_options' {
            if ($o -eq 'LocalSystem NULL session fallback') { & $reg "$lsa\MSV1_0" 'AllowNullSessionFallback' 0 }
            elseif ($o -eq 'PKU2U online identities') { & $reg "$lsa\pku2u" 'AllowOnlineID' 0 }
        }
        'null_session_access' {
            if ($o -eq 'NullSessionShares') { & $reg $srv 'NullSessionShares' $null 'MultiString' }
            elseif ($o -eq 'NullSessionPipes') { & $reg $srv 'NullSessionPipes' $null 'MultiString' }
            elseif ($o -eq 'RestrictNullSessAccess') { & $reg $srv 'RestrictNullSessAccess' 1 }
        }
        'secure_channel_unprotected' {
            $map = @{ 'Netlogon: RequireSignOrSeal' = @('RequireSignOrSeal', 1); 'Netlogon: SealSecureChannel' = @('SealSecureChannel', 1); 'Netlogon: SignSecureChannel' = @('SignSecureChannel', 1)
                'Netlogon: RequireStrongKey' = @('RequireStrongKey', 1); 'Netlogon: DisablePasswordChange' = @('DisablePasswordChange', 0); 'Netlogon: MaximumPasswordAge' = @('MaximumPasswordAge', 30) }
            if ($map.ContainsKey($o)) { & $reg $nl $map[$o][0] $map[$o][1] }
        }
        'winrm_insecure_auth' {
            $map = @{ 'WinRM client: Basic authentication' = @($wrmC, 'AllowBasic'); 'WinRM client: unencrypted traffic' = @($wrmC, 'AllowUnencryptedTraffic')
                'WinRM client: Digest authentication' = @($wrmC, 'AllowDigest'); 'WinRM service: Basic authentication' = @($wrmS, 'AllowBasic')
                'WinRM service: unencrypted traffic' = @($wrmS, 'AllowUnencryptedTraffic') }
            if ($map.ContainsKey($o)) { & $reg $map[$o][0] $map[$o][1] 0 }
        }
        'smb1_client_driver_enabled' { & $reg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 -Restart }
        'smb1_server_enabled' { & $smb 'Server' 'EnableSMB1Protocol' $false }
        'smb_server_signing_not_required' { & $smb 'Server' 'RequireSecuritySignature' $true }
        'smb_client_signing_not_required' { & $smb 'Client' 'RequireSecuritySignature' $true }
        'llmnr_enabled' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
        'autoplay_enabled' {
            if ($o -eq 'NoDriveTypeAutoRun') { & $reg $exp 'NoDriveTypeAutoRun' 255 }
            elseif ($o -eq 'NoAutorun') { & $reg $exp 'NoAutorun' 1 }
            elseif ($o -eq 'NoAutoplayfornonVolume') { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 }
        }
        'interactive_logon_gaps' {
            if ($o -eq 'Last signed-in user shown') { & $reg $sys 'DontDisplayLastUserName' 1 }
            elseif ($o -eq 'CTRL+ALT+DEL not required') { & $reg $sys 'DisableCAD' 0 }
        }
        'inactivity_lock_missing' { & $reg $sys 'InactivityTimeoutSecs' 900 }
        'uac_hardening_gaps' {
            $map = @{ 'Admin Approval Mode for the built-in Administrator' = 'FilterAdministratorToken'; 'Installer detection' = 'EnableInstallerDetection'
                'Secure UIAccess paths' = 'EnableSecureUIAPaths'; 'Secure desktop for prompts' = 'PromptOnSecureDesktop'; 'File and registry virtualization' = 'EnableVirtualization' }
            if ($map.ContainsKey($o)) { & $reg $sys $map[$o] 1 }
        }
        'uac_disabled' { & $reg $sys 'EnableLUA' 1 -Restart }
        'uac_admin_no_prompt' { & $reg $sys 'ConsentPromptBehaviorAdmin' 2 }
        'remote_uac_token_filter_off' { & $reg $sys 'LocalAccountTokenFilterPolicy' 0 }
        'always_install_elevated' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 }
        'wu_auto_updates_disabled' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 0 }
        'smartscreen_off' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1 }
        'event_logs_small' {
            if ($o -eq 'Application log') { & $reg "$evt\Application" 'MaxSize' 32768 }
            elseif ($o -eq 'System log') { & $reg "$evt\System" 'MaxSize' 32768 }
        }
        'security_log_small' { & $reg "$evt\Security" 'MaxSize' ([int64]$Config.MinSecurityLogKB) }
        'powershell_scriptblock_logging_off' { & $reg "$psPol\ScriptBlockLogging" 'EnableScriptBlockLogging' 1 }
        'powershell_transcription_off' { & $reg "$psPol\Transcription" 'EnableTranscripting' 1 }
        'cmdline_audit_off' { & $reg "$sys\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1 }
        'sehop_disabled' { & $reg "$sm\kernel" 'DisableExceptionChainValidation' 0 -Restart }
        'safe_dll_search_off' { & $reg $sm 'SafeDllSearchMode' 1 -Restart }
        'ip_stack_hardening_gaps' {
            if ($o -eq 'IPv4 source routing') { & $reg $tcp4 'DisableIPSourceRouting' 2 }
            elseif ($o -eq 'IPv6 source routing') { & $reg $tcp6 'DisableIPSourceRouting' 2 }
            elseif ($o -eq 'ICMP redirects') { & $reg $tcp4 'EnableICMPRedirect' 0 }
        }
        'rdp_policy_gaps' {
            if ($o -eq 'Security layer') { & $reg $ts 'SecurityLayer' 2 }
            elseif ($o -eq 'Encryption level') { & $reg $ts 'MinEncryptionLevel' 3 }
            elseif ($o -eq 'Password prompt') { & $reg $ts 'fPromptForPassword' 1 }
            elseif ($o -eq 'Secure RPC') { & $reg $ts 'fEncryptRPCTraffic' 1 }
            elseif ($o -eq 'Drive redirection') { & $reg $ts 'fDisableCdm' 1 }
        }
        'rdp_nla_disabled' { & $reg $ts 'UserAuthentication' 1 }
        'cached_logons_high' {
            $limit = if ($Role -eq 'server') { [int]$Config.MaxCachedLogonsServer } else { [int]$Config.MaxCachedLogonsWorkstation }
            & $reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' "$limit" 'String'
        }
        'guest_enabled' {
            # The account name comes from the snapshot: only plain names go into a script.
            if ($o -match '^account: ([\w .\-$]+)$') { & $usr $Matches[1] }
        }
        'defender_realtime_off' { & $mp 'DisableRealtimeMonitoring' $false }
        'defender_pua_off' { & $mp 'PUAProtection' 1 }
        'defender_network_protection_off' { & $mp 'EnableNetworkProtection' 1 }
        'firewall_profile_disabled' {
            if ($o -match '^profile: (Domain|Private|Public)$') { & $fw $Matches[1] 'Enabled' 'True' }
        }
        'firewall_default_inbound_allow' {
            if ($o -match '^profile: (Domain|Private|Public)$') { & $fw $Matches[1] 'DefaultInboundAction' 'Block' }
        }
        'firewall_drop_logging_off' {
            # "Profiles not logging dropped packets: Domain, Private, Public."
            if ("$($Finding.Detail)" -match ':\s*([A-Za-z, ]+)\.?\s*$') {
                foreach ($pn in @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -in 'Domain', 'Private', 'Public' })) { & $fw $pn 'LogBlocked' 'True' }
            }
        }
        'powershell_v2_enabled' { & $feat 'MicrosoftWindowsPowerShellV2Root' }
        'spooler_on_dc' { & $svc 'Spooler' }
    }
    return $out.ToArray()
}

# One action as a line of the per-host script, which defines the helper functions it calls.
function ConvertTo-EngineLine {
    param($A)
    $id = ConvertTo-PsLiteral "$($A.Id)"
    $why = ConvertTo-PsLiteral "$($A.Why)"
    switch ($A.Kind) {
        'reg' {
            $v = if ($A.Type -eq 'DWord') { [string][int64]$A.Value } elseif ($A.Type -eq 'MultiString') { '([string[]]@())' } else { ConvertTo-PsLiteral "$($A.Value)" }
            return "Set-HbRegistry -Id $id -Path $(ConvertTo-PsLiteral $A.Path) -Name $(ConvertTo-PsLiteral $A.Name) -Value $v -Type $(ConvertTo-PsLiteral $A.Type) -Why $why$(if ($A.Restart) { ' -Restart' })"
        }
        'smb' { return "Set-HbSmb -Id $id -Side $(ConvertTo-PsLiteral $A.Side) -Setting $(ConvertTo-PsLiteral $A.Setting) -Value $(if ($A.Value) { '$true' } else { '$false' }) -Why $why" }
        'mp' {
            $v = if ($A.Value -is [bool]) { if ($A.Value) { '$true' } else { '$false' } } else { "$($A.Value)" }
            return "Set-HbMpPreference -Id $id -Setting $(ConvertTo-PsLiteral $A.Setting) -Value $v -Why $why"
        }
        'fw' { return "Set-HbFirewall -Id $id -ProfileName $(ConvertTo-PsLiteral $A.ProfileName) -Setting $(ConvertTo-PsLiteral $A.Setting) -Value $(ConvertTo-PsLiteral $A.Value) -Why $why" }
        'feature' { return "Set-HbFeature -Id $id -Name $(ConvertTo-PsLiteral $A.Name) -Why $why" }
        'user' { return "Set-HbLocalUser -Id $id -Name $(ConvertTo-PsLiteral $A.Name) -Enabled `$false -Why $why" }
        'service' { return "Set-HbService -Id $id -Name $(ConvertTo-PsLiteral $A.Name) -Why $why" }
    }
}

# Plain PowerShell for a set of actions, to read and paste. It shows "old -> new" and changes
# nothing until $Apply is set to $true. There is one block per kind of change.
function ConvertTo-FixSnippet {
    param($Actions)
    $blocks = New-Object System.Collections.Generic.List[string]
    $head = { param([string]$Comment) "# $Comment`n`$Apply = `$false   # set to `$true to apply; with `$false it only shows what would change" }
    $regs = @($Actions | Where-Object { $_.Kind -eq 'reg' })
    if ($regs.Count -gt 0) {
        $rows = @($regs | ForEach-Object {
                $v = if ($_.Type -eq 'DWord') { [string][int64]$_.Value } elseif ($_.Type -eq 'MultiString') { '([string[]]@())' } else { ConvertTo-PsLiteral "$($_.Value)" }
                "    @{ Path = $(ConvertTo-PsLiteral $_.Path); Name = $(ConvertTo-PsLiteral $_.Name); Value = $v; Type = $(ConvertTo-PsLiteral $_.Type) }"
            })
        $restart = @($regs | Where-Object { $_.Restart } | ForEach-Object { $_.Name })
        $lines = @(
            (& $head 'Registry values. Windows PowerShell 5.1, elevated.'),
            '$changes = @(', ($rows -join "`n"), ')',
            'foreach ($c in $changes) {',
            '    $key = Get-Item -LiteralPath $c.Path -ErrorAction SilentlyContinue',
            '    $old = if ($key -and ($key.GetValueNames() -contains $c.Name)) { $key.GetValue($c.Name) } else { ''(not set)'' }',
            '    ''{0}\{1}: {2} -> {3}'' -f $c.Path, $c.Name, $old, $(if ($c.Type -eq ''MultiString'') { ''(empty)'' } else { $c.Value })',
            '    if ($Apply) {',
            '        if (-not $key) { New-Item -Path $c.Path -Force | Out-Null }',
            '        Set-ItemProperty -LiteralPath $c.Path -Name $c.Name -Value $c.Value -Type $c.Type',
            '    }',
            '}',
            '# Undo: set each value back to the "old" printed above, or Remove-ItemProperty it if it was (not set).')
        if ($restart.Count -gt 0) { $lines += "# A restart is needed for: $($restart -join ', ')." }
        $blocks.Add($lines -join "`n")
    }
    $smbs = @($Actions | Where-Object { $_.Kind -eq 'smb' })
    if ($smbs.Count -gt 0) {
        $rows = @($smbs | ForEach-Object { "    @{ Side = $(ConvertTo-PsLiteral $_.Side); Setting = $(ConvertTo-PsLiteral $_.Setting); Value = $(if ($_.Value) { '$true' } else { '$false' }) }" })
        $blocks.Add((@(
                    (& $head 'SMB. Windows PowerShell 5.1, elevated.'),
                    'foreach ($c in @(', ($rows -join "`n"), ')) {',
                    '    $cfg = if ($c.Side -eq ''Server'') { Get-SmbServerConfiguration } else { Get-SmbClientConfiguration }',
                    '    ''SMB {0} {1}: {2} -> {3}'' -f $c.Side, $c.Setting, $cfg.($c.Setting), $c.Value',
                    '    if ($Apply) {',
                    '        $p = @{ $c.Setting = $c.Value; Force = $true; Confirm = $false }',
                    '        if ($c.Side -eq ''Server'') { Set-SmbServerConfiguration @p } else { Set-SmbClientConfiguration @p }',
                    '    }',
                    '}',
                    '# Undo: run it again with the value printed as "old".') -join "`n"))
    }
    $mps = @($Actions | Where-Object { $_.Kind -eq 'mp' })
    if ($mps.Count -gt 0) {
        $rows = @($mps | ForEach-Object { "    @{ Setting = $(ConvertTo-PsLiteral $_.Setting); Value = $(if ($_.Value -is [bool]) { if ($_.Value) { '$true' } else { '$false' } } else { "$($_.Value)" }) }" })
        $blocks.Add((@(
                    (& $head 'Microsoft Defender. Windows PowerShell 5.1, elevated (tamper protection or a policy can refuse the change).'),
                    'foreach ($c in @(', ($rows -join "`n"), ')) {',
                    '    ''Defender {0}: {1} -> {2}'' -f $c.Setting, (Get-MpPreference).($c.Setting), $c.Value',
                    '    if ($Apply) { $p = @{ $c.Setting = $c.Value }; Set-MpPreference @p }',
                    '}',
                    '# Undo: run it again with the value printed as "old".') -join "`n"))
    }
    $fws = @($Actions | Where-Object { $_.Kind -eq 'fw' })
    if ($fws.Count -gt 0) {
        $rows = @($fws | ForEach-Object { "    @{ ProfileName = $(ConvertTo-PsLiteral $_.ProfileName); Setting = $(ConvertTo-PsLiteral $_.Setting); Value = $(ConvertTo-PsLiteral $_.Value) }" })
        $blocks.Add((@(
                    (& $head 'Windows Firewall profile. Windows PowerShell 5.1, elevated (Group Policy can set it back).'),
                    'foreach ($c in @(', ($rows -join "`n"), ')) {',
                    '    ''Firewall {0} {1}: {2} -> {3}'' -f $c.ProfileName, $c.Setting, (Get-NetFirewallProfile -Name $c.ProfileName).($c.Setting), $c.Value',
                    '    if ($Apply) { $p = @{ Name = $c.ProfileName; $c.Setting = $c.Value }; Set-NetFirewallProfile @p }',
                    '}',
                    '# Undo: run it again with the value printed as "old".') -join "`n"))
    }
    foreach ($a in @($Actions | Where-Object { $_.Kind -eq 'feature' })) {
        $blocks.Add((@(
                    (& $head 'Optional Windows feature. Windows PowerShell 5.1, elevated.'),
                    "`$name = $(ConvertTo-PsLiteral $a.Name)",
                    '''Feature {0}: {1} -> Disabled'' -f $name, (Get-WindowsOptionalFeature -Online -FeatureName $name).State',
                    'if ($Apply) { Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart }',
                    '# Undo: Enable-WindowsOptionalFeature -Online -FeatureName $name') -join "`n"))
    }
    foreach ($a in @($Actions | Where-Object { $_.Kind -eq 'user' })) {
        $blocks.Add((@(
                    (& $head 'Local account. Windows PowerShell 5.1, elevated.'),
                    "`$name = $(ConvertTo-PsLiteral $a.Name)",
                    '''Account {0} Enabled: {1} -> False'' -f $name, (Get-LocalUser -Name $name).Enabled',
                    'if ($Apply) { Disable-LocalUser -Name $name }',
                    '# Undo: Enable-LocalUser -Name $name') -join "`n"))
    }
    foreach ($a in @($Actions | Where-Object { $_.Kind -eq 'service' })) {
        $blocks.Add((@(
                    (& $head 'Service. Windows PowerShell 5.1, elevated. Check that nothing prints from this server depends on it first.'),
                    "`$name = $(ConvertTo-PsLiteral $a.Name)",
                    '$svc = Get-Service -Name $name',
                    '''Service {0}: {1} / {2} -> Disabled / Stopped'' -f $name, (Get-CimInstance -ClassName Win32_Service -Filter "Name=''$name''").StartMode, $svc.Status',
                    'if ($Apply) { Set-Service -Name $name -StartupType Disabled; if ($svc.Status -eq ''Running'') { Stop-Service -Name $name -Force } }',
                    '# Undo: Set-Service -Name $name -StartupType Automatic; Start-Service -Name $name') -join "`n"))
    }
    return $blocks.ToArray()
}

# What the report shows under one check: the findings of that check, grouped by the exact set of
# changes they need, so hosts that need the same changes share a snippet.
function Get-CheckFixBlocks {
    param([string]$Type, $Findings, $HostRoles, $Config)
    $perHost = [ordered]@{}
    $withScript = 0
    foreach ($f in @($Findings)) {
        $acts = @(Get-RemediationActions -Finding $f -Role $HostRoles["$($f.Host)"] -Config $Config)
        if ($acts.Count -eq 0) { continue }
        $withScript++
        if (-not $perHost.Contains($f.Host)) { $perHost[$f.Host] = New-Object System.Collections.Generic.List[object] }
        foreach ($a in $acts) { $perHost[$f.Host].Add($a) }
    }
    $groups = @{}
    foreach ($h in $perHost.Keys) {
        $seen = @{}; $unique = New-Object System.Collections.Generic.List[object]
        foreach ($a in $perHost[$h]) { $line = ConvertTo-EngineLine $a; if (-not $seen.ContainsKey($line)) { $seen[$line] = $true; $unique.Add($a) } }
        $key = (@($seen.Keys) | Sort-Object) -join "`n"
        if (-not $groups.ContainsKey($key)) { $groups[$key] = [PSCustomObject]@{ Hosts = New-Object System.Collections.Generic.List[string]; Actions = $unique } }
        $groups[$key].Hosts.Add("$h")
    }
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($g in ($groups.Values | Sort-Object { $_.Hosts[0] })) {
        $result.Add([PSCustomObject]@{ Hosts = $g.Hosts.ToArray(); Settings = $g.Actions.Count; Code = ((ConvertTo-FixSnippet -Actions $g.Actions.ToArray()) -join "`n`n"); WithScript = $withScript; Total = @($Findings).Count })
    }
    return @($result.ToArray())
}

$script:RemediationTemplate = @'
<#
.SYNOPSIS
    HostBadger remediation for {{HOSTCOMMENT}}.

.DESCRIPTION
    Generated by HostBadger {{VERSION}} from the snapshot taken {{COLLECTED}} UTC:
    {{COUNT}} setting(s) for {{FINDINGS}} finding(s).

    Run without -Apply it only shows what it would change. With -Apply it changes the settings,
    after writing the previous value of each one to a rollback file; -Restore <file> -Apply puts
    them back. It stops if this computer is not {{HOSTCOMMENT}} (see -IgnoreHostName).

    HostBadger never runs this script. Read it, try it on a pilot machine, run it elevated.
    Some settings are controlled by Group Policy or Intune, which can set them back; some need a
    restart, and the script says which.

.PARAMETER Apply
    Make the changes. Without it nothing is changed.
.PARAMETER Restore
    Rollback file written by an earlier -Apply run: shows (or, with -Apply, does) the way back.
.PARAMETER RollbackFile
    Where to write the rollback file (default: next to this script).
.PARAMETER IgnoreHostName
    Run on a computer whose name is not the one in the snapshot.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$Restore = '',
    [string]$RollbackFile = '',
    [switch]$IgnoreHostName
)

$ErrorActionPreference = 'Stop'
$script:ExpectedHost = {{HOSTLIT}}
$script:Backups = New-Object System.Collections.Generic.List[object]
$script:Changed = 0
$script:Skipped = 0
$script:Failed = 0
$script:NeedRestart = New-Object System.Collections.Generic.List[string]
$script:RollbackPath = ''

function Test-HbAdmin {
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { return $false }
}

function Write-HbLine {
    param([string]$Tag, [string]$Text, [string]$Color = 'Gray')
    Write-Host ("{0,-9} {1}" -f $Tag, $Text) -ForegroundColor $Color
}

# The rollback file is rewritten after every change, so even an interrupted run can be undone.
function Save-HbBackup {
    param($Entry)
    $script:Backups.Add($Entry)
    $json = ConvertTo-Json -InputObject @($script:Backups.ToArray()) -Depth 6
    [System.IO.File]::WriteAllText($script:RollbackPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Set-HbRegistry {
    param([string]$Id, [string]$Path, [string]$Name, $Value, [string]$Type, [string]$Why, [switch]$Restart)
    try {
        $existed = $false; $old = $null; $oldKind = $null
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($item.GetValueNames() -contains $Name) {
                $existed = $true
                $old = $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
                $oldKind = "$($item.GetValueKind($Name))"
            }
        }
        catch { }
        $same = $false
        if ($existed -and $oldKind -eq $Type) {
            if ($Type -eq 'MultiString') { $same = ((@($old) -join ';') -eq (@($Value) -join ';')) }
            elseif ($Type -eq 'DWord') { $same = ([int64]$old -eq [int64]$Value) }
            else { $same = ("$old" -eq "$Value") }
        }
        if ($same) { Write-HbLine 'ok' "$Path\$Name already set" 'DarkGray'; $script:Skipped++; return }
        $was = if ($existed) { if ($oldKind -eq 'MultiString') { '(' + (@($old) -join ', ') + ')' } else { "$old" } } else { 'not set' }
        $will = if ($Type -eq 'MultiString') { '(empty)' } else { "$Value" }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "$Path\$Name : $was -> $will   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'registry'; id = $Id; path = $Path; name = $Name; existed = $existed; valueKind = $oldKind; value = $old })
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type $Type
        $script:Changed++
        if ($Restart) { $script:NeedRestart.Add("$Path\$Name") }
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "$Path\$Name : $($_.Exception.Message)" 'Red' }
}

function Set-HbSmb {
    param([string]$Id, [ValidateSet('Server', 'Client')][string]$Side, [string]$Setting, [bool]$Value, [string]$Why)
    try {
        $cfg = if ($Side -eq 'Server') { Get-SmbServerConfiguration } else { Get-SmbClientConfiguration }
        $old = [bool]$cfg.$Setting
        if ($old -eq $Value) { Write-HbLine 'ok' "SMB $Side $Setting already $Value" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "SMB $Side $Setting : $old -> $Value   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'smb'; id = $Id; side = $Side; setting = $Setting; value = $old })
        $p = @{ $Setting = $Value; Force = $true; Confirm = $false }
        if ($Side -eq 'Server') { Set-SmbServerConfiguration @p } else { Set-SmbClientConfiguration @p }
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "SMB $Side $Setting : $($_.Exception.Message)" 'Red' }
}

function Set-HbMpPreference {
    param([string]$Id, [string]$Setting, $Value, [string]$Why)
    try {
        $old = (Get-MpPreference).$Setting
        if ("$old" -eq "$Value") { Write-HbLine 'ok' "Defender $Setting already $Value" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "Defender $Setting : $old -> $Value   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'mp'; id = $Id; setting = $Setting; value = "$old" })
        $p = @{ $Setting = $Value }
        Set-MpPreference @p
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "Defender $Setting : $($_.Exception.Message)" 'Red' }
}

function Set-HbFirewall {
    param([string]$Id, [ValidateSet('Domain', 'Private', 'Public')][string]$ProfileName, [string]$Setting, [string]$Value, [string]$Why)
    try {
        $old = "$((Get-NetFirewallProfile -Name $ProfileName -PolicyStore ActiveStore).$Setting)"
        if ($old -eq $Value) { Write-HbLine 'ok' "Firewall $ProfileName $Setting already $Value" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "Firewall $ProfileName $Setting : $old -> $Value   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'firewall'; id = $Id; profile = $ProfileName; setting = $Setting; value = $old })
        $p = @{ Name = $ProfileName; $Setting = $Value }
        Set-NetFirewallProfile @p
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "Firewall $ProfileName $Setting : $($_.Exception.Message)" 'Red' }
}

function Set-HbFeature {
    param([string]$Id, [string]$Name, [string]$Why)
    try {
        $old = "$((Get-WindowsOptionalFeature -Online -FeatureName $Name).State)"
        if ($old -ne 'Enabled') { Write-HbLine 'ok' "Feature $Name already $old" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "Feature $Name : Enabled -> Disabled   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'feature'; id = $Id; name = $Name; value = $old })
        Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart | Out-Null
        $script:Changed++
        $script:NeedRestart.Add("feature $Name")
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "Feature $Name : $($_.Exception.Message)" 'Red' }
}

function Set-HbLocalUser {
    param([string]$Id, [string]$Name, [bool]$Enabled, [string]$Why)
    try {
        $old = [bool](Get-LocalUser -Name $Name).Enabled
        if ($old -eq $Enabled) { Write-HbLine 'ok' "Account $Name already Enabled=$Enabled" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "Account $Name Enabled : $old -> $Enabled   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'localuser'; id = $Id; name = $Name; value = $old })
        if ($Enabled) { Enable-LocalUser -Name $Name } else { Disable-LocalUser -Name $Name }
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "Account $Name : $($_.Exception.Message)" 'Red' }
}

function Set-HbService {
    # Stops the service and disables it.
    param([string]$Id, [string]$Name, [string]$Why)
    try {
        $svc = Get-Service -Name $Name
        $mode = "$((Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'").StartMode)"
        if ($mode -eq 'Disabled' -and "$($svc.Status)" -ne 'Running') { Write-HbLine 'ok' "Service $Name already disabled" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "Service $Name : $mode / $($svc.Status) -> Disabled / Stopped   [$Id] $Why" 'Yellow'
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'service'; id = $Id; name = $Name; startMode = $mode; status = "$($svc.Status)" })
        Set-Service -Name $Name -StartupType Disabled
        if ("$($svc.Status)" -eq 'Running') { Stop-Service -Name $Name -Force }
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "Service $Name : $($_.Exception.Message)" 'Red' }
}

function Restore-HbEntry {
    param($E)
    try {
        switch ($E.kind) {
            'registry' {
                if ($E.existed) {
                    $v = $E.value
                    if ($E.valueKind -eq 'MultiString') { $v = [string[]]@($E.value | Where-Object { $null -ne $_ }) }
                    elseif ($E.valueKind -eq 'DWord') { $v = [int][int64]$E.value }
                    Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "$($E.path)\$($E.name) -> $v" 'Yellow'
                    if ($Apply) { Set-ItemProperty -LiteralPath $E.path -Name $E.name -Value $v -Type $E.valueKind }
                }
                else {
                    Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "$($E.path)\$($E.name) -> removed (it was not set)" 'Yellow'
                    if ($Apply) { Remove-ItemProperty -LiteralPath $E.path -Name $E.name -ErrorAction SilentlyContinue }
                }
            }
            'smb' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "SMB $($E.side) $($E.setting) -> $($E.value)" 'Yellow'
                if ($Apply) { $p = @{ $E.setting = [bool]$E.value; Force = $true; Confirm = $false }; if ($E.side -eq 'Server') { Set-SmbServerConfiguration @p } else { Set-SmbClientConfiguration @p } }
            }
            'mp' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Defender $($E.setting) -> $($E.value)" 'Yellow'
                if ($Apply) { $p = @{ $E.setting = $E.value }; Set-MpPreference @p }
            }
            'firewall' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Firewall $($E.profile) $($E.setting) -> $($E.value)" 'Yellow'
                if ($Apply) { $p = @{ Name = $E.profile; $E.setting = $E.value }; Set-NetFirewallProfile @p }
            }
            'feature' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Feature $($E.name) -> $($E.value)" 'Yellow'
                if ($Apply -and $E.value -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $E.name -NoRestart | Out-Null }
            }
            'localuser' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Account $($E.name) Enabled -> $($E.value)" 'Yellow'
                if ($Apply) { if ([bool]$E.value) { Enable-LocalUser -Name $E.name } else { Disable-LocalUser -Name $E.name } }
            }
            'service' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Service $($E.name) -> $($E.startMode) / $($E.status)" 'Yellow'
                if ($Apply) {
                    $mode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }["$($E.startMode)"]
                    if ($mode) { Set-Service -Name $E.name -StartupType $mode }
                    if ("$($E.status)" -eq 'Running') { Start-Service -Name $E.name }
                }
            }
        }
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "restore $($E.kind) : $($_.Exception.Message)" 'Red' }
}

# ---------------------------------------------------------------- checks before anything
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Warning 'Use Windows PowerShell 5.1 (powershell.exe): the SMB, firewall, Defender and feature cmdlets load through a compatibility layer in PowerShell 7 and may fail.'
}
if ($env:COMPUTERNAME -ine $script:ExpectedHost -and -not $IgnoreHostName) {
    throw "This script was generated for $($script:ExpectedHost) and this computer is $env:COMPUTERNAME. Use -IgnoreHostName only if you mean it."
}
if ($Apply -and -not (Test-HbAdmin)) { throw 'Run this script from an elevated PowerShell to use -Apply.' }
$stamp = (Get-Date).ToString('yyyyMMddHHmmss')
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ---------------------------------------------------------------- restore mode
if ($Restore) {
    # Windows PowerShell 5.1 hands a JSON array back as one object, so foreach takes it apart.
    $entries = @()
    foreach ($x in (Get-Content -LiteralPath $Restore -Raw | ConvertFrom-Json)) { $entries += $x }
    Write-Host "$(if ($Apply) { 'Restoring' } else { 'Preview of the restore' }) from $Restore ($($entries.Count) setting(s))" -ForegroundColor Cyan
    for ($i = $entries.Count - 1; $i -ge 0; $i--) { Restore-HbEntry $entries[$i] }
    if (-not $Apply) { Write-Host 'Nothing was changed. Add -Apply to restore.' -ForegroundColor Cyan }
    if ($script:Failed -gt 0) { exit 1 }
    return
}

# ---------------------------------------------------------------- the fixes
$script:RollbackPath = if ($RollbackFile) { $RollbackFile } else { Join-Path $here ("rollback_{0}_{1}.json" -f ($script:ExpectedHost -replace '[^\w\-]', '_'), $stamp) }
Write-Host "$(if ($Apply) { 'Applying' } else { 'Preview (nothing is changed; add -Apply to apply)' }) HostBadger remediation for $($script:ExpectedHost)" -ForegroundColor Cyan

{{ACTIONS}}

# ---------------------------------------------------------------- summary
Write-Host ''
if ($Apply) {
    Write-Host "Changed $($script:Changed), already fine $($script:Skipped), failed $($script:Failed)." -ForegroundColor Cyan
    if ($script:Changed -gt 0) { Write-Host "Rollback file: $($script:RollbackPath)   (undo with: -Restore '$($script:RollbackPath)' -Apply)" -ForegroundColor Cyan }
    if ($script:NeedRestart.Count -gt 0) { Write-Host "A restart is needed for: $($script:NeedRestart -join '; ')" -ForegroundColor Yellow }
}
else { Write-Host "Preview only: $($script:Skipped) already fine. Nothing was changed." -ForegroundColor Cyan }
if ($script:Failed -gt 0) { exit 1 }
'@

# Builds the script for one host from its active findings, and returns the text together with what
# it covers.
function New-RemediationScript {
    param([string]$HostName, [string]$Role, $Findings, $Config, [string]$CollectedUtc, [string]$ToolVersion)
    $mine = @($Findings | Where-Object { $_.Host -eq $HostName })
    $body = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $fixable = 0
    $notFixable = New-Object System.Collections.Generic.List[object]
    $actions = 0
    $groups = @($mine | Group-Object Type | Sort-Object { - ($_.Group | ForEach-Object { $script:SeverityRank[$_.Severity] } | Measure-Object -Maximum).Maximum }, Name)
    foreach ($g in $groups) {
        $lines = New-Object System.Collections.Generic.List[string]
        $done = 0
        foreach ($f in $g.Group) {
            $acts = @(Get-RemediationActions -Finding $f -Role $Role -Config $Config)
            if ($acts.Count -eq 0) { $notFixable.Add($f); continue }
            $done++
            foreach ($a in $acts) { $line = ConvertTo-EngineLine $a; if (-not $seen.ContainsKey($line)) { $seen[$line] = $true; $lines.Add($line) } }
        }
        if ($lines.Count -eq 0) { continue }
        $fixable += $done
        $actions += $lines.Count
        $meta = $script:CheckCatalog[$g.Name]
        [void]$body.Add("# ---- $($g.Name): $($meta.Title) ($done of $(@($g.Group).Count) finding(s))")
        foreach ($l in $lines) { [void]$body.Add($l) }
        [void]$body.Add('')
    }
    $comment = ($HostName -replace '[^\w.\-]', '_')
    $text = $script:RemediationTemplate
    $text = $text.Replace('{{HOSTCOMMENT}}', $comment)
    $text = $text.Replace('{{HOSTLIT}}', (ConvertTo-PsLiteral $HostName))
    $text = $text.Replace('{{VERSION}}', $ToolVersion)
    $text = $text.Replace('{{COLLECTED}}', $CollectedUtc)
    $text = $text.Replace('{{COUNT}}', "$actions")
    $text = $text.Replace('{{FINDINGS}}', "$fixable")
    $text = $text.Replace('{{ACTIONS}}', ($body -join "`r`n"))
    return [PSCustomObject]@{ Host = $HostName; Text = $text; FixableFindings = $fixable; ActionCount = $actions; NotFixable = $notFixable.ToArray(); TotalFindings = $mine.Count }
}
