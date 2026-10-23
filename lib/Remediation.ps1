# Fix scripts, generated from the findings. They come in two forms: a plain PowerShell snippet under
# each check in the report, and, if you ask for it, one file per host. What we promise, and why it
# is safe to offer: We only offer fixes that are one setting, set to the value the benchmark or
# Microsoft expects. They can be undone, they leave no choice to the organization (no banner text,
# no list of allowed admins), and they don't depend on hardware or firewall rules. A generated
# script changes nothing unless you set $Apply (the per-host file: run it with -Apply). The per-host
# file also records the old value of every setting in a rollback file, which -Restore puts back, and
# it refuses to run on a computer whose name is not the one in the snapshot. The analyzer never runs
# any of this, it only writes text; the guided menu (Start-HostBadger.ps1, Remediate this machine)
# runs this machine's own script after showing it and asking for YES. Fixes that need a decision (banner text, allowed administrators,
# password policy, services to disable, BitLocker, Credential Guard, LAPS, user rights...) are left
# out on purpose.
#
# Remediation profiles (-RemediationProfile Essential / Recommended / Strict, user decision 2026-10-22)
# are the one exception, and only when asked for: a fixed list of settings from
# data\remediation-profiles.json (CIS Windows 11 rules, Essential Eight requirements, and for Strict
# opinionated hardening and the removal of preinstalled apps), added after the fixes of the findings.
# They may embody an organizational choice, and some cannot be undone by the rollback file (an app
# removed, LSA protection with its UEFI lock): the script marks those NOT REVERSIBLE in the preview
# and counts them in the summary.

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
        'defender_pua_off', 'defender_network_protection_off', 'firewall_profile_disabled', 'firewall_default_inbound_allow', 'firewall_drop_logging_off', 'firewall_notifications_on', 'dc_netlogon_policy_weak', 'server_baseline_gaps', 'driver_blocklist_off', 'mdns_enabled',
        'powershell_v2_enabled', 'spooler_on_dc', 'script_files_execute_on_open')) { $script:FixTypes[$k] = $true }

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
            elseif ($o -eq 'WinRM service: RunAs credential storage') { & $reg $wrmS 'DisableRunAs' 1 }
            # AllowAutoConfig (Level 2) is left without a fix script on purpose: disabling remote
            # WinRM configuration can break EDR/RMM tooling that configures WinRM remotely.
        }
        'mdns_enabled' { & $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 0 }
        'driver_blocklist_off' { & $reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 1 -Restart }
        'dc_netlogon_policy_weak' {
            if ($o -eq 'Netlogon: RefusePasswordChange') { & $reg $nl 'RefusePasswordChange' 0 }
            elseif ($o -eq 'Server Operators: schedule tasks') { & $reg $lsa 'SubmitControl' 0 }
            # The Zerologon exception list is left alone: removing it cuts off the devices it lists.
        }
        'server_baseline_gaps' {
            if ($o -eq 'Shutdown without logon') { & $reg $sys 'ShutdownWithoutLogon' 0 }
            # ForceUnlockLogon makes unlocking depend on a domain controller, and the LAPS setting lives
            # in whichever policy root is active: both are decisions.
        }
        'firewall_notifications_on' {
            if ($o -match '^profile: (Domain|Private|Public)$') { & $reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$($Matches[1])Profile" 'DisableNotifications' 1 }
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
        # The extension opens as text (Notepad); scripts called explicitly still run.
        'script_files_execute_on_open' { if ($o -match '^file type: (\.(js|jse|vbs|vbe|wsf|wsh|hta))$') { & $reg "HKLM:\SOFTWARE\Classes\$($Matches[1])" '(default)' 'txtfile' 'String' } }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------- remediation profiles
$script:RemediationTiers = @('Essential', 'Recommended', 'Strict')

# The tier as written in $script:RemediationTiers ('strict' -> 'Strict'), or '' for none.
function Get-TierName {
    param([string]$Name)
    foreach ($t in $script:RemediationTiers) { if ($t -ieq "$Name".Trim()) { return $t } }
    return ''
}

function Get-RemediationProfileData {
    # data\remediation-profiles.json, read once. Windows PowerShell 5.1 hands a JSON array back as
    # one object: foreach takes it apart.
    if ($null -eq $script:RemediationProfileData) {
        $path = Join-Path $PSScriptRoot '..\data\remediation-profiles.json'
        $doc = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))
        $script:RemediationProfileData = [PSCustomObject]@{ Tiers = $doc.tiers; Items = @(foreach ($i in $doc.items) { $i }) }
    }
    return $script:RemediationProfileData
}

# The actions of a profile for one host: every item of that tier and the ones below it that applies
# to the host's role, then (Strict, or -Debloat on its own) one removal per group of preinstalled apps
# of $script:BloatwareApps. Same data as Get-RemediationActions, plus Tier and NoUndo.
function Get-ProfileActions {
    # Privacy: the privacy and telemetry settings of every tier, with or without a tier.
    param([string]$ProfileName, [string]$Role, [switch]$Debloat, [switch]$Privacy)
    $out = New-Object System.Collections.Generic.List[object]
    $rank = [array]::IndexOf($script:RemediationTiers, (Get-TierName $ProfileName))
    if ($rank -ge 0 -or $Privacy) {
        foreach ($i in (Get-RemediationProfileData).Items) {
            $inTier = $rank -ge 0 -and [array]::IndexOf($script:RemediationTiers, (Get-TierName $i.tier)) -le $rank
            if (-not $inTier -and -not ($Privacy -and "$($i.category)" -eq 'privacy')) { continue }
            if (@($i.roles) -notcontains $Role) { continue }
            $a = @{ Kind = "$($i.kind)"; Id = "$($i.tier)/$($i.id)"; Why = "$($i.title) - $($i.ref)"; Tier = "$($i.tier)"; NoUndo = (-not $i.reversible) }
            switch ("$($i.kind)") {
                'reg' { $a.Path = "$($i.path)"; $a.Name = "$($i.name)"; $a.Value = $i.value; $a.Type = "$($i.type)"; $a.Restart = [bool]$i.restart; $a.AtMost = [bool]$i.atMost }
                'fwrule' { $a.Name = "$($i.name)"; $a.Program = @($i.program | ForEach-Object { "$_" }) }
                default { $a.Name = "$($i.name)" }
            }
            $out.Add($a)
        }
    }
    # Preinstalled consumer apps are a workstation matter.
    if (($Debloat -or $rank -eq 2) -and $Role -eq 'workstation') {
        foreach ($b in @($script:BloatwareApps | Where-Object { $_.Appx })) {
            $slug = ("$($b.Label)".ToLower() -replace '[^a-z0-9]+', '-').Trim('-')
            $out.Add(@{ Kind = 'appx'; Id = "debloat/$slug"; Why = "Preinstalled app: $($b.Label)"; Tier = 'debloat'; NoUndo = $true; Label = "$($b.Label)"; Pattern = "$($b.Appx)" })
        }
    }
    return $out.ToArray()
}

# What a change touches, so the same setting from a finding fix and from a profile is written once.
function Get-ActionTarget {
    param($A)
    switch ($A.Kind) {
        'reg' { return "reg|$($A.Path)|$($A.Name)".ToLower() }
        'smb' { return "smb|$($A.Side)|$($A.Setting)".ToLower() }
        'mp' { return "mp|$($A.Setting)".ToLower() }
        'fw' { return "fw|$($A.ProfileName)|$($A.Setting)".ToLower() }
        'appx' { return "appx|$($A.Pattern)" }
        default { return "$($A.Kind)|$($A.Name)".ToLower() }
    }
}

# One action as a line of the per-host script, which defines the helper functions it calls.
function ConvertTo-EngineLine {
    param($A)
    $id = ConvertTo-PsLiteral "$($A.Id)"
    $why = ConvertTo-PsLiteral "$($A.Why)"
    switch ($A.Kind) {
        'reg' {
            $v = if ($A.Type -eq 'DWord') { [string][int64]$A.Value } elseif ($A.Type -eq 'MultiString') { '([string[]]@())' } else { ConvertTo-PsLiteral "$($A.Value)" }
            return "Set-HbRegistry -Id $id -Path $(ConvertTo-PsLiteral $A.Path) -Name $(ConvertTo-PsLiteral $A.Name) -Value $v -Type $(ConvertTo-PsLiteral $A.Type) -Why $why$(if ($A.Restart) { ' -Restart' })$(if ($A.NoUndo) { ' -NoUndo' })$(if ($A.AtMost) { ' -AtMost' })"
        }
        'fwrule' { return "Set-HbFwRule -Id $id -Name $(ConvertTo-PsLiteral $A.Name) -Program @($((@($A.Program) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', ')) -Why $why" }
        'appx' { return "Remove-HbAppx -Id $id -Label $(ConvertTo-PsLiteral $A.Label) -Pattern $(ConvertTo-PsLiteral $A.Pattern) -Why $why" }
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
            '    $vn = if ($c.Name -eq ''(default)'') { '''' } else { $c.Name }   # the default value is '''' to the registry API',
            '    $old = if ($key -and ($key.GetValueNames() -contains $vn)) { $key.GetValue($vn) } else { ''(not set)'' }',
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
    foreach ($a in @($Actions | Where-Object { $_.Kind -eq 'fwrule' })) {
        $progs = (@($a.Program) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', '
        $blocks.Add((@(
                    (& $head 'Outbound firewall rule. Windows PowerShell 5.1, elevated.'),
                    "`$name = $(ConvertTo-PsLiteral $a.Name)",
                    "foreach (`$p in @($progs)) {",
                    '    $rule = ''HostBadger-BlockOut-'' + $name + ''-'' + ((Split-Path $p -Parent) -replace ''^%SystemRoot%'', ''Windows'' -replace ''[^\w]'', '''')',
                    '    ''Firewall rule {0}: {1} -> block outbound {2}'' -f $rule, $(if (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue) { ''present'' } else { ''absent'' }), $p',
                    '    if ($Apply -and -not (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name $rule -DisplayName "HostBadger: block outbound $name" -Direction Outbound -Action Block -Program $p | Out-Null }',
                    '}',
                    '# Undo: Remove-NetFirewallRule -Name ''HostBadger-BlockOut-*''') -join "`n"))
    }
    foreach ($a in @($Actions | Where-Object { $_.Kind -eq 'appx' })) {
        $blocks.Add((@(
                    (& $head 'Preinstalled app, for every user and new profiles. Windows PowerShell 5.1, elevated. NOT REVERSIBLE: it comes back only from the Microsoft Store.'),
                    "`$pattern = $(ConvertTo-PsLiteral $a.Pattern)",
                    '$found = @(Get-AppxPackage -AllUsers | Where-Object { $_.Name -match $pattern }) + @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match $pattern })',
                    '''Remove: {0}'' -f $(if ($found.Count) { ($found | ForEach-Object { if ($_.Name) { $_.Name } else { $_.DisplayName } } | Sort-Object -Unique) -join '', '' } else { ''nothing installed'' })',
                    'if ($Apply) {',
                    '    Get-AppxPackage -AllUsers | Where-Object { $_.Name -match $pattern } | Remove-AppxPackage -AllUsers',
                    '    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match $pattern } | Remove-AppxProvisionedPackage -Online | Out-Null',
                    '}') -join "`n"))
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
    {{COUNT}} setting(s) for {{FINDINGS}} finding(s).{{PROFILE}}

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
.PARAMETER RestorePoint
    With -Apply: create a System Restore point first, without asking (a run with no console, such as
    an RMM or EDR job). By default -Apply offers one when it runs at a console.
.PARAMETER NoRestorePoint
    With -Apply: neither create nor offer a System Restore point.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$Restore = '',
    [string]$RollbackFile = '',
    [switch]$IgnoreHostName,
    [switch]$RestorePoint,
    [switch]$NoRestorePoint
)

$ErrorActionPreference = 'Stop'
$script:ExpectedHost = {{HOSTLIT}}
$script:Backups = New-Object System.Collections.Generic.List[object]
$script:Changed = 0
$script:Skipped = 0
$script:Failed = 0
$script:NoUndo = 0
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
    # -NoUndo: the rollback file records the old value, but putting it back does not undo the change
    # (LSA protection with its UEFI lock).
    # -AtMost: a DWord already at or below the value is left alone (a stricter setting is never loosened).
    param([string]$Id, [string]$Path, [string]$Name, $Value, [string]$Type, [string]$Why, [switch]$Restart, [switch]$NoUndo, [switch]$AtMost)
    try {
        $existed = $false; $old = $null; $oldKind = $null
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            # The default value is '(default)' to Set-ItemProperty and '' to the registry API.
            $vn = if ($Name -eq '(default)') { '' } else { $Name }
            if ($item.GetValueNames() -contains $vn) {
                $existed = $true
                $old = $item.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
                $oldKind = "$($item.GetValueKind($vn))"
            }
        }
        catch { }
        $same = $false
        if ($existed -and $oldKind -eq $Type) {
            if ($Type -eq 'MultiString') { $same = ((@($old) -join ';') -eq (@($Value) -join ';')) }
            elseif ($Type -eq 'DWord') { $same = $(if ($AtMost) { [int64]$old -le [int64]$Value } else { [int64]$old -eq [int64]$Value }) }
            else { $same = ("$old" -eq "$Value") }
        }
        if ($same) { Write-HbLine 'ok' "$Path\$Name already set" 'DarkGray'; $script:Skipped++; return }
        $was = if ($existed) { if ($oldKind -eq 'MultiString') { '(' + (@($old) -join ', ') + ')' } else { "$old" } } else { 'not set' }
        $will = if ($Type -eq 'MultiString') { '(empty)' } else { "$Value" }
        Write-HbLine $(if ($Apply) { 'SET' } else { 'WOULD SET' }) "$Path\$Name : $was -> $will   [$Id] $Why$(if ($NoUndo) { '   NOT REVERSIBLE' })" $(if ($NoUndo) { 'Magenta' } else { 'Yellow' })
        if ($NoUndo) { $script:NoUndo++ }
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
    if (-not (Test-HbAdmin)) { Write-HbLine 'UNKNOWN' "Feature $Name : Windows lets only an elevated PowerShell read it   [$Id] $Why" 'DarkYellow'; return }
    try {
        $old = "$((Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue).State)"
        if (-not $old) { Write-HbLine 'ok' "Feature $Name not present on this Windows" 'DarkGray'; $script:Skipped++; return }
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
        # Get-Service -Name falls back to the display name: "Browser" finds the bowser driver. Only the
        # exact service name counts.
        $svc = @(Get-Service -Name $Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $Name })[0]
        if (-not $svc) { Write-HbLine 'ok' "Service $Name not installed" 'DarkGray'; $script:Skipped++; return }
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

function Set-HbFwRule {
    # One outbound block rule per program path, named HostBadger-BlockOut-<exe>-<folder> (WindowsSystem32,
    # WindowsSysWOW64wbem...); the restore
    # removes the rules it added.
    param([string]$Id, [string]$Name, [string[]]$Program, [string]$Why)
    foreach ($p in $Program) {
        $rule = 'HostBadger-BlockOut-' + $Name + '-' + ((Split-Path $p -Parent) -replace '^%SystemRoot%', 'Windows' -replace '[^\w]', '')
        try {
            if (-not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($p)))) { Write-HbLine 'ok' "$p not present" 'DarkGray'; $script:Skipped++; continue }
            if (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue) { Write-HbLine 'ok' "Firewall rule $rule already present" 'DarkGray'; $script:Skipped++; continue }
            Write-HbLine $(if ($Apply) { 'ADD' } else { 'WOULD ADD' }) "Firewall rule $rule : block outbound $p   [$Id] $Why" 'Yellow'
            if (-not $Apply) { continue }
            Save-HbBackup ([ordered]@{ kind = 'fwrule'; id = $Id; name = $rule })
            New-NetFirewallRule -Name $rule -DisplayName "HostBadger: block outbound $Name" -Direction Outbound -Action Block -Program $p | Out-Null
            $script:Changed++
        }
        catch { $script:Failed++; Write-HbLine 'FAILED' "Firewall rule $rule : $($_.Exception.Message)" 'Red' }
    }
}

function Remove-HbAppx {
    # A group of preinstalled apps, for every user and from the provisioned list (new profiles).
    # Not reversible: the rollback file only names them; they come back from the Microsoft Store.
    param([string]$Id, [string]$Label, [string]$Pattern, [string]$Why)
    if (-not (Test-HbAdmin)) { Write-HbLine 'UNKNOWN' "$Label : Windows lets only an elevated PowerShell list the apps of every user   [$Id]   NOT REVERSIBLE if removed" 'DarkYellow'; return }
    try {
        $inst = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -match $Pattern })
        $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match $Pattern })
        $names = @(@($inst | ForEach-Object { "$($_.Name)" }) + @($prov | ForEach-Object { "$($_.DisplayName)" }) | Sort-Object -Unique)
        if ($names.Count -eq 0) { Write-HbLine 'ok' "$Label not installed" 'DarkGray'; $script:Skipped++; return }
        Write-HbLine $(if ($Apply) { 'REMOVE' } else { 'WOULD REMOVE' }) "$Label : $($names -join ', ')   [$Id]   NOT REVERSIBLE (back only from the Microsoft Store)" 'Magenta'
        $script:NoUndo++
        if (-not $Apply) { return }
        Save-HbBackup ([ordered]@{ kind = 'appx'; id = $Id; label = $Label; names = $names })
        # Provisioned list first (new profiles), then every user. Removing for every user can take the
        # provisioned copy away too, and DISM then answers "path not found" for a package that is gone:
        # what counts is what is still there afterwards.
        $errs = @()
        foreach ($p in $prov) { try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null } catch { $errs += "$($_.Exception.Message)".Trim() } }
        foreach ($i in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -match $Pattern })) {
            try { Remove-AppxPackage -Package $i.PackageFullName -AllUsers -ErrorAction Stop } catch { $errs += "$($_.Exception.Message)".Trim() }
        }
        $left = @(@(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -match $Pattern } | ForEach-Object { "$($_.Name)" }) + @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match $Pattern } | ForEach-Object { "$($_.DisplayName)" }) | Sort-Object -Unique)
        if ($left.Count -gt 0) { throw "still installed: $($left -join ', ')$(if ($errs) { " ($($errs[0]))" })" }
        $script:Changed++
    }
    catch { $script:Failed++; Write-HbLine 'FAILED' "$Label : $($_.Exception.Message)" 'Red' }
}

function New-HbRestorePoint {
    # A System Restore point before the changes: offered at a console, made without asking with
    # -RestorePoint. Windows has none on servers or in PowerShell 7, and makes at most one a day.
    if ($NoRestorePoint) { return }
    $console = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
    if (-not $RestorePoint) {
        if (-not $console) { Write-HbLine 'NOTE' 'No System Restore point offered (no console to ask; add -RestorePoint to make one).' 'DarkGray'; return }
        if ("$(Read-Host 'Create a System Restore point before the changes? (Y/n)')".Trim() -match '^(?i)n(o)?$') { return }
    }
    # With System Protection off (RPSessionInterval 0, the default on many new or virtual machines)
    # Windows answers "service disabled": at a console, offer to turn it on for the system drive.
    $srKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue
    if ($srKey -and $null -ne $srKey.RPSessionInterval -and [int]$srKey.RPSessionInterval -eq 0) {
        Write-HbLine 'NOTE' "System Protection is off on this machine, so Windows cannot make a restore point (Enable-ComputerRestore -Drive '$env:SystemDrive\' turns it on)." 'Yellow'
        if ($console -and "$(Read-Host "Turn System Protection on for $env:SystemDrive first? (y/N)")".Trim() -match '^(?i)y(es)?$') {
            try { Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop }
            catch { Write-HbLine 'NOTE' "System Protection not turned on: $($_.Exception.Message)" 'Yellow' }
        }
    }
    try {
        if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) { throw 'Checkpoint-Computer exists only in Windows PowerShell 5.1 on a Windows client' }
        Checkpoint-Computer -Description 'HostBadger: before remediation' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-HbLine 'OK' 'System Restore point created (Windows skips it if one was made in the last 24 hours).' 'Green'
    }
    catch {
        Write-HbLine 'NOTE' "No System Restore point: $($_.Exception.Message). The rollback file still records every value changed." 'Yellow'
        # System Restore starts the Volume Shadow Copy service and its provider: name the one that is disabled.
        $off = @(Get-Service -Name 'VSS', 'swprv' -ErrorAction SilentlyContinue | Where-Object { "$($_.StartType)" -eq 'Disabled' } | ForEach-Object { $_.Name })
        if ($off.Count -gt 0) { Write-HbLine 'NOTE' "Disabled: $($off -join ', '). System Restore needs them on Manual (the Windows default): Set-Service <name> -StartupType Manual, then Enable-ComputerRestore -Drive 'C:\'." 'Yellow' }
        if ($console -and -not $RestorePoint -and "$(Read-Host 'Go on without it? (y/N)')".Trim() -notmatch '^(?i)y(es)?$') { throw 'Stopped before any change: no System Restore point.' }
    }
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
            'fwrule' {
                Write-HbLine $(if ($Apply) { 'RESTORE' } else { 'WOULD' }) "Firewall rule $($E.name) -> removed" 'Yellow'
                if ($Apply) { Remove-NetFirewallRule -Name $E.name -ErrorAction SilentlyContinue }
            }
            'appx' {
                Write-HbLine 'SKIPPED' "$($E.label) ($(@($E.names) -join ', ')) is not reinstalled: get it back from the Microsoft Store" 'Magenta'
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
if ($Apply) { New-HbRestorePoint }
Write-Host "$(if ($Apply) { 'Applying' } else { 'Preview (nothing is changed; add -Apply to apply)' }) HostBadger remediation for $($script:ExpectedHost)" -ForegroundColor Cyan

{{ACTIONS}}

# ---------------------------------------------------------------- summary
Write-Host ''
if ($Apply) {
    Write-Host "Changed $($script:Changed), already fine $($script:Skipped), failed $($script:Failed)." -ForegroundColor Cyan
    if ($script:Changed -gt 0) { Write-Host "Rollback file: $($script:RollbackPath)   (undo with: -Restore '$($script:RollbackPath)' -Apply)" -ForegroundColor Cyan }
    if ($script:NeedRestart.Count -gt 0) { Write-Host "A restart is needed for: $($script:NeedRestart -join '; ')" -ForegroundColor Yellow }
    if ($script:NoUndo -gt 0) { Write-Host "$($script:NoUndo) change(s) marked NOT REVERSIBLE: -Restore cannot undo them." -ForegroundColor Magenta }
}
else {
    Write-Host "Preview only: $($script:Skipped) already fine. Nothing was changed." -ForegroundColor Cyan
    if ($script:NoUndo -gt 0) { Write-Host "$($script:NoUndo) of the changes above are NOT REVERSIBLE: -Restore cannot undo them." -ForegroundColor Magenta }
}
if ($script:Failed -gt 0) { exit 1 }
'@

# Builds the script for one host from its active findings, and returns the text together with what
# it covers.
function New-RemediationScript {
    param([string]$HostName, [string]$Role, $Findings, $Config, [string]$CollectedUtc, [string]$ToolVersion, [string]$ProfileName = '', [switch]$Debloat, [switch]$Privacy, [switch]$NoApps, [switch]$OnlyProfile)
    # OnlyProfile: the safe fixes of the findings stay out (debloat and telemetry only).
    if ($OnlyProfile) { $Findings = @() }
    $mine = @($Findings | Where-Object { $_.Host -eq $HostName })
    $body = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $targets = @{}
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
            foreach ($a in $acts) { $line = ConvertTo-EngineLine $a; if (-not $seen.ContainsKey($line)) { $seen[$line] = $true; $targets[(Get-ActionTarget $a)] = $true; $lines.Add($line) } }
        }
        if ($lines.Count -eq 0) { continue }
        $fixable += $done
        $actions += $lines.Count
        $meta = $script:CheckCatalog[$g.Name]
        [void]$body.Add("# ---- $($g.Name): $($meta.Title) ($done of $(@($g.Group).Count) finding(s))")
        foreach ($l in $lines) { [void]$body.Add($l) }
        [void]$body.Add('')
    }
    # The profile: its settings whether or not a finding asked for them (the script reads each current
    # value first and skips what is already set), one block per category, a setting already written
    # for a finding left out.
    $profileActions = 0; $profileNoUndo = 0
    # NoApps: the app removals stay out (the guided menu asks for them itself, one list per machine).
    $prof = @(Get-ProfileActions -ProfileName $ProfileName -Role $Role -Debloat:$Debloat -Privacy:$Privacy | Where-Object { -not ($NoApps -and $_.Kind -eq 'appx') })
    $catName = @{ hardening = 'hardening'; privacy = 'privacy and telemetry'; services = 'services'; features = 'Windows features'; debloat = 'preinstalled apps' }
    $catOf = @{}; foreach ($i in (Get-RemediationProfileData).Items) { $catOf["$($i.tier)/$($i.id)"] = "$($i.category)" }
    foreach ($cat in 'hardening', 'privacy', 'services', 'features', 'debloat') {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($a in $prof) {
            $c = if ($a.Kind -eq 'appx') { 'debloat' } else { $catOf[$a.Id] }
            if ($c -ne $cat) { continue }
            $tg = Get-ActionTarget $a
            if ($targets.ContainsKey($tg)) { continue }
            $targets[$tg] = $true
            $lines.Add((ConvertTo-EngineLine $a))
            if ($a.NoUndo) { $profileNoUndo++ }
        }
        if ($lines.Count -eq 0) { continue }
        $profileActions += $lines.Count
        $label = if (Get-TierName $ProfileName) { "profile $(Get-TierName $ProfileName)" } elseif ($cat -eq 'privacy') { 'privacy' } else { 'debloat' }
        [void]$body.Add("# ---- $label`: $($catName[$cat])")
        foreach ($l in $lines) { [void]$body.Add($l) }
        [void]$body.Add('')
    }
    $actions += $profileActions
    $comment = ($HostName -replace '[^\w.\-]', '_')
    $text = $script:RemediationTemplate
    $text = $text.Replace('{{HOSTCOMMENT}}', $comment)
    $text = $text.Replace('{{HOSTLIT}}', (ConvertTo-PsLiteral $HostName))
    $text = $text.Replace('{{VERSION}}', $ToolVersion)
    $text = $text.Replace('{{COLLECTED}}', $CollectedUtc)
    $text = $text.Replace('{{COUNT}}', "$actions")
    $text = $text.Replace('{{FINDINGS}}', "$fixable")
    $profText = ''
    if ($profileActions -gt 0) {
        $what = @()
        if (Get-TierName $ProfileName) { $what += "the $(Get-TierName $ProfileName) remediation profile" }
        if ($Debloat -and -not $NoApps -and $ProfileName -notmatch '^(?i)strict$') { $what += 'the removal of preinstalled apps' }
        if ($Privacy -and $ProfileName -notmatch '^(?i)strict$') { $what += 'the privacy and telemetry settings' }
        $profText = "`r`n    Of them, $profileActions come from $($what -join ' and ')$(if ($profileNoUndo) { ", $profileNoUndo of which are NOT REVERSIBLE" })."
    }
    $text = $text.Replace('{{PROFILE}}', $profText)
    $text = $text.Replace('{{ACTIONS}}', ($body -join "`r`n"))
    return [PSCustomObject]@{ Host = $HostName; Text = $text; FixableFindings = $fixable; ActionCount = $actions; ProfileActions = $profileActions; NoUndoActions = $profileNoUndo; NotFixable = $notFixable.ToArray(); TotalFindings = $mine.Count }
}
