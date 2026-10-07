# Security

## What the collector does on a host

`Collect-HostSnapshot.ps1` only reads. Concretely, it:

- reads registry values under `HKLM` (LSA, WDigest, Winlogon, SMB, DNS client, Terminal Server, UAC, LAPS, PowerShell and audit policies, Run keys, Secure Boot state);
- queries CIM classes (`Win32_ComputerSystem`, `Win32_OperatingSystem`, `Win32_QuickFixEngineering`, `Win32_Service`, `Win32_UserAccount`, `Win32_NetworkAdapterConfiguration`, `Win32_DeviceGuard`, `Win32_EncryptableVolume`);
- calls the read cmdlets `Get-MpComputerStatus`, `Get-MpPreference`, `Get-BitLockerVolume`, `Get-SmbServerConfiguration`, `Get-SmbClientConfiguration`, `Get-NetFirewallProfile`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Get-Process`, `Get-LocalUser`, `Get-ScheduledTask`, `Get-Acl`, `Get-WinEvent -ListLog`;
- reads the Windows Update history through the `Microsoft.Update.Session` COM object, and the members of the local Administrators group through ADSI (`GetProperty` only);
- runs `auditpol /backup` into a CSV in its own output folder, reads it and deletes it;
- runs `secedit /export` (the only secedit verb the safety review accepts) into a temporary INF and log in its own output folder, keeps only the account policy settings and the user rights, and deletes both files; it never uses `/configure` or `/import`;
- writes `hostsnapshot_<host>_<time>.json`, compresses it to a zip and deletes the JSON.

It changes no setting, starts no process or service, and opens no network connection. `Test-HostBadgerSafety.ps1` verifies this from the code (it parses the scripts, it doesn't run them) and fails on anything outside the reviewed list.

## What the snapshot contains

Host configuration in detail: installed updates, Defender exclusions, local account names and SIDs, members of the local Administrators group, listening ports and their processes, service, task and autorun command lines (with password-like arguments masked). Treat snapshots and reports as confidential, and delete snapshots from `C:\Windows\Temp\HostBadger` once fetched.

## The analyzer

`HostBadger.ps1` needs no rights on the hosts and no network: it reads snapshot files and writes the report files you name.

### Remediation scripts

The report shows, under each check that has a safe, standard fix, a **Fix script** block: plain PowerShell text that prints "old -> new" and changes nothing until `$Apply` is set to `$true`. HostBadger does not run it, and the analyzer stays read-only. With the optional `-OutRemediation`, `HostBadger.ps1` also writes `remediate_<host>.ps1` files; such a script only previews unless it is run with `-Apply` (administrator), refuses to run on a computer whose name is not the one in the snapshot, writes a rollback file with the previous value of every setting before changing it, and contains only calls to its own seven helper functions (registry values under HKLM, SMB, Defender, firewall profile, one optional feature, one account, one service). Read it, try it on a pilot host, then apply. Group Policy or Intune may set a value back.

### The optional AI step

Only with `-SendToAI` (or `Start-HostBadger.ps1` option 4), `HostBadger.ps1` sends findings to Gemini (`generativelanguage.googleapis.com`, or the gateway in `HOSTBADGER_GEMINI_BASEURL`). Host names, domains, accounts, groups, SIDs, paths, service/task/autorun/adapter names and addresses are replaced by tokens first, collector error messages are never included, and a leak check refuses to send if any real name survives. `-AiDryRun` writes the exact text and sends nothing; every real send leaves the prompt and the reply next to the report. The key is read from `GEMINI_API_KEY` or `-ApiKey`. The safety review fails on network code anywhere but `lib\AI.ps1` and on any other address, so the collector stays offline.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
