# Contributing

HostBadger is maintained by [@g4bri-3l3](https://github.com/g4bri-3l3).
Contributions are welcome through GitHub.

## Reporting a bug or asking for a check

Open an [issue](https://github.com/g4bri-3l3/HostBadger/issues) with:

- what you ran (the command line, Windows PowerShell 5.1 or PowerShell 7);
- what you expected and what happened (the message, or the finding that looks wrong);
- the Windows version of the host.

Do not attach real snapshots or reports: they describe the host in detail
(accounts, SIDs, paths, listening ports). If a finding needs the data, copy
only the few values involved, or reproduce it with
`tests\New-SyntheticHostSnapshot.ps1`.

A security problem in HostBadger itself goes through a private advisory, not an
issue: see [SECURITY.md](SECURITY.md).

## Proposing a change

1. Open an issue first for anything larger than a fix, so we can agree on the
   approach.
2. Fork the repository and work on a branch.
3. Keep the design rules in the README: the collector stays one read-only
   file, no network code outside `lib\AI.ps1`, nothing silently clean (what
   cannot be read is "not evaluated"), checks deterministic (ages counted at
   collection time).
4. A new check needs its catalog entry, a scenario in
   `tests\New-SyntheticHostSnapshot.ps1` that triggers it, the exact counts in
   `tests\Run-Regression.ps1`, `COVERAGE.md` regenerated with
   `tools\New-CoverageDoc.ps1` and a `CHANGELOG.md` entry.
5. Run, and make pass, on both PowerShell versions:

   ```powershell
   .\tests\Run-Regression.ps1
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Regression.ps1
   .\Test-HostBadgerSafety.ps1
   ```

6. Open a pull request describing what changes and why.

Only synthetic data goes into `examples\` and `tests\`. By contributing you
agree that your work is released under the [MIT License](LICENSE).
