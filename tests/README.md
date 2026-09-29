# Test suite

The suite exercises `Veeam-YARA-SecureRestore.ps1` and the YARA rule pack with Pester 5.7.1, real PowerShell processes, and the real YARA CLI. VBR metadata and mounted restore data are fixtures. No test connects to a production Veeam server or proves a real restore is safe.

## Run the suite

Install YARA on `PATH` and run from the repository root. On Windows, the full suite requires the isolated runner setup described below.

```powershell
# Install the pinned Pester version if needed, require YARA, and reject skips.
pwsh -NoProfile -File tests/Invoke-Tests.ps1 -InstallPester `
	-RequireYara -FailOnSkipped -ResultsPath testresults.xml

# The same suite in native Windows PowerShell 5.1 on the prepared test runner.
powershell.exe -NoProfile -File tests/Invoke-Tests.ps1 -InstallPester `
	-RequireYara -FailOnSkipped -ResultsPath testresults-ps51.xml

# Run one logic file without the native Windows registry fixtures.
pwsh -NoProfile -Command "Import-Module Pester -RequiredVersion 5.7.1; Invoke-Pester -Path ./tests/Unit.PS1Logic.Tests.ps1 -Output Detailed"
```

The runner imports exactly Pester 5.7.1. `-InstallPester` obtains that version from PowerShell Gallery when absent. `-RequireYara` rejects a missing CLI, and `-FailOnSkipped` rejects incomplete test coverage. The runner's output and NUnit file contain the actual pass, failure, and skip counts. Do not infer a result from the workflow definition alone.

`VEEAM_YARA_NOEXEC=1` lets tests dot-source scanner functions without a scan. Entry-point tests clear that variable in child processes and invoke the real script with synthetic targets. They must not inherit a setting that silently suppresses execution.

## Windows native runtime tests

**Use an isolated elevated Windows test runner with no VBR installation.** `Runtime.Native.Tests.ps1` refuses to proceed if the Registry64 Veeam Backup and Replication key already exists. Do not run the full suite on a production VBR server.

The runner needs native x64 Windows PowerShell 5.1 and a stable x64 PowerShell 7.6.3 or later. Set the path to the installed Core executable before starting either test host:

```powershell
$env:VEEAM_TEST_PWSH_PATH = 'C:\Program Files\PowerShell\7\pwsh.exe'
& $env:VEEAM_TEST_PWSH_PATH -NoProfile -Command '$PSVersionTable.PSVersion; [Environment]::Is64BitProcess'
```

Install the ThreadJob module for Windows PowerShell 5.1 as provisioned by the CI workflow. The full scanner execution matrix forces ThreadJob, Job, and Sequential modes, so an unavailable requested tier is a test failure.

Native tests create temporary version-stamped, inert `Veeam.Backup.Service.exe` fixtures and point an owned Registry64 VBR `CorePath` at them. The tests add a unique PowerShellCore InstalledVersions entry for `VEEAM_TEST_PWSH_PATH`, leaving existing runtime entries intact. Cleanup deletes the owned fixture key and its temporary runtime registration. Administrative registry write permission is required.

The matrix starts real Windows PowerShell and PowerShell 7 processes for VBR 12.3.2, Windows VBR 13.0.1, and VBR 13.1 metadata. Assertions check the ending runtime edition, major version, x64 process, detected file version, and absence of preflight scan-log creation. The fixture library is inspected for its file version and is never executed as a Veeam service.

Non-Windows discovery omits this Windows-only test block. Zero skipped tests on macOS or Linux therefore do not mean native Windows transitions were tested.

## Coverage and evidence

| File | What it checks |
|------|----------------|
| `Unit.PS1Logic.Tests.ps1` | Match parsing, mounted paths, wildcard target resolution, JSON output, stdout/stderr separation, launch failures, and timeouts. |
| `Integration.VeeamMock.Tests.ps1` | Mocked Windows volume discovery, actual system-drive exclusion, inaccessible probes, and optional custom logging-hook behavior. |
| `Runtime.Compatibility.Tests.ps1` | Version policy boundaries, x64 and release checks, unavailable runtimes, bounded relaunch, parameter preservation, and subprocess output validation. |
| `Runtime.Native.Tests.ps1` | Actual Windows PowerShell 5.1 and PowerShell 7 transitions using temporary Registry64 and versioned file fixtures. |
| `Scanner.Execution.Tests.ps1` | Actual scanner entry points with real YARA across execution tiers, expected exits and reports, missing tools/targets, discovery failures, timeouts, and report-write failures. |
| `Yara.Detection.Tests.ps1` | All six rules against synthetic positive and benign fixtures, native YARA exit semantics, malformed-rule rejection, and process-runner/parser integration. |
| `Invoke-MockAcceptance.ps1` | A standalone entry-point acceptance command that records scenario results and reports as JSON. |

`mocks/VeeamMock.psm1` supplies sample version and volume data. Its version labels do not change the executing PowerShell runtime. Neither version fixture supplies `Add-VBRJobLogEvent` by default. Tests explicitly enable that synthetic custom hook with `-EnableLogHook`; this is not a claim that either VBR release implements it.

`fixtures/malicious` contains synthetic indicators for rule testing. `fixtures/benign` covers selected exclusions. Every fixture scan must return raw YARA exit 0. Successful no-match and successful match runs both return 0 from YARA; malformed rules return nonzero. The scanner converts findings to its own exit 1 and incomplete scans to exit 2.

## Run entry-point acceptance separately

This command needs the real YARA CLI and all three execution tiers. It creates synthetic target directories and local reports under the supplied output directory.

```powershell
pwsh -NoProfile -File tests/Invoke-MockAcceptance.ps1 `
	-OutputDirectory "$env:TEMP\veeam-yara-acceptance"
```

On macOS or Linux, provide a writable local output path instead of `$env:TEMP`. The command runs in explicit Standalone mode, checks scenario exit codes and report status, and writes `acceptance.json`. It emulates mount discovery failures and mounted data, not Veeam's services or APIs.

## CI and limits

[`.github/workflows/tests.yml`](../.github/workflows/tests.yml) defines the native Windows and non-Windows jobs, dependency versions, and result artifacts. [`.github/workflows/powershell.yml`](../.github/workflows/powershell.yml) provides blocking analyzer checks and rule compilation. Required jobs reject absent YARA and skipped tests. Review a completed run's logs and NUnit artifacts for evidence tied to that commit.

The owner's historical VBR 12/PowerShell 5.1 report in [issue #25](https://github.com/cgfixit/Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links/issues/25), local macOS execution, native Windows CI, and live Veeam acceptance are different evidence. These fixtures do not load the proprietary Veeam module, mount backups, exercise production service-account permissions, or validate `AntivirusInfos.xml` in a live Secure Restore session.
