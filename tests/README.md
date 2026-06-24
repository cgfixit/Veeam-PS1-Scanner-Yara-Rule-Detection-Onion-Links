# Test Suite

Automated tests for **Veeam-YARA-SecureRestore.ps1** and **yara-malware-detection.yara**.
The suite is [Pester 5](https://pester.dev) for the PowerShell logic and the real
[YARA](https://virustotal.github.io/yara/) engine for rule detection.

```
tests/
├── Invoke-Tests.ps1                 # runner (configures Pester, NUnit output, exit code)
├── Unit.PS1Logic.Tests.ps1          # unit tests for the scanner's PowerShell logic
├── Integration.VeeamMock.Tests.ps1  # scanner driven against a mocked Veeam environment
├── Yara.Detection.Tests.ps1         # fixture-based YARA true-positive / true-negative tests
├── mocks/
│   └── VeeamMock.psm1               # mock VBR 12.3.2 (PS 5.1) and VBR 13 (PS 7) cmdlet surface
└── fixtures/
    ├── malicious/                   # synthetic samples that SHOULD trip rules (fake IOCs)
    ├── benign/                      # clean samples that must NOT match (FP-exclusion checks)
    └── yara_output/                 # captured `yara -s -m` output for parser tests
```

## Running

```powershell
# Everything (auto-installs Pester if missing):
pwsh -File tests/Invoke-Tests.ps1 -InstallPester

# A single file:
pwsh -Command "Invoke-Pester -Path ./tests/Unit.PS1Logic.Tests.ps1 -Output Detailed"

# With CI-style NUnit results:
pwsh -File tests/Invoke-Tests.ps1 -ResultsPath testresults.xml
```

The scanner is loaded with `$env:VEEAM_YARA_NOEXEC=1` so its functions can be
dot-sourced **without** launching a real scan (see the dot-source guard in the
script). Runs on Windows PowerShell 5.1 and PowerShell 7.

## What's covered

| Area | Highlights |
|------|-----------|
| **PS1 logic** | `Parse-YARAOutput` (string/onion extraction, dedup, metadata stripping, multi-rule/multi-file, null safety), `Convert-ToWindowsPath`, `Get-ScanTargets` (quick vs full), `Export-ScanResults` (grouping + JSON envelope), `Write-Log`, `Invoke-ProcessWithTimeout` (success / non-zero exit / timeout / launch failure). |
| **Mock Veeam env** | `VeeamMock.psm1` models **VBR 12.3.2 (PowerShell 5.1)** — `Add-VBRJobLogEvent` absent → file/host logging — and **VBR 13 (PowerShell 7)** — `Add-VBRJobLogEvent` present → events forwarded. Volume discovery filtering + failure hardening via a mocked `Get-Volume`. |
| **YARA detection** | All six rules verified against synthetic malicious fixtures (true positives) and benign fixtures that exercise the false-positive exclusion strings (true negatives), plus an end-to-end run through the scanner's own `Invoke-ProcessWithTimeout` + `Parse-YARAOutput`. |

## Requirements

- **PowerShell** 5.1+ (Windows PowerShell) or 7+ (`pwsh`)
- **Pester** 5.0+ (`Install-Module Pester`, or pass `-InstallPester`)
- **yara** CLI on `PATH` for the detection tests — they self-skip if it is absent

CI runs the suite via [`.github/workflows/tests.yml`](../.github/workflows/tests.yml).
