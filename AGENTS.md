# AGENTS.md

Repository: `Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links`
Stack: PowerShell 5.1+/7, YARA, Pester

Start here:

- Read `README.md` before editing scanner flow, deployment guidance, or rule behavior.
- Read `.codex/README.md` for the repo-local Codex workflow.
- Use `.codex/skills/refactor/SKILL.md` when asked to refactor the scanner or run an iterative speed/refactor loop.
- Use Ponytail defaults inside the refactor loop: delete duplication first, reuse native PowerShell features, and keep Windows PowerShell 5.1 compatibility.

Validation commands:

- `pwsh -File tests/Invoke-Tests.ps1 -InstallPester`
- `pwsh -Command "Invoke-Pester -Path ./tests/Unit.PS1Logic.Tests.ps1 -Output Detailed"`
- `pwsh -Command "Invoke-Pester -Path ./tests/Integration.VeeamMock.Tests.ps1 -Output Detailed"`
- `pwsh -Command "Invoke-Pester -Path ./tests/Yara.Detection.Tests.ps1 -Output Detailed"`

Repo facts:

- Primary compatibility target is Windows PowerShell 5.1 on Veeam v12.x hosts.
- PowerShell 7 is an acceleration path, not the baseline behavior contract.
- `Veeam-YARA-SecureRestore.ps1` must remain safe to dot-source with `VEEAM_YARA_NOEXEC=1` for tests.
- YARA rules live in `yara-malware-detection.yara`; scanner logic lives in `Veeam-YARA-SecureRestore.ps1`.
- The test suite uses Pester plus real/synthetic YARA fixture coverage in `tests/`.

Change rules:

- Preserve PowerShell 5.1 parsing compatibility unless the maintainer explicitly drops it.
- Do not weaken timeout handling, logging fallbacks, HTTPS-only Veeam ONE alarms, or test dot-sourcing guards.
- Prefer native PowerShell and current repo helpers over adding wrappers or helper scripts.
- Keep scanner and rule changes reviewable. Avoid mixing README/marketing edits with behavioral changes unless the docs would otherwise lie.

Code map:

- `Veeam-YARA-SecureRestore.ps1` - scanner, logging, timeout, parsing, Veeam integration
- `yara-malware-detection.yara` - rule pack
- `tests/Unit.PS1Logic.Tests.ps1` - logic/unit coverage
- `tests/Integration.VeeamMock.Tests.ps1` - mocked Veeam flow
- `tests/Yara.Detection.Tests.ps1` - rule and parser coverage
- `tests/mocks/VeeamMock.psm1` - VBR 12.3.2 and 13 mock behavior

Claim discipline:

- Separate repo-backed fact, measured runtime result, market signal, and inference when editing README or deployment claims.
- Do not imply production efficacy, restore safety, or performance benefits without a measured or test-backed basis.
