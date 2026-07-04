---
name: refactor
description: >-
  Iterative architecture and speed refactor loop for
  Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links. Use when asked to clean up
  the scanner architecture, simplify the rule workflow, or run a measured
  optimization loop with verification, review, commits, and tracker updates.
---

# Refactor

Use this skill when the user asks to refactor or optimize the PowerShell
scanner.

This is a Codex-native loop with Ponytail always on: keep PowerShell 5.1
compatibility, reuse existing functions, delete duplication before inventing
helpers, and make one measurable change at a time.

## Rules

- Keep progress in `/tmp/refactor-${PROJNAME}.md`.
- Do not use production restore points as a benchmark.
- Measure local deterministic paths under fixed conditions.
- One targeted change per loop.
- After each significant step: measure, test, autoreview, commit, update the
  tracker.

## Setup

```bash
PROJNAME=$(basename "$PWD")
TRACKER="/tmp/refactor-${PROJNAME}.md"
```

```bash
[ -f "$TRACKER" ] || cat > "$TRACKER" <<EOF
# Refactor Loop - $PROJNAME
Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Target: cleaner scanner architecture and deterministic local paths under 50 ms where feasible
## Goals
- Clean, modular scanner flow
- No duplicated quoting, timeout, logging, or path logic
- Deterministic local hot paths measured after each change
- Ponytail defaults: delete, simplify, reuse
## Baseline
(record first measurements before editing)
## Progress
EOF
```

## Measurement Protocol

This repo is not a web app. Measure deterministic scanner hot paths and helper
functions instead of pretending HTTP endpoints exist.

Keep conditions fixed:

- same PowerShell host per comparison
- same YARA availability state
- same fixture or mock inputs
- five runs per measurement
- median, not mean

Suggested baseline set:

```powershell
Measure-Command { pwsh -Command "$env:VEEAM_YARA_NOEXEC=1; . .\Veeam-YARA-SecureRestore.ps1; Parse-YARAOutput -Output (Get-Content ./tests/fixtures/yara_output/real_tor_c2.txt -Raw) -VolumeRoot 'E:\' -VMName 'vm1'" }
Measure-Command { pwsh -Command "$env:VEEAM_YARA_NOEXEC=1; . .\Veeam-YARA-SecureRestore.ps1; Get-ScanTargets -VolumeRoot 'E:\'" }
pwsh -Command "Invoke-Pester -Path ./tests/Unit.PS1Logic.Tests.ps1 -Output None"
```

If the step targets another path, switch to the matching function or test and
record why.

Pass/fail gate:

- The targeted owned paths should trend toward sub-50 ms medians where feasible.
- If the remaining floor is host startup, real YARA process cost, or external
  file-system latency, document that ceiling explicitly in the tracker instead
  of faking success.

## Loop

1. Assess
   - Look for duplicated quoting/path handling, repeated directory scans,
     overgrown functions, mixed parsing/logging/orchestration, rule/test drift,
     or worker bootstrap overhead.
2. Pick one change
   - Prefer deleting duplication, extracting one bounded helper, reducing
     repeated file-system or rule loads, or tightening worker setup.
3. Execute
   - Keep the diff focused.
4. Measure
   - Re-run the same measurement set.
5. Live-test correctness
   - `pwsh -File tests/Invoke-Tests.ps1 -InstallPester` for broad behavior
   - narrower `Invoke-Pester` path for the changed area when possible
6. Autoreview
   - Review the diff in REVIEW MODE.
   - Prioritize findings broad optimizer passes often miss here:
     - PowerShell 5.1 compatibility breaks
     - worker bootstrap cost
     - repeated rule or file-system scans
     - parser/logging choke points
     - code that can be removed instead of wrapped
7. Commit
   - `git add -p`
   - `git commit -m "refactor: <what changed and why>"`
   - Use `perf:` when the step is mainly a measured speed gain.
8. Update tracker
   - Record target, change, measurements, tests, autoreview outcome, commit hash

## Stop Criteria

Stop when all are true:

- The scanner paths you touched have one obvious owner each.
- Parsing, logging, timeout, and orchestration concerns are not tangled without
  reason.
- Targeted tests pass.
- Latest autoreview finds no correctness issues worth fixing first.
- Deterministic owned hot paths are under 50 ms for two consecutive runs, or a
  documented host/process floor is the only remaining limit.

Append:

```md
## Final State
Completed: <timestamp>
Summary: <what improved>
Ceilings: <anything still above target and why>
```
