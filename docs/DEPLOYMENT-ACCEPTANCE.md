# Deployment acceptance for Windows VBR

The deployable scanner remains one PowerShell script. Its Auto policy already selects Windows PowerShell 5.1 for VBR 12.3.2, PowerShell 7.4.13+ for Windows VBR 13.0.1.180 and later 13.0, and PowerShell 7.6.3+ for 13.1. Unknown families fail closed. See the maintained [compatibility table and official sources](../README.md#compatibility); do not assume future V13 releases preserve these requirements.

The scanner does not invoke Veeam cmdlets. A console-menu shell has an automatically connected Veeam session; a scheduled shell does not. Separate mount/orchestration code must import the matching module and call `Connect-VBRServer` explicitly. Do not add a Veeam connection merely to scan already mounted files.

## Before production use

1. Record the candidate commit, scanner SHA256, rule-pack SHA256, YARA version, Windows build, local VBR binary version, execution identity and PowerShell executable/version/bitness. Use the exact candidate deployed to the mount server.
2. Run `-PreflightOnly` in a fresh, noninteractive process under the intended identity. On V12 with PS5.1 and PS7 installed, exercise both launchers and verify the selected host is PS5.1. On Windows V13 with only supported PS7 installed, invoke that PS7 directly. Preflight validates runtime selection only; it does not validate mount access, YARA or restore policy.
3. Mount a disposable test backup using the supported Veeam workflow. Identify each authorized disk root. An explicit root is trusted even if it is a mount point; descendant links/reparse points are rejected. A parent containing disk junctions is not automatically traversed. Do not grant new permissions or follow links just to obtain a clean result.
4. Run a full scan with explicit paths, `-RequireExplicitScanPath`, a log path outside the mount, and the same identity used by Veeam. Use a stable, read-only mount. Path comparisons are not handle-level protection against concurrent privileged path replacement or directory aliases.
5. Exercise the acceptance cases below. Retain stdout, stderr, exit code and JSON together. Inspect `Status`, `Errors`, `Coverage`, `Scope`, `Runtime`, `RuleEvidence`, and `NotificationStatus`; a zero exit alone is insufficient deployment evidence.
6. Configure the candidate command in `AntivirusInfos.xml` on the mount server after backing up the existing configuration. Preserve the mapping `Success=0`, `Infected=1`, `Error=2`. These are Veeam configuration labels: an indicator match is not an infection verdict. Verify caller behavior for all three exits in an isolated restore, especially that exit 2 cannot allow an unscanned restore.
7. Enable optional notifications only after report persistence and caller mapping pass. UDP submission is not delivery acknowledgement; verify the receiver separately. The Veeam ONE prototype records `Unsupported` and creates no alarm.

## Required cases

| Case | Required observation |
| --- | --- |
| Readable clean fixture | Exit 0, completed coverage, zero selected-rule matches |
| Known malicious indicator fixture | Exit 1, original evidence and metadata retained; analyst review required |
| Clean first root, unreadable descendant on another root | Exit 2, explicit access error; no clean coverage claim |
| Match first root, error later root | Exit 2 and earlier findings retained |
| Descendant symlink/junction | Exit 2; no outside target is scanned |
| Malformed rule, missing YARA or timeout | Exit 2; actionable report/log where storage is available |
| Report directory inside scan target | Exit 2 before scanning; choose an external log path |
| Missing explicit path with deployment guard | Exit 2; heuristic discovery does not run |
| Notification failure/unsupported integration | Completed match remains exit 1; persisted evidence and separate notification status |
| QuickScan | Recorded Quick scope; only selected paths; not interchangeable with the full-scan acceptance |

Use only inert text fixtures such as `tests/fixtures`; no real malware is required. On Windows verify ACL and junction behavior using disposable directories. Do not run registry-emulation tests on a production VBR server: the hosted native tests require an isolated runner without an installed VBR registry key.

## Evidence boundaries

CI runs real YARA and native Windows PowerShell hosts with simulated VBR installation metadata and mounts. This proves the exercised code paths on those runners, not proprietary VBR assemblies, live restore mounts, caller exit mapping, or production identity permissions. Computer Use inspection of generated JSON evidence verifies the displayed report; it does not replace the live acceptance steps above. Keep the rollout draft until live acceptance is recorded by the operator.
