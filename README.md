# Powershell + YARA Rules: <a href="https://community.veeam.com/blogs-and-podcasts-57/veeam-malware-detection-a-forensics-analysis-how-to-guide-7829?tid=7829&fid=57">Enhanced filepath Output w/ hostname</a> for <a href="https://helpcenter.veeam.com/docs/vbr/userguide/scan_backup_yara_log.html?ver=13">VBR/VDPA </a>
Onion Link & Ransomware Detection [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Veeam YARA Detection](https://i.imgur.com/pEXT1rt.png)
The owner reported working VBR 12 and Windows PowerShell 5.1 deployment in [issue #25](https://github.com/cgfixit/Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links/issues/25). Current automated tests exercise simulated mount targets and real YARA; they do not establish production VBR restore behavior.
A comprehensive malware detection system combining YARA rules with PowerShell automation to detect Tor `.onion` links, ransomware payment portals, and C2 configurations in Veeam backup environments.</center>

**New:** Native PowerShell scanner with detailed onion link extraction and file path reporting for Veeam Secure Restore and SureBackup workflows.

---

## 📋 Table of Contents

- [What's New](#whats-new)
- [Rules Included](#rules-included)
- [PowerShell Integration](#powershell-integration)
- [Usage](#usage)
- [Deployment Options](#deployment-options)
- [Rule Details](#rule-details)
- [Compatibility](#compatibility)
- [Deployment Guide](#deployment-guide)
- [Output Examples](#output-examples)
- [Feedback & Recommendations](#feedback--recommendations)
- [Automated Tests](#automated-tests)
- [Testing Recommendations](#testing-recommendations)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## What's New

### One script for supported Windows VBR hosts

`Veeam-YARA-SecureRestore.ps1` now selects the PowerShell host before scanning. Default `-RuntimeMode Auto` reads the installed local VBR server version and keeps or relaunches the process into the required x64 runtime. A VBR 12.3.2 server uses Windows PowerShell 5.1 even if PowerShell 7 launched the script. Supported Windows VBR 13 builds use PowerShell 7. See the exact [runtime policy](#compatibility).

The scanner accepts an explicit mounted directory through `-ScanPath`, resolves quick-scan wildcards, extracts onion links, and writes JSON reports. Paths in reports identify files on the scanning host. The scanner does not reconstruct original guest drive letters.

### Incomplete scans return an error

A missing target or rule, failed discovery, inaccessible volume probe, YARA error, timeout, worker failure, or failed report write returns **exit 2**. Scanner-owned enumeration records inaccessible descendants and rejects descendant links/reparse points. These make the result incomplete even when YARA itself returns zero. Findings already collected are retained in error reports. Successful scans return 0 without matches or 1 with matches. These codes become restore decisions only through the caller's configured policy.

The [test suite](tests/README.md) covers host selection, relaunch arguments, real YARA matching, process failures, and simulated mounted directories. Its runner reports the current test count and writes NUnit results.

---

## Rules Included

- **comprehensive_onion_detection** - Detects Tor `.onion` links with ransomware context (ransom notes, payment instructions)
- **onion_links_simple** - Broad detection of any Tor `.onion` links (1 MB filesize cap; excludes common FP strings such as Tor Browser documentation and security research)
- **ransomware_payment_portal** - Identifies payment portals using `.onion` addresses with urgency indicators
- **tor_c2_configuration** - Detects C2 configuration patterns referencing Tor hidden services
- **i2p_malware_indicator** - Detects I2P `.i2p` / `.b32.i2p` hidden-service addresses in ransomware/C2 context (severity: HIGH)
- **freenet_darknet_indicator** - Detects Freenet `CHK@`/`SSK@`/`USK@`/`KSK@` URI patterns in malicious context (severity: MEDIUM)

---

## PowerShell Integration

### Execution flow

```text
A scheduled task, manual invocation, or configured Veeam scan command
    -> Veeam-YARA-SecureRestore.ps1
    -> local VBR version + PowerShell check, or explicit Standalone mode
    -> at most one relaunch into a compatible x64 PowerShell host
    -> supplied mounted directories, or Windows volume discovery
    -> real YARA scans and JSON report
    -> exit 0, 1, or 2 returned to the caller
```

Auto mode reads the Registry64 Veeam `CorePath` and the file version of `Veeam.Backup.Service.exe`. It requires a local Windows VBR server installation; a console-only installation is insufficient. Missing, unsupported, or unreadable version data stops execution before scanning. The script does not infer the backup server version from a managed host returned by `Get-VBRServer`.

Relaunch preserves the supplied parameters, switches, arrays, working directory, and final exit code. The child verifies the runtime again and refuses a second relaunch. No profile is loaded, no runtime is installed automatically, and no caller execution policy is changed.

### PowerShell launched from the VBR menu

Veeam documents that opening PowerShell through the VBR console calls `Connect-VBRServer` automatically. This explains why a script that depends on an existing Veeam session can behave differently when a scheduled task launches a fresh shell. It does not make the menu a prerequisite for unattended execution. See [Connect-VBRServer](https://helpcenter.veeam.com/docs/vbr/powershell/connect-vbrserver.html).

**This scanner does not import the Veeam module or call a VBR API.** It reads local installation metadata, scans mounted files with YARA, and writes local output. It needs neither the console menu nor a Veeam connection. Mounting backups and configuring restore decisions remain the responsibility of the caller.

If separate orchestration code calls Veeam cmdlets, initialize its session explicitly in a vendor-supported PowerShell runtime with the matching Veeam console/module installed. This example uses the current Windows identity and does not run the scanner:

```powershell
Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
Connect-VBRServer -Server 'vbr.example.internal' -ErrorAction Stop
try {
	Get-VBRBackup
} finally {
	Disconnect-VBRServer
}
```

The execution identity needs the appropriate Veeam permissions for that separate orchestration. Installing the console and connecting are documented in [Running Veeam Backup PowerShell on Windows](https://helpcenter.veeam.com/docs/vbr/powershell/running_ps_sessions_windows.html).

`Add-VBRJobLogEvent` is an optional custom hook, not a documented native VBR 13 capability. Normal scanner output is stdout, a text log, and a JSON report.

---

## Usage

### Prerequisites

**On the Windows machine that can read the mounted restore data:**

Use a runtime from the [compatibility policy](#compatibility) for Auto mode. On a separate mount server without the VBR server installation, select `-RuntimeMode Standalone` and supply `-ScanPath`.

1. **Install YARA for Windows (v4.4+)**

```powershell
# Download from https://github.com/VirusTotal/yara/releases
# Extract to C:\Program Files\YARA\
# Verify installation
& "C:\Program Files\YARA\yara64.exe" --version
```

2. **Create YARA rules directory**

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\YARA\Rules" -Force
```

3. **Download YARA rule file**

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/main/yara-malware-detection.yara" `
                  -OutFile "C:\ProgramData\YARA\Rules\yara-malware-detection.yara"
```

4. **Download PowerShell scanner**

```powershell
New-Item -ItemType Directory -Path "C:\Scripts" -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/main/Veeam-YARA-SecureRestore.ps1" `
                  -OutFile "C:\Scripts\Veeam-YARA-SecureRestore.ps1"
```

---

## Deployment Options

### Manual or scheduled execution on the local VBR server

Launch the same scanner file from an installed PowerShell host. Auto mode checks the actual process edition, version, architecture, and release status before scanning. A VBR 12.3.2 host with both shells selects x64 Windows PowerShell 5.1. A supported VBR 13 host with only PowerShell 7 can start directly in `pwsh.exe`.

```powershell
# Check the local VBR policy and selected runtime without scanning.
& 'C:\Scripts\Veeam-YARA-SecureRestore.ps1' -PreflightOnly

# Scan an already mounted restore directory from Windows PowerShell.
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
	-NoLogo -NoProfile -NonInteractive -File 'C:\Scripts\Veeam-YARA-SecureRestore.ps1' `
	-ScanPath 'C:\VeeamFLR\PROD-DC01' -SessionId 'PROD-DC01'

# The same entry point from an installed PowerShell 7 host.
& 'C:\Program Files\PowerShell\7\pwsh.exe' `
	-NoLogo -NoProfile -NonInteractive -File 'C:\Scripts\Veeam-YARA-SecureRestore.ps1' `
	-ScanPath 'C:\VeeamFLR\PROD-DC01' -SessionId 'PROD-DC01'
```

Deploy the script and rules to paths that the execution identity can read. Give that identity access to the mounted files and a writable report directory. Configure the caller to preserve the native exit code. For a wrapper script, capture `$LASTEXITCODE` immediately after the scanner finishes and return it with `exit`.

`-PreflightOnly` emits JSON for the selected host and installed VBR version, then exits. It may relaunch into the required host. It does not validate YARA, rules, mount access, reports, or a Veeam connection.

### Separate Windows mount server

Use Standalone mode when the scanner runs on a Windows mount server that does not have the local VBR server installation. This mode keeps the current PowerShell process and skips VBR version detection. It does not select a runtime for separate Veeam cmdlet orchestration.

```powershell
& 'C:\Scripts\Veeam-YARA-SecureRestore.ps1' -RuntimeMode Standalone `
	-ScanPath 'C:\VeeamFLR\PROD-DC01' `
	-YaraPath 'C:\Program Files\YARA\yara64.exe' `
	-YaraRulesPath 'C:\ProgramData\YARA\Rules' `
	-LogPath 'D:\ScanReports' -ExecutionMode Sequential
```

Use `-ScanPath` for the exact mounted directory supplied by your workflow. Without it, the scanner discovers non-system NTFS/ReFS drive-letter volumes with Windows or Users directories. That heuristic does not prove a volume belongs to a particular Veeam session and cannot discover every mount layout. Supply each approved mounted disk root explicitly when a parent directory contains junctions: descendant links are rejected, while the starting root is explicitly authorized by the caller. Use stable, read-only restore mounts; this path-based scanner does not provide handle-level protection against concurrent privileged replacement of mount paths. QuickScan filters files beneath each supplied disk root and reports an error when no files match its selected subdirectories.

### Secure Restore antivirus configuration

Veeam's documented CLI integration uses `AntivirusInfos.xml` on the mount server. During Secure Restore or Scan Backup, `%Path%` becomes the directory containing mounted disks. Pass that value to `-ScanPath` and map this script's exits to `Success=0`, `Infected=1`, and `Error=2`. See [Antivirus Configuration File](https://helpcenter.veeam.com/docs/vbr/userguide/av_scan_xml.html).

The following is an illustrative entry for a **separate Windows mount server with PowerShell 7 installed**. Merge it into the existing `<Antiviruses>` document after reviewing the installed Veeam version's schema. Use the installed PowerShell executable path. For a mount server that is also the local VBR server, change `Standalone` to `Auto`.

```xml
<AntivirusInfo Type="Windows" Name="YARA mounted-file scanner"
	IsPortableSoftware="true"
	ExecutableFilePath="C:\Program Files\PowerShell\7\pwsh.exe"
	CommandLineParameters="-NoLogo -NoProfile -NonInteractive -File &quot;C:\Scripts\Veeam-YARA-SecureRestore.ps1&quot; -RuntimeMode Standalone -ScanPath &quot;%Path%&quot;"
	RegPath="" ServiceName="" ThreatExistsRegEx=""
	IsParallelScanAvailable="false" OutputSupported="true">
	<ExitCodes>
		<ExitCode Type="Success" Description="Selected rules completed without matches">0</ExitCode>
		<ExitCode Type="Infected" Description="Selected rules matched files">1</ExitCode>
		<ExitCode Type="Error" Description="Scan incomplete or report unavailable">2</ExitCode>
	</ExitCodes>
</AntivirusInfo>
```

Keep a copy of the customization because Veeam upgrades can replace the file. Test the entry against a disposable restore point, including exit 2, before relying on the resulting restore decision. This repository does not claim live acceptance of this XML example. See the [vendor configuration guidance](https://helpcenter.veeam.com/docs/vbr/userguide/av_scan_xml.html).

SureBackup orchestration must likewise provide a directory that is actually mounted and readable on the machine running this script. A booted virtual-lab VM is not automatically a mounted host directory.

### Scan options and exit codes

| Option | Behavior |
|--------|----------|
| `-RuntimeMode Auto` | Default. Enforces the local Windows VBR policy before scanning. |
| `-RuntimeMode Standalone` | Keeps the current PowerShell host without VBR detection. |
| `-PreflightOnly` | Reports runtime selection as JSON without scanning or creating scan logs. |
| `-ScanPath` | One or more existing filesystem directories. A missing directory is an error. |
| `-QuickScan` | Expands selected high-risk subdirectories beneath each scan root. It deliberately reduces coverage. |
| `-ExecutionMode Auto` | Uses ThreadJob if available, otherwise Job, otherwise Sequential in the selected host. |
| `-ExecutionMode Sequential`, `Job`, or `ThreadJob` | Forces that execution tier. An unavailable requested tier is an error. |
| `-ScanTimeout` | Per-YARA-process limit in seconds, from 1 through 86400. Default 3600. |
| `-SessionId` | Identifier included in report and log filenames. |

| Exit | Meaning |
|------|---------|
| `0` | Every selected scan completed, the report was written, and no selected rule matched. This is not a malware-free guarantee. |
| `1` | The completed scan found matches and wrote the report. |
| `2` | Runtime selection failed, the scan was incomplete, or the report could not be written. Treat this as a failed scan. |

The raw YARA CLI returns 0 for both successful matches and successful no-match scans. A raw YARA exit 1 is an error. The scanner derives its exit 1 from parsed findings, not from YARA's exit 1.

---

## Output Examples

### Console Output (Infected Detection)

Illustrative output. `WindowsPath` retains the mounted path; it does not recover the original guest drive letter. Explicit scan roots use `VMName=ExplicitTarget`.

```
[2024-12-23 14:32:54] [WARNING] ⚠️⚠️⚠️  ONION LINKS DETECTED - INFECTED FILES  ⚠️⚠️⚠️

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VM: PROD-DC01
Windows Path: E:\Users\Administrator\Documents\README_DECRYPT.txt
  Matched Rules: Ransomware_Onion_Link
  🔴 Onion Links: http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion
  Other Matches: Your files have been encrypted
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VM: PROD-DC01
Windows Path: E:\ProgramData\recovery_instructions.html
  Matched Rules: Ransomware_Onion_Link
  🔴 Onion Links: http://ransomleak5xyz.onion/payment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  ACTION REQUIRED: Review infected files before restoring!
Full report: C:\ProgramData\Veeam\Logs\YARA-SecureRestore\results_Secure_Restore_20241223_143215.json
```

### JSON Report Structure

Illustrative excerpt. Current reports also include execution mode, PowerShell version, scan scope, and runtime-selection metadata.

**Location:** `C:\ProgramData\Veeam\Logs\YARA-SecureRestore\results_[JobID]_[Timestamp].json`

```json
{
  "ScanTimestamp": "2024-12-23T14:32:54.1234567-05:00",
  "JobId": "Secure_Restore_20241223_143215",
  "TotalMatches": 2,
  "UniqueFiles": 2,
  "YaraVersion": "4.5.4",
  "Status": "Completed",
  "Errors": [],
  "Findings": [
    {
      "VMName": "PROD-DC01",
      "WindowsPath": "E:\\Users\\Administrator\\Documents\\README_DECRYPT.txt",
      "MountedPath": "E:\\Users\\Administrator\\Documents\\README_DECRYPT.txt",
      "MatchedRules": "Ransomware_Onion_Link",
      "OnionLinks": "http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion",
      "MatchedStrings": "http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion | Your files have been encrypted",
      "RuleCount": 1
    },
    {
      "VMName": "PROD-DC01",
      "WindowsPath": "E:\\ProgramData\\recovery_instructions.html",
      "MountedPath": "E:\\ProgramData\\recovery_instructions.html",
      "MatchedRules": "Ransomware_Onion_Link",
      "OnionLinks": "http://ransomleak5xyz.onion/payment",
      "MatchedStrings": "http://ransomleak5xyz.onion/payment | Bitcoin payment required",
      "RuleCount": 1
    }
  ]
}
```

### Report and caller integration

Console text and report files are the scanner's output. Veeam displays scan status only when its configured integration consumes that output and the exit code. The scanner does not create Veeam job-log events or change restore policy by itself.

Reports use `Status=Completed` for a finished scan and `Status=Error` with an error message after a scan failure. A runtime preflight failure occurs before report initialization. If the report path is unwritable, exit 2 remains the authoritative failure signal even when an error report cannot be saved.

---

## Rule Details

### 1. comprehensive_onion_detection

```yara
rule comprehensive_onion_detection {
    meta:
        description = "Detects Tor .onion links with ransomware context"
        author      = "CG"
        severity    = "HIGH"
        category    = "TOR_RANSOMWARE"
    strings:
        $v2_onion     = /[a-z2-7]{16}\.onion[\/\w.\-?=&]*/
        $v3_onion     = /[a-z2-7]{56}\.onion[\/\w.\-?=&]*/
        $http_onion   = /https?:\/\/[a-z2-7]{16,56}\.onion/
        $tor_protocol = /tor:\/\/[a-z2-7]{16,56}\.onion/

        $ransom1  = "ransom"    ascii wide nocase
        $ransom2  = "encrypted" ascii wide nocase
        $ransom3  = "decrypt"   ascii wide nocase
        $payment  = "payment"   ascii wide nocase
        $bitcoin  = /(bitcoin|btc)/i

        $note1 = "READ"    fullword ascii nocase
        $note2 = "HOW_TO"  nocase
        $note3 = "DECRYPT" ascii wide nocase

    condition:
        1 of ($v2_onion,$v3_onion,$http_onion,$tor_protocol) and
        filesize < 26214400 and
        (
            any of ($ransom*) or $payment or $bitcoin or
            2 of ($note*)
        )
}
```

**Purpose:** Context-rich ransomware detection combining .onion addresses with ransom-related keywords.

**Triggers on:**

- v2/v3 .onion addresses (16 or 56 characters)
- HTTP(S) and tor:// protocols
- Ransomware keywords: "ransom", "encrypted", "decrypt", "payment", "bitcoin"
- Ransom note indicators: "READ", "HOW_TO", "DECRYPT"

---

### 2. onion_links_simple

```yara
rule onion_links_simple {
    meta:
        description = "Detects any Tor .onion links (broad detection)"
        author      = "CG"
        severity    = "MEDIUM"
        category    = "TOR_INDICATOR"
    strings:
        $onion2 = /[a-z2-7]{16}\.onion/
        $onion3 = /[a-z2-7]{56}\.onion/
    condition:
        any of them and filesize < 52428800
}
```

**Purpose:** Broad IOC sweep for any .onion address.

**Triggers on:**

- Any v2 or v3 .onion address
- **Warning:** May produce false positives on privacy guides, Tor documentation, or academic papers.

> **Note:** The rule shown above is simplified for illustration. The current version in `yara-malware-detection.yara` uses a 1 MB filesize cap and includes false-positive exclusion strings (Tor Browser, privacy guide, Tails, onion service, hidden service, OSINT, threat intelligence, security research). See the rule file for the full text.

---

### 3. ransomware_payment_portal

```yara
rule ransomware_payment_portal {
    meta:
        description = "Detects ransomware payment portals with onion links"
        author      = "CG"
        severity    = "CRITICAL"
        category    = "RANSOMWARE_C2"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/

        $pay1 = /\bpay\b/i
        $pay2 = "payment"        nocase
        $pay3 = "bitcoin wallet" nocase
        $pay4 = /btc/i
        $pay5 = /bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,59}/

        $dec1 = "decrypt"        nocase
        $dec2 = "decryption key" nocase
        $dec3 = "unlock"         nocase

        $urg1 = "deadline" nocase
        $urg2 = "hours"    nocase
        $urg3 = "days left" nocase

    condition:
        filesize < 18612019 and
        $onion and
        ( 2 of ($pay*) or 2 of ($dec*) ) and
        any of ($urg*)
}
```

**Purpose:** Identifies ransomware payment portals with urgency indicators.

**Triggers on:**

- .onion address presence
- Payment/decryption context (2+ matches required)
- Urgency indicators ("deadline", "hours", "days left")
- Bitcoin addresses (Bech32 format)

---

### 4. tor_c2_configuration

```yara
rule tor_c2_configuration {
    meta:
        description = "Detects C2 configs with Tor hidden service endpoints"
        author      = "CG"
        severity    = "CRITICAL"
        category    = "C2_COMMUNICATION"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/

        $c2_1 = /c2[_-]?server/i
        $c2_2 = /command[_-]?server/i
        $c2_3 = /control[_-]?server/i
        $c2_4 = "callback" nocase
        $c2_5 = "beacon"   nocase
        $c2_6 = "endpoint" nocase

        $cfg1 = /"url"\s*:/
        $cfg2 = /"endpoint"\s*:/
        $cfg3 = /"server"\s*:/

    condition:
        filesize < 52428800 and
        $onion and
        any of ($c2_*) and
        any of ($cfg*)
}
```

**Purpose:** Detects C2 configuration files using Tor hidden services.

**Triggers on:**

- .onion address presence
- C2-related keywords ("c2_server", "callback", "beacon", etc.)
- Configuration file indicators (JSON key patterns)

---

## Compatibility

Auto mode supports the following **Windows VBR runtime policy**. Every selected host must be x64 and a stable release.

| Local Windows VBR version | Required PowerShell process | Source for the policy |
|---------------------------|-----------------------------|-----------------------|
| `12.3.2.x` | Windows PowerShell 5.1, Desktop edition | [V12 reference, current archived build 12.3.2.4854](https://helpcenter.veeam.com/archive/backup/120/powershell/getting_started.html) |
| `13.0.x` from `13.0.1.180` | PowerShell 7, Core edition, version `7.4.13` or later | [Windows V13.0.1 release notes](https://helpcenter.veeam.com/rn/veeam_backup_13_0_1_release_notes.html) |
| `13.1.x` | PowerShell 7, Core edition, version `7.6.3` or later | [Current V13.1 PowerShell requirements](https://helpcenter.veeam.com/docs/vbr/powershell/running_ps_sessions_windows.html) |

These are conservative project floors based on the cited documentation, not a claim about the minimum accepted by every historical build. The V13.1 source applies to build 13.1.1.18. Unknown families, including 13.2, and Windows V13 builds below 13.0.1.180 are rejected rather than guessed. Veeam distinguishes Windows releases from the earlier software appliance release in [KB4738](https://www.veeam.com/kb4738).

Auto mode checks the local server installation and cannot discover a remote server's version from a console-only machine. It does not support the Linux Veeam Software Appliance. Standalone mode runs the scanner in the existing PowerShell host without claiming Veeam cmdlet compatibility.

- YARA 4.4 or later is the deployment target. Real-engine tests exercise the rule pack with the installed CLI.
- Use a Windows version supported by the installed VBR release for production deployment.
- The owner reported historical VBR 12 and PowerShell 5.1 success in [issue #25](https://github.com/cgfixit/Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links/issues/25). That report is distinct from current automated tests.
- Local macOS tests run real PowerShell 7 and YARA against simulated mount targets. Native Windows CI exercises PowerShell 5.1 and 7 with temporary VBR metadata fixtures. Neither substitutes for a live VBR Secure Restore acceptance run. Inspect the specific CI run and uploaded NUnit results before claiming a pass.

**Note:** Comments using `//` in YARA rules may cause errors in some Veeam contexts - use `/* */` style if issues occur.

---

## Deployment Guide

### Install and check the runtime

```powershell
# 1. Install YARA
# Download from https://github.com/VirusTotal/yara/releases
# Extract to C:\Program Files\YARA\

# 2. Create directories
New-Item -ItemType Directory -Path "C:\ProgramData\YARA\Rules" -Force
New-Item -ItemType Directory -Path "C:\Scripts" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\Veeam\Logs\YARA-SecureRestore" -Force

# 3. Download files
$baseUrl = "https://raw.githubusercontent.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/main"
Invoke-WebRequest -Uri "$baseUrl/yara-malware-detection.yara" `
                  -OutFile "C:\ProgramData\YARA\Rules\yara-malware-detection.yara"
Invoke-WebRequest -Uri "$baseUrl/Veeam-YARA-SecureRestore.ps1" `
                  -OutFile "C:\Scripts\Veeam-YARA-SecureRestore.ps1"

# 4. Test installation
& "C:\Program Files\YARA\yara64.exe" --version
& "C:\Scripts\Veeam-YARA-SecureRestore.ps1" -PreflightOnly

# 5. Scan a disposable mounted target, then configure the caller
& "C:\Scripts\Veeam-YARA-SecureRestore.ps1" -ScanPath "C:\VeeamFLR\LabVM"
```

### Security Hardening

```powershell
# Restrict script execution to Veeam service accounts
$acl = Get-Acl "C:\Scripts\Veeam-YARA-SecureRestore.ps1"
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

# Add Veeam service account (adjust username)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "DOMAIN\VeeamService", "ReadAndExecute", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\Scripts\Veeam-YARA-SecureRestore.ps1" $acl
```

---

## Feedback & Recommendations

### Why Use This?

- Rules detect selected onion and ransomware-context indicators, including content that warrants manual review.
- Callers can use the documented exit codes to enforce their scan policy.
- JSON reports retain mounted file paths and extracted links for investigation.
- Detection coverage and false positives depend on the selected rules and scan scope.

### Improvements Implemented

#### 1. Filesize Syntax Consistency

Replaced MB suffix with explicit byte values for universal YARA compatibility:

- 25 MB = 26214400 bytes
- 50 MB = 52428800 bytes
- 17.75 MB = 18612019 bytes (optimized for performance)

#### 2. Performance Optimization

- Moved filesize checks to beginning of conditions for faster short-circuiting
- Quick scan mode targets common ransomware locations:
  - `Users\*\Documents`
  - `Users\*\Desktop`
  - `Users\*\Downloads`
  - `Users\*\AppData\Local\Temp`
  - `Windows\Temp`
  - `ProgramData`

#### 3. Enhanced String Extraction

- PowerShell parser extracts actual .onion URLs (not just detection)
- Supports v2 (16 char) and v3 (56 char) onion addresses
- Handles HTTP(S) and tor:// protocols

### Additional Recommendations

#### Bitcoin Address Enhancement

Add legacy Bitcoin address formats for broader cryptocurrency detection:

```yara
$btc_legacy = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
$btc_segwit = /\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,87}\b/
```

#### Monero (XMR) Addresses

Many ransomware groups now prefer Monero for anonymity:

```yara
$xmr_addr = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
```

#### SIEM Integration

Ingest JSON reports into your SIEM for centralized monitoring:

```powershell
$jsonContent = Get-Content "C:\ProgramData\Veeam\Logs\YARA-SecureRestore\results_*.json" | ConvertFrom-Json
Invoke-RestMethod -Uri "https://splunk.company.com:8088/services/collector" `
                  -Method Post `
                  -Headers @{"Authorization"="Splunk YOUR_HEC_TOKEN"} `
                  -Body ($jsonContent | ConvertTo-Json -Depth 10)
```

---

## Automated Tests

The [test suite](tests/README.md) uses pinned Pester 5.7.1 and the real YARA CLI. It covers runtime policy, native relaunch arguments and exit propagation, scanner entry points, all execution tiers, parser behavior, report persistence, and rule fixtures. The runner prints the current test count.

```powershell
pwsh -NoProfile -File tests/Invoke-Tests.ps1 -InstallPester `
	-RequireYara -FailOnSkipped -ResultsPath testresults.xml
```

On Windows, run the full suite only on an isolated elevated test runner without an installed VBR registry key. Set `VEEAM_TEST_PWSH_PATH` to an installed x64 PowerShell 7.6.3+ executable first. Native tests temporarily register versioned VBR metadata and launch real PowerShell 5.1 and 7 processes. See [Windows test prerequisites](tests/README.md#windows-native-runtime-tests).

Most unit tests dot-source the scanner with `VEEAM_YARA_NOEXEC=1`. Entry-point tests launch real child processes against synthetic mounted directories. Mock version labels do not prove vendor compatibility, and optional logging-hook tests do not claim that VBR supplies `Add-VBRJobLogEvent`.

[`.github/workflows/tests.yml`](.github/workflows/tests.yml) defines the CI matrix and uploaded results. Required CI runs fail when YARA is absent or tests skip. Non-Windows runs omit the Windows-only registry tests entirely; a zero-skip macOS or Linux result is not a native Windows result.

---

## Testing Recommendations

### False Positive Testing

Run against:

- Tor Project documentation (torproject.org)
- Privacy-focused websites (EFF, PrivacyGuides)
- Academic papers on anonymity networks
- Security blogs discussing Tor/darknet

### True Positive Validation

Test against:

- Known ransomware samples from [MalwareBazaar](https://bazaar.abuse.ch/)
- Ransom note templates (Conti, LockBit, BlackCat, REvil, ALPHV)
- C2 configuration files from public malware analysis reports

#### End-to-End Secure Restore Emulation (Chrome History Onion IOC)

Use a disposable restore point to assess the selected rules against a known indicator. The automated suite does not establish live restore blocking. A browser-history file may exceed a rule's size limit, and QuickScan does not cover the Chrome history location.

1. Create a test restore point from a VM containing a known `.onion` string under:
   - `C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History`
   - If testing with environment variables, use `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (not `D:\%localappdata&\...`, which is malformed).
2. Mount that restore point through the supported Veeam workflow and record its actual directory on the Windows mount server.
3. Verify scanner prerequisites on the mount server:
   - `C:\Program Files\YARA\yara64.exe`
   - At least one `.yar`/`.yara` file in `C:\ProgramData\YARA\Rules`
4. Run full scan mode (do **not** use `-QuickScan` for this scenario):
   ```powershell
   .\Veeam-YARA-SecureRestore.ps1 -RuntimeMode Standalone -ScanPath "C:\VeeamFLR\LabVM"
   ```
5. Review output in `C:\ProgramData\Veeam\Logs\YARA-SecureRestore\`:
   - `scan_*.log` for per-file detections
   - `results_*.json` for structured findings, extracted onion links, and mounted paths
6. Validate expected exit behavior:
   - `1` = rules matched; verify that the configured Veeam policy handles this as infected.
   - `0` = no selected rule matched within the completed scan scope.
   - `2` = scan failed; verify that the configured integration treats this as an error.

#### Create Synthetic Test Files

```powershell
# Test file with onion link + ransomware context
@"
Your files have been encrypted!
To decrypt your data, visit our payment portal:
http://darknetpay7x3k2.onion/recover

Bitcoin wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Deadline: 48 hours
"@ | Out-File "C:\Test\README_DECRYPT.txt"

# Scan the directory containing the synthetic test file
.\Veeam-YARA-SecureRestore.ps1 -RuntimeMode Standalone -ScanPath "C:\Test"
```

### Performance Benchmarking

```powershell
# Measure scan time
Measure-Command {
    .\Veeam-YARA-SecureRestore.ps1 -RuntimeMode Standalone -ScanPath "E:\" -QuickScan
}

# Profile YARA performance
& "C:\Program Files\YARA\yara64.exe" -p 4 -r -s `
  "C:\ProgramData\YARA\Rules\yara-malware-detection.yara" `
  "E:\"
```

---

## Troubleshooting

### Common Issues

#### 1. "YARA not found at C:\Program Files\YARA\yara64.exe"

```powershell
# Verify YARA installation
Test-Path "C:\Program Files\YARA\yara64.exe"

# If false, reinstall from https://github.com/VirusTotal/yara/releases
```

#### 2. "No YARA rules found in C:\ProgramData\YARA\Rules"

```powershell
# Verify rule file exists
Get-ChildItem "C:\ProgramData\YARA\Rules" -Filter "*.yar*"

# Re-download if missing
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/main/yara-malware-detection.yara" `
                  -OutFile "C:\ProgramData\YARA\Rules\yara-malware-detection.yara"
```

#### 3. "No volumes to scan"

```powershell
# Inspect host volumes; this does not identify a Veeam session
Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemType -in @('NTFS','ReFS') }

# Check if Windows directory exists on mounted volumes
Get-Volume | ForEach-Object {
    Test-Path "$($_.DriveLetter):\Windows"
}
```

#### 4. A scan times out

`-ScanTimeout 7200` allows up to two hours per YARA process. Also configure the caller's timeout to allow the entire scan, not just one process. A timeout returns exit 2. Use QuickScan only when its reduced directory coverage matches your intended scope.

#### 5. Runtime preflight fails during unattended execution

Run `-PreflightOnly` under the same execution identity and bitness as the scheduled scan. Confirm the VBR file version, the required x64 PowerShell installation, and read access to the installation path. Install a supported runtime through your normal deployment process. On a separate mount server with no local VBR installation, use explicit `-RuntimeMode Standalone` and `-ScanPath`.

---

## Disclaimer

These rules and scripts are provided as-is for educational, research, and defensive security purposes. Always test in a safe, controlled environment before deploying in production.

**The author is not responsible for:**

- False positives/negatives affecting business operations
- Performance impacts on Veeam infrastructure
- Any misuse or damage caused by these tools

**Recommended:** Test thoroughly in lab environment with known ransomware samples before production deployment.

---

## Contributing

Contributions welcome! Please submit:

- New YARA rules for emerging ransomware families
- Performance optimizations for PowerShell scanner
- Integration examples (SIEM, ticketing systems, etc.)
- Bug reports with sanitized logs

---

## Metadata

- **Author:** CG [[@cgfixit]](https://linktr.ee/cgrady92)
- **Category:** Ransomware Detection, Tor/Onion IOCs, C2 Detection
- **License:** MIT
- **Last Updated:** September 2026

---

## Quick Links

- [YARA Documentation](https://yara.readthedocs.io/)
- [Veeam Secure Restore Guide](https://helpcenter.veeam.com/docs/vbr/userguide/malware_detection_scan_backup_yara.html)
- [GitHub Repository](https://github.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links)
- [Report Issues](https://github.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/issues)
