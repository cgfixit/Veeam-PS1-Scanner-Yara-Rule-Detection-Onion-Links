# <a href="https://community.veeam.com/blogs-and-podcasts-57/veeam-malware-detection-a-forensics-analysis-how-to-guide-7829?tid=7829&fid=57">Restore Securely!</a> - Powershell + YARA Rules: <a href="https://community.veeam.com/blogs-and-podcasts-57/veeam-malware-detection-a-forensics-analysis-how-to-guide-7829?tid=7829&fid=57">Enhanced filepath Output w/ hostname</a> for <a href="https://helpcenter.veeam.com/docs/vbr/userguide/scan_backup_yara_log.html?ver=13">VBR/VDPA </a>
Onion Link & Ransomware Detection [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Veeam YARA Detection](https://i.imgur.com/pEXT1rt.png)
Designed and tested with Veeam (SecureResore/SureBackup), but many use cases since yara is a framework that is free.
A comprehensive malware detection system combining YARA rules with PowerShell automation to detect Tor `.onion` links, ransomware payment portals, and C2 configurations in Veeam backup environments.</center>

**New:** Native PowerShell scanner with detailed onion link extraction and file path reporting for Veeam Secure Restore and SureBackup workflows.

---

## 📋 Table of Contents

- [What's New](#whats-new)
- [Rules Included](#rules-included)
- [PowerShell Integration](#powershell-integration)
- [Usage](#usage)
- [Rule Details](#rule-details)
- [Compatibility](#compatibility)
- [Deployment Guide](#deployment-guide)
- [Output Examples](#output-examples)
- [Feedback & Recommendations](#feedback--recommendations)
- [Testing Recommendations](#testing-recommendations)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## What's New

### PowerShell Scanner (`Veeam-YARA-SecureRestore.ps1`)

The native Windows scanner provides:

- **Automatic VM volume discovery** - Detects mounted VMs from Secure Restore or SureBackup
- **Onion link extraction** - Extracts actual `.onion` URLs from matched files (not just detection)
- **Windows path mapping** - Converts mount points (E:\) to original VM paths (C:\)
- **Detailed JSON reports** - Machine-readable output for SIEM/automation
- **Veeam job integration** - Exit codes that block unsafe restores automatically
- **Quick scan mode** - Target high-risk locations (ransomware hot spots)

**PowerShell 5.1 is now the primary requirement.** PS7+ is used automatically when available for in-process parallel acceleration via `ThreadJob`/`Start-Job`, falling back to sequential mode on PS5.1-only systems. Two new YARA rules (`i2p_malware_indicator` and `freenet_darknet_indicator`) expand coverage beyond Tor. Optional `-SyslogServer` / `-VeeamOneServer` parameters enable RFC-5424 syslog and Veeam ONE REST API alerting on detection.

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

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Veeam Backup & Replication Console                              │
│ ├─ Secure Restore Job (Pre-Restore Script)                      │
│ └─ SureBackup Job (Application Group Verification)              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Mount Server / SureBackup Proxy (Windows)                        │
│ ├─ C:\Program Files\YARA\yara64.exe (v4.4+)                    │
│ ├─ C:\ProgramData\YARA\Rules\yara-malware-detection.yara       │
│ └─ Veeam-YARA-SecureRestore.ps1                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Mounted VM Volumes (Auto-Detected)                              │
│ ├─ E:\ → Instant Recovery VM #1                                │
│ ├─ F:\ → SureBackup Verified VM #2                             │
│ └─ G:\ → Secure Restore Staged VM                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Output Locations                                                 │
│ ├─ Console: Job logs in VBR UI                                 │
│ ├─ Log File: C:\ProgramData\Veeam\Logs\YARA-SecureRestore\     │
│ │            scan_[JobID][Timestamp].log                        │
│ └─ JSON Report: C:\ProgramData\Veeam\Logs\YARA-SecureRestore\  │
│                results[JobID]_[Timestamp].json                 │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **VM Mount Detection** - Script discovers all mounted Windows volumes (Secure Restore/SureBackup)
2. **YARA Scan Execution** - Runs YARA with `-s` flag to extract matched strings (onion links)
3. **Path Translation** - Maps mounted drive letters (E:\) to original VM paths (C:\)
4. **Result Aggregation** - Groups findings by file with all matched onion links
5. **Exit Code Control** - Returns code to Veeam:
   - `0` = Clean (restore allowed)
   - `1` = Infected (blocks restore)
   - `2` = Script error (manual review)

---

## Usage

### Prerequisites

**On Veeam Mount Server or SureBackup Proxy (Windows):**

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
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/main/Veeam-YARA-SecureRestore.ps1" `
                  -OutFile "C:\Scripts\Veeam-YARA-SecureRestore.ps1"
```

---

## Deployment Options

### Option 1: Veeam Secure Restore (Pre-Restore Script)

**Use Case:** Scan VMs before production restore to prevent reinfection

**Configuration:**

1. Open Veeam Backup & Replication Console
2. Navigate to: `Backup Infrastructure → Backup Repositories → [Your Repository] → Properties`
3. Go to `Secure Restore` tab → `Advanced` → `Script`
4. Configure script:
   - **Script Path:** `C:\Scripts\Veeam-YARA-SecureRestore.ps1`
   - **Parameters:** `-QuickScan` (optional for faster scans)
5. Set **Failure Action:** Fail the job (critical for blocking infected restores)

**Behavior:**

- Script runs automatically during Instant Recovery or Full Restore
- Scans mounted VM volumes before they go live
- Blocks restore if onion links detected (exit code 1)
- Logs visible in restore job details

### Option 2: SureBackup Verification Scan

**Use Case:** Automated backup validation with malware scanning

**Configuration:**

1. Open Veeam Backup & Replication Console
2. Navigate to: `Jobs → SureBackup`
3. Create/Edit Application Group → `Linked Jobs → Settings`
4. Add Test Script:
   - **Test Name:** `YARA Onion Detection`
   - **Script Path:** `C:\Scripts\Veeam-YARA-SecureRestore.ps1`
   - **Script Arguments:** `-QuickScan -SessionId "%job_id%"`
5. Set **Test Timeout:** 3600 seconds (1 hour)
6. Enable **Fail job on test failure:** Yes

**Behavior:**

- Runs after VM boot/heartbeat tests complete
- Scans mounted VM volumes in isolated network
- Flags backups as infected if detections occur
- Results logged in SureBackup session details

### Manual Execution (Testing)

```powershell
# Full scan of all mounted volumes
.\Veeam-YARA-SecureRestore.ps1

# Quick scan (common malware locations only)
.\Veeam-YARA-SecureRestore.ps1 -QuickScan

# Custom YARA paths
.\Veeam-YARA-SecureRestore.ps1 -YaraPath "D:\Tools\yara64.exe" `
                                -YaraRulesPath "D:\Rules" `
                                -LogPath "D:\Logs"

# With custom session ID (for tracking)
.\Veeam-YARA-SecureRestore.ps1 -SessionId "Restore_PROD-DC01_20241223"
```

---

## Output Examples

### Console Output (Infected Detection)

```
[2024-12-23 14:32:54] [WARNING] ⚠️⚠️⚠️  ONION LINKS DETECTED - INFECTED FILES  ⚠️⚠️⚠️

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VM: PROD-DC01
Windows Path: C:\Users\Administrator\Documents\README_DECRYPT.txt
  Matched Rules: Ransomware_Onion_Link
  🔴 Onion Links: http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion
  Other Matches: Your files have been encrypted
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VM: PROD-DC01
Windows Path: C:\ProgramData\recovery_instructions.html
  Matched Rules: Ransomware_Onion_Link
  🔴 Onion Links: http://ransomleak5xyz.onion/payment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  ACTION REQUIRED: Review infected files before restoring!
Full report: C:\ProgramData\Veeam\Logs\YARA-SecureRestore\results_Secure_Restore_20241223_143215.json
```

### JSON Report Structure

**Location:** `C:\ProgramData\Veeam\Logs\YARA-SecureRestore\results_[JobID]_[Timestamp].json`

```json
{
  "ScanTimestamp": "2024-12-23T14:32:54.1234567-05:00",
  "JobId": "Secure_Restore_20241223_143215",
  "TotalMatches": 4,
  "UniqueFiles": 3,
  "YaraVersion": "4.4.0",
  "Findings": [
    {
      "VMName": "PROD-DC01",
      "WindowsPath": "C:\\Users\\Administrator\\Documents\\README_DECRYPT.txt",
      "MountedPath": "E:\\Users\\Administrator\\Documents\\README_DECRYPT.txt",
      "MatchedRules": "Ransomware_Onion_Link",
      "OnionLinks": "http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion",
      "MatchedStrings": "http://darknetpay7x3k2.onion/recover | tor2doorabcdef123.onion | Your files have been encrypted",
      "RuleCount": 1
    },
    {
      "VMName": "PROD-DC01",
      "WindowsPath": "C:\\ProgramData\\recovery_instructions.html",
      "MountedPath": "E:\\ProgramData\\recovery_instructions.html",
      "MatchedRules": "Ransomware_Onion_Link",
      "OnionLinks": "http://ransomleak5xyz.onion/payment",
      "MatchedStrings": "http://ransomleak5xyz.onion/payment | Bitcoin payment required",
      "RuleCount": 1
    }
  ]
}
```

### Veeam UI Integration

**Secure Restore Job Logs:**

```
Restore Job: PROD-DC01_Restore_20241223
Status: Failed ❌
Details: Pre-restore script exited with code 1

[View Script Output] → Shows full console output with onion links
```

**SureBackup Session:**

```
SureBackup Job: Daily_Verification
VM: PROD-DC01
  ├─ Boot: Success ✓
  ├─ Heartbeat: Success ✓
  ├─ Ping: Success ✓
  └─ YARA Onion Detection: Failed ❌
      └─ 3 infected files detected
          └─ C:\Users\Administrator\Documents\README_DECRYPT.txt
          └─ C:\ProgramData\recovery_instructions.html
          └─ C:\Windows\Temp\shadow_backup.dat
```

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

- **YARA Version:** v4.4+ (tested with 4.4.0)
- **Veeam Version:** Backup & Replication v12.x / v13.x
- **Operating System:** Windows Server 2016+ (for PowerShell scanner)
- **PowerShell:** v5.1+ primary; v7+ used automatically when available for in-process parallel acceleration via ThreadJob
- **Mount Servers:** Windows-based mount servers or SureBackup proxies

**Note:** Comments using `//` in YARA rules may cause errors in some Veeam contexts - use `/* */` style if issues occur.

---

## Deployment Guide

### Quick Start (15 Minutes)

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
& "C:\Scripts\Veeam-YARA-SecureRestore.ps1" -WhatIf

# 5. Configure in Veeam (see Deployment Options above)
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

- **Zero-day ransomware detection** - Catches new variants by IoC patterns (onion links) rather than signatures
- **Prevent reinfection** - Blocks restores of infected backups before they reach production
- **Automated validation** - Integrates with existing Veeam workflows (no manual scans)
- **Forensic evidence** - JSON reports provide exact file paths and onion links for IR teams
- **Cost-effective** - No additional licensing beyond Veeam VDP Advanced

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

Use this workflow to emulate a backup that contains an onion indicator in Chrome history data and verify restore blocking behavior:

1. Create a test restore point from a VM containing a known `.onion` string under:
   - `C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History`
   - If testing with environment variables, use `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (not `D:\%localappdata&\...`, which is malformed).
2. Mount that restore point in Secure Restore or SureBackup so the VM appears as a mounted Windows volume (for example `E:\` or `F:\`) on the mount server.
3. Verify scanner prerequisites on the mount server:
   - `C:\Program Files\YARA\yara64.exe`
   - At least one `.yar`/`.yara` file in `C:\ProgramData\YARA\Rules`
4. Run full scan mode (do **not** use `-QuickScan` for this scenario):
   ```powershell
   .\Veeam-YARA-SecureRestore.ps1
   ```
5. Review output in `C:\ProgramData\Veeam\Logs\YARA-SecureRestore\`:
   - `scan_*.log` for per-file detections
   - `results_*.json` for structured findings, extracted onion links, and path mapping
6. Validate expected exit behavior:
   - `1` = detection found (restore should be blocked)
   - `0` = no detection
   - `2` = script/runtime error

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

# Run scanner
.\Veeam-YARA-SecureRestore.ps1 -QuickScan
```

### Performance Benchmarking

```powershell
# Measure scan time
Measure-Command {
    .\Veeam-YARA-SecureRestore.ps1 -QuickScan
}

# Profile YARA performance
& "C:\Program Files\YARA\yara64.exe" -p -r -s `
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

#### 3. "No mounted Windows volumes found"

```powershell
# Verify VM is mounted via Instant Recovery/SureBackup
Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemType -in @('NTFS','ReFS') }

# Check if Windows directory exists on mounted volumes
Get-Volume | ForEach-Object {
    Test-Path "$($_.DriveLetter):\Windows"
}
```

#### 4. Script times out in SureBackup

```powershell
# Use QuickScan mode to reduce scan time
-QuickScan

# Or increase timeout in SureBackup job settings:
# Application Group → Test Script → Timeout: 7200 (2 hours)
```

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
- **Last Updated:** June 2026

---

## Quick Links

- [YARA Documentation](https://yara.readthedocs.io/)
- [Veeam Secure Restore Guide](https://helpcenter.veeam.com/docs/vbr/userguide/malware_detection_scan_backup_yara.html)
- [GitHub Repository](https://github.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links)
- [Report Issues](https://github.com/cgfixit/veeam-ps1-scanner-yara-rule-detection-onion-links/issues)
