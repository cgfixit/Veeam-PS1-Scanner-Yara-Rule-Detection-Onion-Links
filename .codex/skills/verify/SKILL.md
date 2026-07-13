---
name: verify
description: Verify the PowerShell scanner repository's Codex setup and narrow test paths.
---

# Verify

Use this skill after cloning or before publishing changes.

1. Confirm `AGENTS.md`, `.codex/README.md`, and the scanner files exist.
2. Confirm the checkout is on `main` or a named work branch and has a clean
   status before making changes.
3. Run the narrowest applicable check:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '$env:VEEAM_YARA_NOEXEC = "1"; . .\Veeam-YARA-SecureRestore.ps1'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1 -InstallPester
```

Keep Windows PowerShell 5.1 compatibility and do not launch a real scan during
verification.
