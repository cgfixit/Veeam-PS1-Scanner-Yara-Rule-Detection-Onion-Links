# `.codex/`

This folder holds Codex-specific operating material for `Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links`.

Keep the CyClaw-style split:

- `AGENTS.md` for repo facts, commands, and non-negotiable rules
- `.codex/` for reusable repo-local skills and small task playbooks

Available skills:

- `skills/refactor/` - iterative architecture and speed refactor loop for the scanner and rule workflow

Codex optimization bias:

- Prefer measured scanner bottlenecks, shared parsing choke points, rule/test drift, PowerShell 5.1 compatibility hazards, and code deletion over broad rewrite ideas.
- Try to find different issues than a generic Claude-style optimizer would repeat: import/bootstrap overhead in worker setup, duplicated quoting/path handling, repeated file-system work, and validation gaps between unit tests and real YARA flows.
