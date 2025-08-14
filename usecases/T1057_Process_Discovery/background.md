## MITRE Technique: T1057 – Process Discovery

Adversaries may enumerate running processes on a system to identify security tools, user activity, or weak targets for injection. This helps them escalate privileges or remain stealthy.

### Common Tools:
- tasklist (Windows)
- ps, top, pgrep (Linux)
- wmic process list
- PowerShell Get-Process

### ATT&CK Tags:
- tactic: Discovery
- technique: T1057
