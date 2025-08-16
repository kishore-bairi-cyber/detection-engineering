# 🛰️ Detection Use Case – WMI Remote Execution (MITRE T1047)
## Background
Adversaries use **WMI** to execute commands on remote hosts. Patterns: `wmic /node: <target> process call create`, PowerShell `Invoke-WmiMethod` / `Invoke-CimMethod`, and **WmiPrvSE.exe → cmd.exe/powershell.exe** on the target.
## Technique
- MITRE: T1047 – Windows Management Instrumentation
- Tactics: Execution, Lateral Movement
## How to use
1) Ingest `sample_logs/` (index `windows`).
2) Run detections (`splunk_query.spl`, `sentinel_query.kql`, `logrhythm_query.sql`).
3) Import `validation/dashboard_wmi_exec.xml` and follow `Evidence_Checklist.md`.
