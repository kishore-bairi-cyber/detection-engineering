# 🪟 Detection Use Case – SMB/PSExec Remote Service (MITRE T1021.002)

## Background
Attackers use **SMB & admin shares** with tools like **PsExec** to run commands on remote hosts. Typical traces:
- Service creation events (**4697**, **System 7045**) with names like **PSEXESVC**.
- Process activity: `psexec.exe`, `sc.exe create`, service binaries in `\ADMIN$` or temp paths.
- Network: SMB (445) from admin/jump hosts to targets.

## Technique
- **MITRE:** T1021.002 – Remote Services: SMB/Windows Admin Shares
- **Related:** T1569.002 (Service Execution), T1570 (Lateral Tool Transfer)

## How to use
1) Ingest `sample_logs/*.csv` (index `windows`).
2) Run detections (`splunk_query.spl`, `sentinel_query.kql`, `logrhythm_query.sql`).
3) Import dashboard in `validation/` and follow `Evidence_Checklist.md`.
