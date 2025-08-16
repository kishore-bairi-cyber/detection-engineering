# 🔔 Detection Use Case – Suspicious Scheduled Task Creation (MITRE T1053.005)

## 📌 Background
Adversaries create or modify **Scheduled Tasks** to achieve **Execution**, **Persistence**, or **Privilege Escalation**. Abuse often includes:
- `schtasks.exe /create` with SYSTEM or high frequency (`/SC MINUTE`), hidden windows, or **LOLBins** payloads (PowerShell, mshta, wscript).
- Task definitions pointing to user-writable paths such as **AppData** or **ProgramData**.
- Post-creation runs to stage payloads.

## 🎯 Threat Context
- **Technique:** T1053.005 *Scheduled Task/Job: Scheduled Task*
- **Tactics:** Execution, Persistence, Privilege Escalation
- **Primary Logs:** Windows Security (**4698** created, **4702** updated), Task Scheduler Operational, Sysmon (process create), EDR telemetry.

## 🛠️ Expected Signals
- Creation/Update events referencing suspicious paths or LOLBins.
- `schtasks.exe` with `/RU SYSTEM`, `/SC MINUTE`, `/TN` odd names, or payloads such as `powershell -enc`.
- Immediate **task run** followed by outbound connection or child process spawn.

## 🧪 How to Use This Folder
1. Ingest `sample_logs/*.csv` into your lab (index `windows`).
2. Run `splunk_query.spl` or `sentinel_query.kql`.
3. Use `validation/` to visualize & alert; follow `Evidence_Checklist.md` for screenshots.
4. Review `defensive_controls.md` and `hardening/` for prevention and tuning.

## 📚 MITRE
- https://attack.mitre.org/techniques/T1053/005/
