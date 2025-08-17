# 🧬 Detection Use Case – Process Injection (MITRE T1055)

## Background
Process injection lets an attacker run code **inside another process** to hide, bypass controls, or gain higher privileges. 
Common techniques include **CreateRemoteThread** + `WriteProcessMemory`, **DLL injection**, and abuse via tools/scripts (PowerShell loaders, `rundll32`, `regsvr32`). 
High-signal artifacts:
- Cross‑process **thread creation** (remote thread) from a suspicious source to a sensitive target
- **High access rights** when opening a target process (e.g., `0x1fffff`, `0x1410`)
- Injection tools/LOLBINs used as launchers (PowerShell, `rundll32.exe`, `regsvr32.exe`)

## Technique
- **MITRE:** T1055 – Process Injection
- **Tactics:** Defense Evasion, Privilege Escalation
- **Related:** T1003.001 (LSASS dump), T1218 (LOLBAS), T1059.001 (PowerShell)

## Data sources
- **Sysmon** – **EID 8** (CreateRemoteThread), **EID 10** (ProcessAccess), **EID 7** (ImageLoad) for odd DLL loads.
- **Windows Security 4688** – process creation of likely injectors.
- **Microsoft Defender for Endpoint (MDE)** – `DeviceEvents` (ActionType: `CreateRemoteThread`, `OpenProcess`), `DeviceProcessEvents`.

## Detection approach (summary)
- Flag **Sysmon EID 8** where `SourceImage` and `TargetImage` differ and the **source** is suspicious (`powershell.exe`, `rundll32.exe`, unsigned tools) or the **target** is sensitive (`lsass.exe`, `winlogon.exe`, `explorer.exe`).
- Use **Sysmon EID 10** to catch **high-privilege handles** opened to targets (e.g., `lsass.exe`) by non‑security processes.
- In MDE, look for **CreateRemoteThread/OpenProcess** actions and exclude EDR/AV processes (`MsMpEng.exe`, `SenseIR.exe`) as needed.

> Queries: see `splunk_query.spl`, `sentinel_query.kql`, `logrhythm_query.sql`.

## How to use (lab)
1) Ingest CSVs from `sample_logs/` into your Windows index.
2) Run the queries above and review the **source→target** pairs.
3) Import `validation/dashboard_injection.xml` and collect screenshots per the checklist.

## Triage
- Identify **source → target** pair and **user** context.
- Check **GrantedAccess** (e.g., `0x1fffff`, `0x1410`) and **StartAddress/CallTrace** (module path).
- Look for **preceding downloads/macros** and **follow‑on behavior** (credential access, network egress).
- Benign possibilities: EDR/AV memory scans; confirm signed vendor binaries and change tickets.

## Hardening / Prevention
- Enable **LSA Protection (RunAsPPL)**; block non‑PPL access to LSASS.
- **ASR rules** (e.g., block Office child processes / block credential theft from LSASS).
- **WDAC/AppLocker** to restrict unsigned loaders and LOLBIN abuse.
- Monitor and alert on **CreateRemoteThread** to sensitive processes.

## Validation checklist
- [ ] Sysmon EID 8 showing remote thread creation with suspicious source/target.
- [ ] Sysmon EID 10 showing high‑privilege access to target (esp. `lsass.exe`).
- [ ] Timeline/dashboard panels populated with top source→target pairs.
- [ ] Screenshots: detailed event tables including `GrantedAccess`, `StartAddress`.
