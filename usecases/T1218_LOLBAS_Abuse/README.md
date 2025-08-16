# 🧰 Detection Use Case – LOLBAS Abuse (MITRE T1218)

## Background
Adversaries abuse **signed Windows binaries** (LOLBAS) to execute code, bypass controls, or stage payloads. Common tools:
- **certutil.exe** (download/encode), **mshta.exe** (HTA/JS), **rundll32.exe** (LOL scriptlets), **regsvr32.exe** (COM/scriptlet), **installutil.exe**, **msbuild.exe**.

## Technique
- **MITRE:** T1218 – Signed Binary Proxy Execution
- **Tactics:** Defense Evasion, Execution, Initial Access

## How to use
1) Ingest `sample_logs/` (index `windows`).
2) Run detections (`splunk_query.spl`, `sentinel_query.kql`, `logrhythm_query.sql`).
3) Import `validation/dashboard_lolbas.xml` and follow `Evidence_Checklist.md`.
