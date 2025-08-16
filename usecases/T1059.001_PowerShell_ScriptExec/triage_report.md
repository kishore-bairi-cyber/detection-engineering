# 📝 Incident Triage Report – Suspicious PowerShell Script Execution (T1059.001)

## 1. What happened?
Multiple endpoints executed PowerShell with **encoded commands**, **AMSI bypass strings**, and **hidden windows**. One host initiated an outbound connection to an **unseen domain** and downloaded a script via `IEX (New-Object Net.WebClient).DownloadString(...)`.

## 2. Where did it happen?
- Hosts: `WS-042`, `WS-105`, `SRV-JMP-01`
- Users: `acme\svc_backup`, `acme\jane.doe`
- Network egress: `hxxp://updates-soft[.]com/p.ps1` (proxy logs)

## 3. Who was involved?
- Potential threat actor using LOL techniques.
- Accounts observed: `svc_backup` (should be **non-interactive**), `jane.doe` (workstation user).

## 4. When did it happen?
- First event: 2025-08-16 02:11:43 IST
- Last event: 2025-08-16 02:19:12 IST
- Dwell time within 8 minutes (staging → download → execution)

## 5. Why did it happen?
- Likely **initial staging** for payload delivery / discovery in memory to bypass disk AV.
- Weak controls: Script Block Logging not universally enabled; AMSI tampering allowed; service account misuse.

## 6. How was it detected?
- Splunk correlation on PowerShell **evasion flags** + **download cradle** patterns.
- Cross-joined with proxy logs for rare domain egress from the same process tree.

---

### Recommended Response
**Containment**
- Isolate affected endpoints (`WS-042`, `WS-105`) from the network.
- Disable/reset `svc_backup`; enforce **logon type** restrictions on service accounts.

**Eradication**
- Kill suspicious PS processes; clear scheduled tasks created during window.
- Remove downloaded artifacts; block domain/IP in egress controls.

**Recovery**
- Rebuild affected endpoints if LSASS/credential theft is suspected.
- Re-enable and enforce hardening: **AMSI**, **Constrained Language Mode**, **PowerShell Script Block Logging** (4104), and **PS Transcription**.

**Follow-up**
- Add allowlist for known admin jobs; convert this case into a **hunt** for the last 14 days (same indicators).
