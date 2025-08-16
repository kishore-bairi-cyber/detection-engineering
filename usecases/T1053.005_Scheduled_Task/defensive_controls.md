# 🛡️ Defensive Countermeasures – Scheduled Task Abuse

## Preventive
- **Enable Security 4698/4702** and **Task Scheduler Operational** logging across endpoints.
- Restrict who can **Create global tasks**; prefer **least privilege** & admin jump boxes.
- Enforce **code signing** and WDAC/AppLocker for script execution.
- Store admin scripts in **read-only shares** for standard users.

## Detective
- Alert on `schtasks.exe /create` with **/RU SYSTEM**, **/SC MINUTE**, LOLBins (`powershell -enc`, `mshta`, `wscript`), or paths in **AppData/ProgramData**.
- Hunt for **Task run** shortly after creation + egress.

## Tuning
- Allowlist *approved* enterprise tasks by name, path, signer, owner, and device group with **expiry**.
