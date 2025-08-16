# Tuning & Triage Checklist
1) Confirm task *owner* and *creator* → should this account create tasks?
2) Inspect *Action* → PowerShell/mshta/wscript or uncommon binary?
3) Path points to **AppData/ProgramData** or temp?
4) Frequency (minute/5 minute) unusual for the environment?
5) Immediate follow-on events: task run → network egress or child process?
6) If benign, add to **allowlist** with owner & expiry and capture change ticket.
