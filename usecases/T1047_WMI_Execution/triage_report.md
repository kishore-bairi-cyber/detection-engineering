# Triage – WMI Remote Execution (T1047)
- Confirm source→target host pair and user context.
- On target, verify WmiPrvSE.exe spawned cmd/powershell and extract payload.
- Check lateral movement sequence and tickets/change records for legit admin jobs.
- Contain: block account, isolate target, kill spawned processes; Eradicate & Recover per SOP.
