# 📝 Triage – Process Injection
- Confirm source→target and user/session. Is the source an LOLBIN or unsigned tool?
- Check GrantedAccess values and whether the target is `lsass.exe` or other sensitive processes.
- Review subsequent behavior: dump files, network beacons, credential access.
- Validate if the source is a known security tool (EDR/AV) before escalating.
