# 🛡️ Defensive Controls – LOLBAS
- **WDAC/AppLocker:** restrict certutil/mshta/rundll32/regsvr32 on workstations; allow only signed, known-good use.
- **PowerShell Constrained Language Mode** for non-admins.
- **EDR blocking** rules for LOLBIN network access and suspicious flags.
- **Proxy/DNS**: block downloads from newly registered or uncategorized domains.
