# 🛡️ Defensive Controls – SMB/PSExec
- Limit **Admin$** access: host firewalls, restrict SMB (445) to management networks.
- Prefer **WinRM/PS Remoting with JEA**; block PsExec in EDR on workstations.
- AppLocker/WDAC: block `psexec*.exe` and unsigned service binaries.
- Alert on **System 7045**, **Security 4697**, and **ServiceName=PSEXESVC**.
