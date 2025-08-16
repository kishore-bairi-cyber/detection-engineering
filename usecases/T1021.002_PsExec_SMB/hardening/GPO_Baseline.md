# GPO / EDR Baseline – SMB/PSExec
- Block inbound SMB on workstations; restrict 445 to mgmt VLANs.
- Disable default admin shares where feasible; enforce local firewall rules.
- AppLocker/WDAC rules to block PsExec binaries and unsigned service images.
- Monitor for System 7045, Security 4697, ServiceName=PSEXESVC.
