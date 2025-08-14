## Incident Response Steps – Tier 2 SOC

1. Isolate the hosts: WIN-ENG-03 and WIN-ENG-08
2. Search process logs (Sysmon/EDR) for curl, wget, or PowerShell invocation
3. Check browser history to rule out false positives
4. Search for files downloaded in last 30 minutes
5. Notify IR team for memory acquisition
6. Block domain `malicious.c2sync.co` in firewall and proxy
7. Initiate full endpoint triage + kill chain review
