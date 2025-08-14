# T1071 – C2 via Web Protocols

This detection use case identifies potential Command and Control activity over HTTP/HTTPS using base64-encoded payloads or repeat traffic to suspicious domains.

- MITRE Technique: T1071.001
- Logs analyzed: 10 endpoints (mix of normal + malicious)
- Tools used: curl, wget, browser
- Detection goal: Identify beaconing or exfiltration using HTTP

> Includes triage report, simulated logs, and incident response steps.
