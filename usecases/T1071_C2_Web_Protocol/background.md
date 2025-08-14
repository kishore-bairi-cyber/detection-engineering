## MITRE Technique: T1071.001 – Application Layer Protocol: Web Protocols

Attackers use HTTP/S to exfiltrate data or establish C2 channels that blend in with legitimate web traffic.

### Why This Detection Matters in Production:

- 🔸 HTTP/S traffic is always allowed, making it a **favored channel for malware C2**.
- 🔸 Many beaconing behaviors (curl, wget, PowerShell web requests) **bypass firewall policies** and **evade EDR** if not monitored.
- 🔸 Detecting abnormal usage patterns (e.g., repetitive, timed, encoded) across **multiple hosts** helps break C2 channels early.

### Real-World Cases:
- **Emotet, TrickBot, Cobalt Strike** regularly use this technique.
- Threat actors like **APT29, FIN7** have used encrypted HTTP to tunnel commands.
