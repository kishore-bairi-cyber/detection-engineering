## Known Threat Actors Using T1071.001

| Threat Group | Malware Used     | Behavior Summary |
|--------------|------------------|------------------|
| APT29        | Custom backdoors | HTTP/S POSTs with base64 payloads |
| FIN7         | PowerShell + JS  | GET beaconing from user PCs |
| Conti        | Cobalt Strike    | HTTPS beaconing over port 443 |

Indicators include:
- Repeated communication with rare IPs/domains
- Base64-encoded URLs
- Odd time interval patterns
