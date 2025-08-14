### What?
Suspicious beaconing activity over HTTP from multiple endpoints to a known C2 domain, potentially indicating malware communication.

### Where?
- Hostnames: `WIN-ENG-03`, `WIN-ENG-08`
- Suspicious Domain: `malicious.c2sync.co`

### Who?
- Users involved: `corp\neha.r`, `corp\ajay.v`

### When?
- Timestamp range: `2025-08-14 10:01:15` to `10:04:10`

---

### Why?
**T1071.001** is commonly used for stealthy C2 communications. In this case:
- The beaconing interval was close to **30 seconds**
- Usage of **curl/wget** rather than browsers
- URLs contained **base64 strings** (`b64=ZXZpbAo=`)

---

### How?
- Likely initial malware stage using HTTP C2 channels.
- No user browser activity was involved, suggesting non-human interaction.

---

### 🔍 Evidence

| Host        | User           | URI                                              | Tool  | Timestamp           |
|-------------|----------------|--------------------------------------------------|-------|---------------------|
| WIN-ENG-03  | corp\neha.r    | https://malicious.c2sync.co/b64=ZXZpbAo=        | curl  | 2025-08-14 10:01:15 |
| WIN-ENG-03  | corp\neha.r    | https://malicious.c2sync.co/b64=ZXZpbAo=        | curl  | 2025-08-14 10:02:01 |
| WIN-ENG-03  | corp\neha.r    | https://malicious.c2sync.co/b64=ZXZpbAo=        | curl  | 2025-08-14 10:02:30 |
| WIN-ENG-08  | corp\ajay.v    | https://malicious.c2sync.co/ping                | wget  | 2025-08-14 10:03:45 |
| WIN-ENG-08  | corp\ajay.v    | https://malicious.c2sync.co/ping                | wget  | 2025-08-14 10:04:10 |

---

### 🧬 MITRE TTPs

- **Tactic**: Command and Control
- **Technique**: [T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

---

### 🚨 Triage Conclusion:
The repeated access to a suspicious domain with encoded URLs from command-line tools (not browsers) across two hosts suggests likely malware-driven outbound C2 activity.

**Escalate to IR for containment and memory acquisition.**
