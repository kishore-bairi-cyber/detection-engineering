# 📝 Triage – LOLBAS Abuse
- Confirm the **binary** and **payload path/URL**.
- Decode certutil outputs or HTA/scriptlet content if reachable.
- Check **parent process** (Office/email client often indicates phishing).
- Inspect **network egress** immediately after execution.
- If benign (admin scripts), record ticket and add allowlist with expiry.
