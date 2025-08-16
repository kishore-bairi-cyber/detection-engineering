# 📝 Incident Triage Report – Suspicious Scheduled Task Creation (T1053.005)

## 1. What happened?
A scheduled task was **created/updated** with potentially malicious characteristics (SYSTEM account, high frequency, LOLBin payload, or user-writable path).

## 2. Where did it happen?
- Hosts: WS-220, DC-01
- Accounts: acme\svc_updater, acme\jane.doe

## 3. Who was involved?
- Creator account = `svc_updater` (should be non-interactive)
- Potential lateral use via GPO-deployed tasks

## 4. When did it happen?
- Window: 2025-08-16 03:25:00 to 03:33:00 IST

## 5. Why did it happen?
- Likely persistence or scheduled execution for staging payloads.

## 6. How was it detected?
- Correlation of **4698/4702** + `schtasks /create` process creation with suspicious command-line terms.

### Recommended Response
**Containment**
- Disable or delete the suspicious task (`schtasks /delete /tn "<TaskName>" /f`).
- Revoke tokens for creator account; rotate credentials if service account.

**Eradication**
- Remove payload files; block malicious domains; inspect startup locations.

**Recovery**
- Restore legitimate tasks if impacted; monitor for re-creation attempts.

**Follow-up**
- Add legitimate admin tasks to **allowlist** with owner & expiry.
