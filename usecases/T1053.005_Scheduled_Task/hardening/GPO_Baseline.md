# GPO Baseline – Scheduled Tasks Visibility & Control

## Enable Logs
- **Task Scheduler Operational**: `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`
- **Security**: Enable **Other Object Access** subcategory to log 4698/4702.

## Restrict Task Creation
- Limit "Create global objects / scheduled tasks" to admins on **jump boxes**.
- Prefer **SYSTEM tasks** managed by configuration management (not ad-hoc).

## WDAC/AppLocker
- Deny unsigned scripts in production tiers; allow signed/pinned hashes for admin jobs.

## Inventory & Review
- Periodic export of tasks via `schtasks /query /fo LIST /v` and diff against baseline.
