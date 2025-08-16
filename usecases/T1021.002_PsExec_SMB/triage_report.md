# 📝 Triage – SMB/PSExec Remote Service
- Confirm **source host** (admin/jump?) and **target host** that installed/runs the service.
- Look for **ServiceName=PSEXESVC** or suspicious names; extract **ImagePath** (payload).
- Review **creator account** and recent **SMB (445)** connections from source to target.
- If benign (software deploy), capture change ticket and add to allowlist.
