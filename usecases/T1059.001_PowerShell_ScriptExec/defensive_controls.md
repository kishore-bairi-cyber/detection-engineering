# 🛡️ Defensive Countermeasures – PowerShell Abuse (T1059.001)

## Preventive
- **GPO:** Enable **PowerShell Script Block Logging (4104)** and **Transcription** across endpoints.
- **AMSI:** Ensure AMSI is enabled and not bypassed; alert on touching `System.Management.Automation.AmsiUtils`.
- **Execution Policy:** Enforce `AllSigned` in high-risk segments; prefer **PowerShell 7** with reduced attack surface.
- **Service Accounts:** Convert to **Managed Service Accounts**, deny interactive logon.

## Detective
- **Process Flags:** Alert on `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, long base64 blobs.
- **Download Cradles:** Detect `IEX (New-Object Net.WebClient).DownloadString`, `Invoke-WebRequest/iwr`, `Start-BitsTransfer`.
- **Parentage:** Unusual parents (e.g., `winword.exe`, `excel.exe`, `outlook.exe` → `powershell.exe`).
- **Egress:** Rare destinations following PowerShell process start; SNI/URL categorization = newly-seen.

## Hardening & Tuning
- Build **entity-based allowlists** for known admin scripts (path, hash, signer, account).
- Require **code signing** for prod scripts; monitor/alert unsigned in prod.
- Pair with **EDR** rules to block **encoded or hidden-window** PowerShell when not expected.
