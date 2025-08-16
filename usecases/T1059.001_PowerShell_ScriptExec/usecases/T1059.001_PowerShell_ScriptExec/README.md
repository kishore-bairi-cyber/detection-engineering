# 🔍 Detection Use Case – Suspicious PowerShell Script Execution (MITRE T1059.001)

## 📌 Background
PowerShell is a legitimate Windows automation framework that adversaries frequently abuse for **fileless** execution, payload staging, credential access, and lateral movement. Its deep OS access and living-off-the-land (LOL) nature make detections require **behavioral** signals—beyond simply matching on `powershell.exe`.

## 🎯 Threat Context
- **MITRE ATT&CK Mapping:** T1059 – Command and Scripting Interpreter → **T1059.001 PowerShell**
- **Tactics:** Execution, Defense Evasion, Discovery, Credential Access, Lateral Movement
- **Real-world Pattern:** Common in ransomware pre-stages and red-team ops using encoded commands (`-enc`), AMSI bypasses, download cradles, and in-memory execution.

## 🛠️ Attacker Behavior
- **Tools/Patterns:** `-enc/-EncodedCommand`, `-nop/-NoProfile`, `-w hidden`, `Start-BitsTransfer`, `IEX (New-Object Net.WebClient).DownloadString(...)`, AMSI bypass strings (e.g., `System.Management.Automation.AmsiUtils`), Base64 payloads
- **Kill Chain Flow:** Initial access → PS-encoded stager → Payload download/reflective load → Cred dumping/discovery → Lateral movement
- **Expected Logs:** Sysmon (Event ID 1, 3), Windows Security 4688/4104 (if enabled), EDR process telemetry, Proxy/Firewall egress to rare hosts

## 📊 Sample Logs
See `/sample_logs/` for **endpoint**, **server**, and **proxy** examples to test queries.

## 🔎 Detection Logic

### Splunk SPL (Endpoint – Sysmon/4688/ScriptBlock)
```spl
(
  index=windows (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=WinEventLog:Security OR sourcetype=PowerShell:Operational)
)
(
  (EventCode=1 OR EventID=1 OR EventCode=4688 OR EventID=4688 OR EventID=4104)
  AND (Image="*\powershell.exe" OR NewProcessName="*\powershell.exe" OR ParentImage="*\powershell.exe" OR Message="*PowerShell*")
)
| fillnull
| eval cmd=coalesce(CommandLine, NewProcessName." ".CommandLine, Message)
| where like(lower(cmd), "%-enc%")
    OR like(lower(cmd), "%-encodedcommand%")
    OR like(lower(cmd), "% -w hidden%")
    OR like(lower(cmd), "% -nop%")
    OR like(lower(cmd), "%iex%new-object%net.webclient%downloadstring%")
    OR like(lower(cmd), "%start-bitstransfer%")
    OR like(lower(cmd), "%system.management.automation.amsiutils%")
    OR (len(replace(cmd, "\s", ""))>200 AND like(lower(cmd), "%powershell%"))
| stats earliest(_time) as firstTime latest(_time) as lastTime count values(Computer) as hosts values(User) as users values(ParentImage) as parents values(Image) as images values(cmd) as cmds by dest, user
| sort - count
```

### LogRhythm Native Query (AI Engine / Log Source Virtualization)
```sql
-- Detect suspicious PowerShell invocations with common evasion and staging flags
SELECT
  Hostname,
  Username,
  Process,
  CommandLine,
  ParentProcess,
  VendorMessage,
  StartTime
FROM EventLog
WHERE
  (Process ILIKE '%\powershell.exe%' OR VendorMessage ILIKE '%PowerShell%')
  AND (
    CommandLine ILIKE '%-enc%' OR
    CommandLine ILIKE '%-encodedcommand%' OR
    CommandLine ILIKE '% -nop%' OR
    CommandLine ILIKE '% -w hidden%' OR
    CommandLine ILIKE '%start-bitstransfer%' OR
    CommandLine ILIKE '%iex%new-object%net.webclient%downloadstring%' OR
    CommandLine ILIKE '%system.management.automation.amsiutils%'
  )
  AND NOT (CommandLine ILIKE '%\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -ExecutionPolicy Bypass -Command "Get-ComputerInfo"%' )
ORDER BY StartTime DESC;
```

> **Note:** Convert the above into an **AI Engine Rule** with field mappings to your schema (e.g., `Process = Common Event.Process`, `CommandLine = Common Event.Command Line`). Add entity-based allowlists for known automation accounts/paths.

### Microsoft Sentinel KQL (Endpoint + ScriptBlock + Network)
```kql
let suspicious_terms = dynamic([
  "-enc","-encodedcommand","-nop","-w hidden","start-bitstransfer",
  "System.Management.Automation.AmsiUtils","iex","downloadstring","iwr","invoke-webrequest"
]);
let bad_pattern = @"(?i)iex\s*\(new-object\s+net\.webclient\)\.downloadstring";
DeviceProcessEvents
| where ProcessCommandLine has_any (suspicious_terms) or ProcessCommandLine matches regex bad_pattern
| where Process has_any ("powershell.exe","pwsh.exe")
| extend Parent = tostring(InitiatingProcessFileName), User = tostring(AccountName)
| project Timestamp, DeviceName, User, Process, ProcessCommandLine, Parent, InitiatingProcessCommandLine
| join kind=leftouter (
  DeviceNetworkEvents
  | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
  | project DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, Timestamp
) on DeviceName
| order by Timestamp desc
```

## 🧾 Triage Report (5W+1H)
See `triage_report.md` for a complete analyst walkthrough with **timeline, indicators, and response**.

## 🛡️ Defensive Countermeasures
See `defensive_controls.md` for prevention (GPO, AMSI, Script Block Logging), detection tuning, and hardening tips.

## 📚 References
- MITRE ATT&CK T1059.001 – PowerShell
- Microsoft: PowerShell Security Best Practices
- CISA: Ransomware advisories (living-off-the-land)
