-- LogRhythm SQL – WMI Remote Execution (T1047)
SELECT Hostname, Username, Process, ParentProcess, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (
  Process ILIKE '%\\wmic.exe%' OR
  CommandLine ILIKE '%Invoke-WmiMethod%' OR
  CommandLine ILIKE '%Win32_Process%Create%' OR
  (ParentProcess ILIKE '%\\WmiPrvSE.exe%' AND (Process ILIKE '%\\cmd.exe%' OR Process ILIKE '%\\powershell.exe%'))
)
ORDER BY StartTime DESC;
