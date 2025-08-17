-- LogRhythm SQL – Process Injection (T1055)
SELECT Hostname, Username, Process, ParentProcess, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (
  VendorMessage ILIKE '%EventID=8%' -- CreateRemoteThread
  OR VendorMessage ILIKE '%EventID=10%' AND (VendorMessage ILIKE '%lsass.exe%' OR VendorMessage ILIKE '%0x1fffff%' OR VendorMessage ILIKE '%0x1410%')
  OR Process ILIKE '%\\rundll32.exe' OR Process ILIKE '%\\regsvr32.exe' OR Process ILIKE '%\\mshta.exe' OR Process ILIKE '%\\powershell.exe'
)
AND VendorMessage NOT ILIKE '%MsMpEng.exe%'
ORDER BY StartTime DESC;
