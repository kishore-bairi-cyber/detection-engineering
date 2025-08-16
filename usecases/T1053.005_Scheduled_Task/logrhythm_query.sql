-- LogRhythm SQL – Suspicious Scheduled Task Creation (T1053.005)
SELECT Hostname, Username, Process, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (Process ILIKE '%\\schtasks.exe%' OR VendorMessage ILIKE '%4698%' OR VendorMessage ILIKE '%TaskScheduler%')
  AND (
       CommandLine ILIKE '%/create%' OR
       CommandLine ILIKE '%/sc minute%' OR
       CommandLine ILIKE '%/ru system%' OR
       CommandLine ILIKE '%\\AppData\\%' OR
       CommandLine ILIKE '%\\ProgramData\\%' OR
       CommandLine ILIKE '%powershell% -enc%' OR
       CommandLine ILIKE '%mshta%' OR
       CommandLine ILIKE '%wscript%'
  )
ORDER BY StartTime DESC;
