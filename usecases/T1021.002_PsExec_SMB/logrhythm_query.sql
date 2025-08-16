-- LogRhythm SQL – SMB/PSExec Remote Service (T1021.002)
SELECT Hostname, Username, Process, ParentProcess, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (
  VendorMessage ILIKE '%EventID=7045%' OR VendorMessage ILIKE '%4697%'
  OR Process ILIKE '%\\psexec%' OR CommandLine ILIKE '% sc % create %' OR CommandLine ILIKE '%\\\\ADMIN$%'
)
ORDER BY StartTime DESC;
