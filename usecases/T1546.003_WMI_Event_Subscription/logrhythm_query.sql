SELECT Hostname, Username, Process, ParentProcess, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (
  CommandLine ILIKE '%root\\subscription%'
  OR CommandLine ILIKE '%__EventFilter%'
  OR CommandLine ILIKE '%CommandLineEventConsumer%'
  OR CommandLine ILIKE '%ActiveScriptEventConsumer%'
  OR VendorMessage ILIKE '%WMI-Activity%' AND (VendorMessage ILIKE '%5857%' OR VendorMessage ILIKE '%5858%' OR VendorMessage ILIKE '%5861%')
)
ORDER BY StartTime DESC;
