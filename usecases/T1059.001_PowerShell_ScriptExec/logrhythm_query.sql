-- LogRhythm AI Engine SQL – Suspicious PowerShell
SELECT Hostname, Username, Process, CommandLine, ParentProcess, StartTime
FROM EventLog
WHERE (Process ILIKE '%\\powershell.exe%' OR VendorMessage ILIKE '%PowerShell%')
  AND (
    CommandLine ILIKE '%-enc%' OR
    CommandLine ILIKE '%-encodedcommand%' OR
    CommandLine ILIKE '% -nop%' OR
    CommandLine ILIKE '% -w hidden%' OR
    CommandLine ILIKE '%start-bitstransfer%' OR
    CommandLine ILIKE '%iex%new-object%net.webclient%downloadstring%' OR
    CommandLine ILIKE '%system.management.automation.amsiutils%'
  )
ORDER BY StartTime DESC;
