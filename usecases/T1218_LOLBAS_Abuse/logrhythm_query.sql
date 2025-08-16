-- LogRhythm SQL – LOLBAS Abuse (T1218)
SELECT Hostname, Username, Process, ParentProcess, CommandLine, VendorMessage, StartTime
FROM EventLog
WHERE (
  Process ILIKE '%\\certutil.exe%' OR Process ILIKE '%\\mshta.exe%' OR Process ILIKE '%\\rundll32.exe%' OR Process ILIKE '%\\regsvr32.exe%' OR Process ILIKE '%\\installutil.exe%' OR Process ILIKE '%\\msbuild.exe%'
  OR CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%' OR CommandLine ILIKE '% -urlcache -split -f %' OR CommandLine ILIKE '%javascript:%' OR CommandLine ILIKE '%vbscript:%' OR CommandLine ILIKE '% scrobj.dll%'
)
ORDER BY StartTime DESC;
