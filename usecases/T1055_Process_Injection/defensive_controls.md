# 🛡️ Defensive Controls – Process Injection
- Enable LSA Protection (RunAsPPL) and Credential Guard.
- ASR rules to block Office child process and credential theft from LSASS.
- WDAC/AppLocker to restrict unsigned loaders and LOLBINs used for injection.
- Alert on CreateRemoteThread and suspicious OpenProcess to sensitive targets.
