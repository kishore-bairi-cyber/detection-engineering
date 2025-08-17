# Baseline – Process Injection Protections
- Enable ASR rules: Block credential theft from LSASS; Block Office child process creation; Block process creations from PS.
- WDAC/AppLocker allowlist known tools; block unsigned loaders from user-writable paths.
- Ensure LSA Protection (RunAsPPL) and Credential Guard on endpoints where possible.
