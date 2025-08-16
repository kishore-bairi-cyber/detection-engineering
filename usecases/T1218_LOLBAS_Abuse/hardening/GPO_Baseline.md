# GPO / EDR Baseline – LOLBAS
- AppLocker/WDAC: explicitly block risky LOLBINs (certutil/mshta/rundll32/regsvr32) for standard users.
- Enforce Constrained Language Mode.
- EDR: detect LOLBIN + network egress combo, block on workstations.
