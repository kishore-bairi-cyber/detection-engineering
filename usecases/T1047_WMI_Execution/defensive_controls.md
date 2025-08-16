# Defensive Controls – WMI
- Enable **Microsoft-Windows-WMI-Activity/Operational** logging (5857–5861).
- Restrict remote WMI to admin jump hosts; limit DCOM and RPC with firewall rules.
- Prefer PS Remoting + JEA; monitor WmiPrvSE→cmd/ps spawns.
