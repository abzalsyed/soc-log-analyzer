# SOC Log Analyzer

Python tool that detects brute-force login attacks by analyzing 
authentication logs. Flags source IPs with excessive failed login 
attempts within threshold-based rules, similar to SIEM correlation logic.

## How it works
- Reads a CSV log file of login attempts
- Counts failed logins per source IP
- Alerts when an IP crosses the threshold (5+ failed attempts)
