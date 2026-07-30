# Mini SIEM Project

A lightweight, from-scratch SIEM pipeline built entirely in Python on WSL/Linux — log generation, normalization, storage, detection rules, and a CLI dashboard.

## Architecture
generators/ -> produces raw log files (SSH, web, firewall) simulating normal + attack traffic
parsers/    -> normalizes raw logs into a common schema, loads into SQLite
detectors/  -> runs detection rules (brute-force, web attacks, port scans) against the DB
reports/    -> CLI dashboard showing top IPs and current alerts

## How to run
python3 run_pipeline.py

## Detection rules
- Brute-force SSH: 3+ failed logins from one IP
- Web attack patterns: SQLi/XSS-style request strings
- Port scanning: 10+ distinct ports denied from one IP

## Example output
Top Source IPs by Event Count, plus generated alerts such as:
[HIGH] Brute-force suspected from <ip>: 8 failed SSH logins
[HIGH] Web attack pattern from <ip>: 6 malicious requests
[MEDIUM] Port scan suspected from <ip>: 15 distinct ports probed
