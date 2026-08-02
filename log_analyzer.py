"""
Mini Log Analyzer
------------------
Reads a log file of login attempts and flags possible brute-force attacks:
if the same source IP has too many failed logins, print an ALERT.
"""

import csv
from collections import defaultdict

LOG_FILE = "sample_logs.csv"
FAILED_LOGIN_THRESHOLD = 5   # 5 or more failed logins from one IP = alert


def read_log_file(filepath):
    """Reads the CSV log file and returns a list of rows (dictionaries)."""
    with open(filepath, mode="r") as file:
        reader = csv.DictReader(file)
        return list(reader)


def detect_brute_force(log_rows):
    """Counts failed logins per IP and returns IPs that cross the threshold."""
    failed_login_counts = defaultdict(int)

    for row in log_rows:
        if row["event_type"] == "failed_login":
            ip = row["source_ip"]
            failed_login_counts[ip] += 1

    alerts = []
    for ip, count in failed_login_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append((ip, count))

    return alerts


def main():
    print("Reading log file:", LOG_FILE)
    log_rows = read_log_file(LOG_FILE)
    print(f"Total log entries read: {len(log_rows)}\n")

    alerts = detect_brute_force(log_rows)

    if alerts:
        print("=== ALERTS ===")
        for ip, count in alerts:
            print(f"ALERT: Possible brute force detected from IP {ip} "
                  f"({count} failed login attempts)")
    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()
