from collections import Counter
from datetime import datetime

LOG_FILE = "soc_events.log"
REPORT_FILE = "soc_report.txt"

events = []

with open(LOG_FILE, "r") as file:
    for line in file:
        line = line.strip()
        if line:
            events.append(line)

failed_logins = []
role_changes = []
suspicious_access = []

for event in events:
    if "LOGIN_FAILED" in event:
        failed_logins.append(event)

    if "ROLE_CHANGED" in event:
        role_changes.append(event)

    if "SUSPICIOUS_ACCESS" in event:
        suspicious_access.append(event)

ip_counter = Counter()

for event in failed_logins:
    for part in event.split():
        if part.startswith("ip="):
            ip = part.split("=", 1)[1]
            ip_counter[ip] += 1

alerts = []

for ip, count in ip_counter.items():
    if count >= 3:
        alerts.append(
            f"[HIGH] Brute-force activity detected from {ip} ({count} failed logins)"
        )

for event in role_changes:
    alerts.append(f"[HIGH] Privilege change detected: {event}")

for event in suspicious_access:
    alerts.append(f"[MEDIUM] Suspicious access detected: {event}")

risk_score = 0

for alert in alerts:
    if "[HIGH]" in alert:
        risk_score += 30
    elif "[MEDIUM]" in alert:
        risk_score += 15

if risk_score >= 70:
    risk_level = "CRITICAL"
elif risk_score >= 40:
    risk_level = "HIGH"
elif risk_score >= 20:
    risk_level = "MEDIUM"
else:
    risk_level = "LOW"

incident_summary = []

if alerts:
    incident_summary.append("Security incidents detected:")
    incident_summary.extend(alerts)
else:
    incident_summary.append("No security incidents detected.")

report = [
    "CYBERSECURITY SOC REPORT",
    "=" * 45,
    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "",
    f"Events analyzed: {len(events)}",
    f"Failed logins: {len(failed_logins)}",
    f"Privilege changes: {len(role_changes)}",
    f"Suspicious access events: {len(suspicious_access)}",
    f"Security alerts: {len(alerts)}",
    f"Risk score: {risk_score}",
    f"Risk level: {risk_level}",
    "",
    "INCIDENT SUMMARY",
    "-" * 45
]

report.extend(incident_summary)

with open(REPORT_FILE, "w") as file:
    file.write("\n".join(report))

print("\n".join(report))
print(f"\nReport saved to: {REPORT_FILE}")
