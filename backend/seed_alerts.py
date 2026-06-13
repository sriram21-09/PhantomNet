"""Seed realistic security alerts into the database for dashboard testing."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.database import SessionLocal
from database.models import Alert
from datetime import datetime, timedelta
import random
import json

db = SessionLocal()

alert_templates = [
    ("HIGH", "SSH_BRUTE_FORCE", "Multiple failed SSH login attempts detected from suspicious IP", "192.168.1.105"),
    ("CRITICAL", "SQL_INJECTION", "SQL injection payload detected in HTTP request to /admin", "10.0.0.42"),
    ("MEDIUM", "PORT_SCAN", "Sequential port scanning activity detected on honeypot network", "172.16.0.88"),
    ("HIGH", "MALWARE_DELIVERY", "EICAR test string detected in SMTP payload", "203.0.113.15"),
    ("LOW", "RECON_ACTIVITY", "Directory traversal attempt on HTTP honeypot", "198.51.100.22"),
    ("MEDIUM", "FTP_BRUTE_FORCE", "Repeated FTP authentication failures from single source", "10.0.0.99"),
    ("HIGH", "LATERAL_MOVEMENT", "Suspicious cross-honeypot connection pattern detected", "172.19.0.3"),
    ("CRITICAL", "DATA_EXFILTRATION", "Abnormal outbound data volume detected from FTP honeypot", "192.168.2.50"),
    ("MEDIUM", "DNS_TUNNELING", "Potential DNS tunneling activity detected", "10.10.10.15"),
    ("HIGH", "CREDENTIAL_STUFFING", "High-volume credential testing against SSH service", "45.33.32.156"),
    ("LOW", "BANNER_GRAB", "Service banner enumeration detected on multiple ports", "192.168.1.200"),
    ("MEDIUM", "SMTP_RELAY", "Open relay probe attempt on SMTP honeypot", "198.51.100.44"),
]

now = datetime.utcnow()
for i, (level, atype, desc, ip) in enumerate(alert_templates):
    details = json.dumps({"protocol": atype.split("_")[0], "event_count": random.randint(3, 50)})
    alert = Alert(
        level=level,
        type=atype,
        source_ip=ip,
        description=desc,
        details=details,
        timestamp=now - timedelta(minutes=random.randint(1, 120)),
        is_resolved=(i > 9),
    )
    db.add(alert)

db.commit()
print(f"Seeded {len(alert_templates)} alerts")
print(f"Total alerts in DB: {db.query(Alert).count()}")
db.close()
