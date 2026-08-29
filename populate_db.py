import random
import datetime
import sys
import os

# Ensure backend modules can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from database.database import SessionLocal
from database.models import PacketLog

db = SessionLocal()

current_count = db.query(PacketLog).count()
target_count = 1000
needed = max(0, target_count - current_count)

if needed > 0:
    print(f"Adding {needed} realistic rows to packet_logs...")
    protocols = ["TCP", "UDP", "ICMP"]
    attack_types = ["BENIGN", "SSH_AUTH_FAILURE", "HTTP_SQL_INJECTION", "HTTP_SCANNER_BEHAVIOR", "PORT_SCAN", "BENIGN"]
    sample_ips = [
        ("192.168.1.105", "US", "New York", 40.7128, -74.0060),
        ("10.0.1.15", "DE", "Frankfurt", 50.1109, 8.6821),
        ("185.220.101.5", "RU", "Moscow", 55.7558, 37.6173),
        ("45.146.164.110", "NL", "Amsterdam", 52.3676, 4.9041),
        ("103.203.57.18", "IN", "Mumbai", 19.0760, 72.8777),
        ("192.168.1.200", "Local Network", "Internal", 0.0, 0.0)
    ]

    batch = []
    now = datetime.datetime.utcnow()

    for i in range(needed):
        src_info = random.choice(sample_ips)
        proto = random.choice(protocols)
        attack = random.choice(attack_types)
        score = random.uniform(70.0, 98.0) if attack != "BENIGN" else random.uniform(0.0, 25.0)
        level = "CRITICAL" if score >= 80 else ("HIGH" if score >= 60 else ("MEDIUM" if score >= 40 else "LOW"))
        
        log = PacketLog(
            timestamp=now - datetime.timedelta(minutes=random.randint(1, 1440)),
            src_ip=src_info[0],
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([22, 80, 443, 8080, 2121, 2525, 445]),
            protocol=proto,
            length=random.randint(64, 1500),
            attack_type=attack,
            threat_score=round(score, 2),
            threat_level=level,
            confidence=round(random.uniform(0.75, 0.99), 2),
            is_malicious=(attack != "BENIGN"),
            anomaly_score=round(score / 100.0, 3),
            country=src_info[1],
            city=src_info[2],
            latitude=src_info[3],
            longitude=src_info[4]
        )
        batch.append(log)

    db.bulk_save_objects(batch)
    db.commit()
    print(f"✅ Successfully added {needed} records. Total packet_logs in DB: {db.query(PacketLog).count()}")
else:
    print(f"Database already has {current_count} packet log rows.")

db.close()

