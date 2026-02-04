import random
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app_models import PacketLog
from backend.app_models import Base

DB_URL = "sqlite:///./phantomnet.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(bind=engine)

PROTOCOLS = ["TCP", "UDP", "ICMP"]
IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.9",
    "8.8.8.8",
    "1.1.1.1"
]

def main():
    db = SessionLocal()
    now = datetime.utcnow()

    rows = []
    for i in range(350):
        rows.append(PacketLog(
            timestamp=now - timedelta(seconds=i * 5),
            src_ip=random.choice(IPS),
            dst_ip=random.choice(IPS),
            protocol=random.choice(PROTOCOLS),
            length=random.randint(40, 1500),
            is_malicious=random.random() > 0.8,
            threat_score=random.uniform(0, 100),
            attack_type=random.choice(["BENIGN", "SUSPICIOUS", "MALICIOUS"])
        ))

    db.add_all(rows)
    db.commit()
    db.close()

    print(f"✅ Inserted {len(rows)} synthetic packet logs")

if __name__ == "__main__":
    main()
