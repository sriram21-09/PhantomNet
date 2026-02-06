import sys
import os
import random
from datetime import datetime, timedelta

# --------------------------------------------------
# PATH FIX (CRITICAL FOR CI)
# --------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))

# Ensure backend is importable
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# --------------------------------------------------
# Imports (now safe)
# --------------------------------------------------
from database.database import SessionLocal, engine, Base
from database.models import AttackSession, Event
from ml.train_model import train_model

# --------------------------------------------------
# SEED + TRAIN
# --------------------------------------------------
def force_seed_and_train():
    print("🧹 Cleaning Database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    print("🌱 Injecting synthetic attack sessions...")

    for _ in range(50):
        attacker_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))

        session = AttackSession(
            attacker_ip=attacker_ip,
            start_time=datetime.utcnow(),
            threat_score=random.random() * 10
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        for _ in range(random.randint(5, 20)):
            event = Event(
                session_id=session.id,
                source_ip=attacker_ip,
                src_port=random.randint(1024, 65535),
                honeypot_type=random.choice(["ssh", "http", "ftp", "smtp"]),
                raw_data="CI synthetic seed",
                timestamp=datetime.utcnow() - timedelta(
                    minutes=random.randint(1, 60)
                )
            )
            db.add(event)

    db.commit()
    db.close()
    print("✅ Database seeded successfully")

    print("\n🧠 Starting ML training pipeline...")
    train_model()


if __name__ == "__main__":
    force_seed_and_train()
