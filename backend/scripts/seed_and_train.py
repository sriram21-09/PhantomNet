import sys
import os
import random
from datetime import datetime, timedelta

# --------------------------------------------------
# PATH SETUP
# --------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
BACKEND_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

# --------------------------------------------------
# CI DETECTION
# --------------------------------------------------
IS_CI = os.getenv("CI", "false").lower() == "true"

# --------------------------------------------------
# IMPORTS
# --------------------------------------------------
from ml.train_model import train_model

# Only import DB stuff when NOT in CI
from database.database import SessionLocal, engine, Base
from database.models import AttackSession, Event

# --------------------------------------------------
# SEED + TRAIN
# --------------------------------------------------
def force_seed_and_train():
    if IS_CI:
        print("⚠️ CI detected — creating tables but skipping extensive seeding")
        # Start fresh in CI
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        
        # Seed minimal data to allow training to run (needs >= 5 sessions)
        db = SessionLocal()
        print("🌱 Seeding minimal CI data...")
        for _ in range(6):
            session = AttackSession(
                attacker_ip="127.0.0.1",
                start_time=datetime.utcnow(),
                threat_score=5.0,
            )
            db.add(session)
            db.commit()
            db.refresh(session)
            # Add at least one event
            event = Event(
                session_id=session.id,
                source_ip="127.0.0.1",
                src_port=80,
                honeypot_type="http",
                raw_data="CI data",
                timestamp=datetime.utcnow()
            )
            db.add(event)
        db.commit()
        db.close()
            
        print("🧠 Running ML training...")
        train_model()
        return

    print("🧹 Cleaning PostgreSQL database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    print("🌱 Seeding PostgreSQL with synthetic attack data...")

    for _ in range(50):
        attacker_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))

        session = AttackSession(
            attacker_ip=attacker_ip,
            start_time=datetime.utcnow(),
            threat_score=random.random() * 10,
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
                raw_data="Local PostgreSQL seed",
                timestamp=datetime.utcnow()
                - timedelta(minutes=random.randint(1, 60)),
            )
            db.add(event)

    db.commit()
    db.close()
    print("✅ PostgreSQL seeding complete")

    print("\n🧠 Starting ML training...")
    train_model()


if __name__ == "__main__":
    force_seed_and_train()
