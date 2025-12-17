import sys
import os
import random
from datetime import datetime, timedelta

# Add backend to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import SessionLocal, engine, Base
from database.models import AttackSession, Event
from ml.train_model import train_model

def force_seed_and_train():
    print("🧹 Cleaning Database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    print("🌱 Injecting 50 Fake Hackers directly into SQL...")

    for i in range(50):
        # 1. Create a Fake Session
        attacker_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        session = AttackSession(
            attacker_ip=attacker_ip,
            start_time=datetime.utcnow(),
            threat_score=random.random() * 10
        )
        db.add(session)
        db.commit() # Save to get the ID

        # 2. Add some events to this session
        for _ in range(random.randint(5, 20)):
            event = Event(
                session_id=session.id,
                source_ip=attacker_ip,
                src_port=random.randint(1024, 65535),
                honeypot_type=random.choice(["ssh", "http", "smb"]),
                raw_data="Direct DB Seed",
                timestamp=datetime.utcnow() - timedelta(minutes=random.randint(1, 60))
            )
            db.add(event)
    
    db.commit()
    print("✅ Database successfully seeded with diverse data!")
    db.close()

    print("\n🧠 Starting Training immediately...")
    train_model()

if __name__ == "__main__":
    force_seed_and_train()