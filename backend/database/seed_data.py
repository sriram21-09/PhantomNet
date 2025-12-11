from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
import random
import sys
import os

# Setup path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.models import Event

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

def seed():
    print("🌱 Seeding database with test events...")
    
    ips = ["192.168.1.5", "10.0.0.99", "45.33.22.11", "203.0.113.55"]
    types = ["ssh-honeypot", "http-honeypot", "cowrie", "dionaea"]
    
    events = []
    for i in range(10):
        e = Event(
            timestamp=datetime.datetime.now() - datetime.timedelta(minutes=random.randint(1, 60)),
            source_ip=random.choice(ips),
            honeypot_type=random.choice(types),
            port=random.randint(22, 8080),
            raw_data="Simulated Attack"
        )
        events.append(e)

    db.add_all(events)
    db.commit()
    print(f"✅ Success! Added {len(events)} fake attacks to the Events table.")

if __name__ == "__main__":
    seed()