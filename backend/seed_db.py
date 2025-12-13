print("--------------------------------------------------")
print("🚀 SCRIPT STARTED: If you see this, Python is working!")
print("--------------------------------------------------")

import random
import sys
import os
import uuid
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 1. SETUP PATHS
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# 2. IMPORTS
print("🔍 Importing Database Models...")
try:
    from database.models import Base, Event, Session
    print("✅ Imports Successful!")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)

# ⚠️ YOUR DATABASE URL
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

print("🌱 Connecting to Database...")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

ips = ["192.168.1.50", "10.10.5.1", "203.0.113.8", "45.33.22.11", "172.16.0.5"]
types = ["ssh-honeypot", "cowrie", "dionaea", "elastic-honey", "rdp-pot"]

events = []
sessions = []

print("⚡ Generating 50 fake attacks...")

for i in range(50):
    ts = datetime.now() - timedelta(minutes=random.randint(1, 1440))
    ip = random.choice(ips)
    
    event = Event(
        timestamp=ts,
        source_ip=ip,
        honeypot_type=random.choice(types),
        port=random.randint(22, 9000),
        raw_data=f"{{'simulated_id': {i}, 'risk': 'medium'}}"
    )
    events.append(event)

    if i % 5 == 0:
        sess = Session(
            session_token=str(uuid.uuid4()),
            start_time=ts,
            end_time=ts + timedelta(minutes=5),
            ip_address=ip,
            event_count=random.randint(1, 10)
        )
        sessions.append(sess)

db.add_all(events)
db.add_all(sessions)
db.commit()

print("--------------------------------------------------")
print(f"🎉 SUCCESS! Inserted {len(events)} events.")
print("--------------------------------------------------")