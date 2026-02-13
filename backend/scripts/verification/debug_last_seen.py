from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# Import Models
from database.models import PacketLog
from database.database import SessionLocal

load_dotenv()

db = SessionLocal()

print("--- Debugging Last Seen Logic ---")

try:
    # 1. Check raw distinct values
    raw_protos = db.query(PacketLog.protocol).distinct().all()
    print(f"Raw Protocols in DB: {[repr(p[0]) for p in raw_protos]}")

    # 2. Replicate main.py Logic
    last_seen_map = {}
    results = db.query(
        PacketLog.protocol, 
        func.max(PacketLog.timestamp)
    ).group_by(PacketLog.protocol).all()

    print("\nQuery Results (from main.py logic):")
    for protocol, last_time in results:
        print(f"  Protocol: {repr(protocol)}, Max Time: {last_time}")
        if last_time:
            last_seen_map[protocol] = last_time.strftime("%Y-%m-%d %H:%M:%S")

    print("\nLast Seen Map:")
    print(last_seen_map)

    # 3. Check Lookup
    target = "SSH"
    print(f"\nLooking up '{target}': {last_seen_map.get(target, 'Never')}")

except Exception as e:
    print(f"Error: {e}")
finally:
    db.close()
