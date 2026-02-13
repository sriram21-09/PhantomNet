import os
import json
import sys
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# ⚠️ REPLACE 'Luckky' WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@phantomnet_postgres:5432/phantomnet_db"

Base = declarative_base()

class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    honeypot_type = Column(String)
    port = Column(Integer)
    raw_data = Column(String)

def debug_test():
    print("🚀 STARTING DEBUG TEST...")
    
    # 1. Create a dummy log file
    log_filename = "debug_temp.json"
    with open(log_filename, "w") as f:
        f.write('{"timestamp": "2025-01-01 10:00:00", "src_ip": "9.9.9.9", "honeypot_type": "debug", "port": 80}\n')

    try:
        # 2. Connect to Database
        engine = create_engine(DATABASE_URL)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        
        # 3. Count before
        before = db.query(Event).count()
        print(f"📊 Rows Before: {before}")

        # 4. Read file and Insert
        with open(log_filename, "r") as f:
            for line in f:
                data = json.loads(line)
                new_event = Event(
                    timestamp=datetime.now(),
                    source_ip=data.get("src_ip"),
                    honeypot_type="debug",
                    port=80,
                    raw_data=line
                )
                db.add(new_event)
        
        db.commit() # The magic save button
        print("✅ Data Committed.")

        # 5. Count after
        after = db.query(Event).count()
        print(f"📊 Rows After:  {after}")

        if after > before:
            print("🎉 SUCCESS! Database works.")
        else:
            print("❌ FAILURE! No rows added.")

    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
    finally:
        if os.path.exists(log_filename):
            os.remove(log_filename)

if __name__ == "__main__":
    debug_test()
