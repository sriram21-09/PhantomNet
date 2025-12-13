import json
import os
import sys
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 🔧 Fix path to find 'backend' if run directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.models import Base, Event, Session

# ⚠️ REPLACE 'Luckky' WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

def ingest_logs(log_file_path):
    if not os.path.exists(log_file_path):
        print(f"❌ File not found: {log_file_path}")
        return

    # 1. Connect
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    print(f"📂 Processing: {log_file_path}")
    active_sessions = {}

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    
                    # Parse basics
                    ip = data.get("src_ip", "unknown")
                    ts_str = data.get("timestamp")
                    try:
                        timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    except:
                        timestamp = datetime.now()

                    # A. SAVE EVENT
                    new_event = Event(
                        timestamp=timestamp,
                        source_ip=ip,
                        honeypot_type=data.get("honeypot_type", "unknown"),
                        port=data.get("port", 0),
                        raw_data=json.dumps(data)
                    )
                    db.add(new_event)

                    # B. SESSION LOGIC
                    if ip in active_sessions:
                        sess = active_sessions[ip]
                        if (timestamp - sess.start_time) < timedelta(minutes=5):
                            sess.event_count += 1
                            sess.end_time = timestamp
                        else:
                            db.add(sess) # Save old session
                            # Start new
                            active_sessions[ip] = Session(
                                session_token=f"{ip}-{timestamp.timestamp()}",
                                start_time=timestamp, end_time=timestamp,
                                ip_address=ip, event_count=1
                            )
                    else:
                        active_sessions[ip] = Session(
                            session_token=f"{ip}-{timestamp.timestamp()}",
                            start_time=timestamp, end_time=timestamp,
                            ip_address=ip, event_count=1
                        )
                        # Ensure active_sessions holds the object
                        
                except json.JSONDecodeError:
                    continue
        
        # Save remaining sessions
        for sess in active_sessions.values():
            db.add(sess)

        # 🚨 FINAL COMMIT
        db.commit()
        print("✅ Data Successfully Saved to Database!")

    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    # Test run
    ingest_logs("test_logs.json")