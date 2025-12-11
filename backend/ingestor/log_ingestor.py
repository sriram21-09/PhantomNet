import json
import sys
import os
import uuid
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Setup paths
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.models import Event, Session

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

def detect_type_from_filename(filename):
    if "http" in filename.lower(): return "http-honeypot"
    elif "ssh" in filename.lower(): return "ssh-honeypot"
    return "unknown"

def ingest_logs(file_path):
    print(f"📂 Processing Session Data from: {file_path}")
    
    if not os.path.exists(file_path):
        print("❌ Error: File not found.")
        return

    # 1. Read all events into memory first
    raw_events = []
    filename = os.path.basename(file_path)
    detected_type = detect_type_from_filename(filename)

    with open(file_path, 'r') as f:
        for line in f:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                # Parse timestamp
                ts_str = data.get("timestamp")
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except:
                    ts = datetime.fromisoformat(ts_str)

                event_obj = {
                    "timestamp": ts,
                    "src_ip": data.get("src_ip") or data.get("source_ip"),
                    "type": data.get("honeypot_type") or detected_type,
                    "raw": line
                }
                raw_events.append(event_obj)
            except Exception as e:
                continue

    # 2. Sort by IP, then by Time
    raw_events.sort(key=lambda x: (x['src_ip'], x['timestamp']))

    # 3. Group into Sessions (5-minute window)
    if not raw_events:
        print("No events found.")
        return

    current_session = None
    sessions_created = 0

    for event in raw_events:
        # Check if we can add to current session
        is_same_ip = current_session and current_session['src_ip'] == event['src_ip']
        
        if is_same_ip:
            time_diff = event['timestamp'] - current_session['end_time']
            if time_diff <= timedelta(minutes=5):
                # Extend session
                current_session['end_time'] = event['timestamp']
                current_session['count'] += 1
                continue

        # If not, save previous session and start new one
        if current_session:
            save_session(current_session)
            sessions_created += 1

        # Start new session
        current_session = {
            "session_id": str(uuid.uuid4()),
            "src_ip": event['src_ip'],
            "type": event['type'],
            "start_time": event['timestamp'],
            "end_time": event['timestamp'],
            "count": 1
        }

    # Save the last session
    if current_session:
        save_session(current_session)
        sessions_created += 1
    
    print(f"✅ Logic Complete. Created {sessions_created} Sessions from {len(raw_events)} events.")

def save_session(session_data):
    new_session = Session(
        session_id=session_data['session_id'],
        src_ip=session_data['src_ip'],
        honeypot_type=session_data['type'],
        start_time=session_data['start_time'],
        end_time=session_data['end_time'],
        event_count=session_data['count']
    )
    db.add(new_session)
    db.commit()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m ingestor.log_ingestor <file>")
    else:
        ingest_logs(sys.argv[1])