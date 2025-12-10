import json
import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 1. Setup paths to import 'database' module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import from the Team's existing model file
from database.models import Event

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def detect_type_from_filename(filename):
    filename_lower = filename.lower()
    if "http" in filename_lower:
        return "http-honeypot"
    elif "ssh" in filename_lower:
        return "ssh-honeypot"
    return "unknown"

def ingest_logs(file_path):
    print(f"📂 Reading logs from: {file_path}")
    
    if not os.path.exists(file_path):
        print("❌ Error: File not found.")
        return

    filename = os.path.basename(file_path)
    detected_type = detect_type_from_filename(filename)
    print(f"🕵️  Detected Log Type: {detected_type}")

    count = 0
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                except:
                    continue 
                
                h_type = data.get("honeypot_type") or detected_type
                default_port = 80 if "http" in detected_type else 22

                new_event = Event(
                    timestamp=data.get("timestamp"),
                    source_ip=data.get("src_ip") or data.get("source_ip"),
                    honeypot_type=h_type,
                    port=data.get("port", default_port),
                    raw_data=json.dumps(data)
                )
                session.add(new_event)
                count += 1
        
        session.commit()
        print(f"✅ Success! Inserted {count} events.")

    except Exception as e:
        session.rollback()
        print(f"❌ Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m ingestor.log_ingestor <file>")
    else:
        ingest_logs(sys.argv[1])