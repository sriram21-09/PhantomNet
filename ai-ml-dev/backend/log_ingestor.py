import json
import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 1. Setup paths to import 'database' module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.models import Base, Event

# 2. Database Config (REPLACE PASSWORD HERE)
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def ingest_logs(file_path):
    print(f"📂 Reading logs from: {file_path}")
    
    if not os.path.exists(file_path):
        print("❌ Error: File not found.")
        return

    count = 0
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue # Skip empty lines
                
                # Parse JSON line
                data = json.loads(line)
                
                # Map JSON fields to Database Columns
                # We use .get() to avoid crashing if a field is missing
                new_event = Event(
                    timestamp=data.get("timestamp"),
                    source_ip=data.get("src_ip") or data.get("source_ip"),
                    honeypot_type=data.get("honeypot_type", "unknown"),
                    port=data.get("port", 0),
                    # Store the whole JSON blob as a string in raw_data
                    raw_data=json.dumps(data) 
                )
                
                session.add(new_event)
                count += 1
        
        session.commit()
        print(f"✅ Success! Inserted {count} log entries into the database.")

    except Exception as e:
        session.rollback()
        print(f"❌ Error processing logs: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    # Allow running script with a file argument
    if len(sys.argv) < 2:
        print("Usage: python -m ingestor.log_ingestor <path_to_log_file>")
    else:
        log_file = sys.argv[1]
        ingest_logs(log_file)