import os
import time
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Import your actual models
from app_models import Base, PacketLog

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    logger.error("DATABASE_URL not found in .env")
    exit(1)

# DB Setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

# Track file positions to avoid re-reading
files_cursor = {}

def process_line(db, line, protocol):
    try:
        data = json.loads(line)
        
        # Map fields to PacketLog
        # Adjust these mappings based on what your honeypots actually output
        timestamp_str = data.get("timestamp")
        timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.utcnow()
        
        src_ip = data.get("source_ip") or data.get("src_ip") or "0.0.0.0"
        
        # Attack Type Logic (Simple rule based on event)
        event = data.get("event", "unknown")
        attack_type = "BENIGN"
        threat_score = 0.0
        
        if event in ["login_failed", "command", "exploit_attempt"]:
            attack_type = "SUSPICIOUS"
            threat_score = 50.0
        
        if event in ["malware_download", "shell_activity"]:
            attack_type = "MALICIOUS"
            threat_score = 90.0

        log_entry = PacketLog(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=data.get("dest_ip", "127.0.0.1"),
            protocol=protocol.upper(),
            length=data.get("length", 0),
            is_malicious=(threat_score > 0),
            threat_score=threat_score,
            attack_type=attack_type,
            # Store raw data in a suitable field if needed, or just specific fields
        )
        db.add(log_entry)
        return True
    except Exception as e:
        logger.error(f"Error processing line: {e}")
        return False

def ingest_logs():
    db = SessionLocal()
    try:
        # Define log files to watch
        log_files = {
            "ssh": os.path.join(LOG_DIR, "ssh.jsonl"),  # This one was correct
            "http": os.path.join(LOG_DIR, "http_logs.jsonl"),
            "ftp": os.path.join(LOG_DIR, "ftp_logs.jsonl"),
            "smtp": os.path.join(LOG_DIR, "smtp_logs.jsonl"),
        }

        for proto, filepath in log_files.items():
            if not os.path.exists(filepath):
                continue
            
            # Get current size
            current_size = os.path.getsize(filepath)
            last_position = files_cursor.get(filepath, 0)
            
            if current_size > last_position:
                logger.info(f"New data in {proto} log...")
                with open(filepath, "r") as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    files_cursor[filepath] = f.tell()
                
                count = 0
                for line in new_lines:
                    if process_line(db, line, proto):
                        count += 1
                
                if count > 0:
                    db.commit()
                    logger.info(f"Ingested {count} {proto} logs.")
            
    except Exception as e:
        logger.error(f"Ingestor Loop Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Starting Simple Log Ingestor...")
    logger.info(f"Watching logs in: {LOG_DIR}")
    
    # Initialize cursors to end of file (optional: start from beginning if you want to import history)
    # For now, let's start from BEGINNING to import even past logs for 'Last Seen'
    # files_cursor = {} 
    
    while True:
        ingest_logs()
        time.sleep(5)
