import sys
import os
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Add current directory to path
sys.path.append(os.getcwd())

from app_models import PacketLog

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("DATABASE_URL not set")
    exit(1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

try:
    count = db.query(PacketLog).count()
    print(f"Total PacketLogs: {count}")
    
    if count > 0:
        print("\nLogs per Protocol:")
        results = db.query(PacketLog.protocol, func.count(PacketLog.id), func.max(PacketLog.timestamp)).group_by(PacketLog.protocol).all()
        for proto, cnt, last in results:
            print(f"  {proto}: {cnt} logs (Last: {last})")
            
        print("\nFirst 3 Logs:")
        first_logs = db.query(PacketLog).limit(3).all()
        for l in first_logs:
            print(f"  [{l.timestamp}] {l.protocol} {l.src_ip} -> {l.threat_score}")
    else:
        print("Database is empty.")

except Exception as e:
    print(f"Error: {e}")
finally:
    db.close()
