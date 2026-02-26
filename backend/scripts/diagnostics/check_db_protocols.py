import sys
import os
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Add current directory to path
# Add backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Import Models
from database.models import PacketLog

# Import DB Connection
# Try to import SessionLocal from where it is defined
try:
    from database.database import SessionLocal
except ImportError:
    # Fallback if not found, recreate it
    load_dotenv()
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        print("DATABASE_URL not set")
        exit(1)
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)

db = SessionLocal()

try:
    print("Checking Database Protocols...")
    results = db.query(PacketLog.protocol, func.count(PacketLog.id), func.max(PacketLog.timestamp)).group_by(PacketLog.protocol).all()
    
    print(f"{'Protocol':<10} | {'Count':<10} | {'Last Seen'}")
    print("-" * 50)
    for proto, cnt, last in results:
        print(f"{proto:<10} | {cnt:<10} | {last}")

except Exception as e:
    print(f"Error: {e}")
finally:
    db.close()
