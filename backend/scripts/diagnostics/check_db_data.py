import sys
import os
from sqlalchemy import create_engine, func, inspect, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Add current directory to path
# Add backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from database.models import PacketLog

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("DATABASE_URL not set")
    exit(1)

engine = create_engine(DATABASE_URL)

# Inspect Table Columns
inspector = inspect(engine)
columns = [col['name'] for col in inspector.get_columns("packet_logs")]
print(f"PacketLog Columns: {columns}")

SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

try:
    # Check packet_logs count using connection
    with engine.connect() as connection:
        result = connection.execute(text("SELECT COUNT(*) FROM packet_logs"))
        connection_count = result.scalar_one()
        print(f"Total PacketLogs (via connection): {connection_count}")

    count = db.query(PacketLog).count()
    print(f"Total PacketLogs (via ORM): {count}")
    
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
