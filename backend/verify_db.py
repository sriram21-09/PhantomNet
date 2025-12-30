from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from app_models import Base, PacketLog
import os
from dotenv import load_dotenv
import time

# 1. Load Config
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

print("🔍 STARTING DATABASE VERIFICATION...\n")

# ---------------------------------------------------------
# TASK 1 & 4: Confirm Access & Check Pooling Config
# ---------------------------------------------------------
print(f"[TASK 1 & 4] Checking Connection & Pooling...")
if not DATABASE_URL:
    print("   ❌ Error: DATABASE_URL is missing from .env")
    exit()

try:
    # Creating engine with default pool settings (usually pool_size=5 for Postgres)
    engine = create_engine(DATABASE_URL, echo=False)
    connection = engine.connect()
    print(f"   ✅ Connection Successful: {DATABASE_URL.split('@')[1]}") # Hide password
    
    # Check Pool Status
    pool_status = engine.pool.status()
    print(f"   ✅ Connection Pool Status: {pool_status}")
    connection.close()
except Exception as e:
    print(f"   ❌ Connection Failed: {e}")
    exit()

# ---------------------------------------------------------
# TASK 2: Validate Database Schema
# ---------------------------------------------------------
print(f"\n[TASK 2] Validating Schema against Design...")
inspector = inspect(engine)
tables = inspector.get_table_names()

if not tables:
    print("   ⚠️  Warning: Database is empty (No tables found).")
else:
    print(f"   ✅ Tables Found: {tables}")
    
    # Check specific table structure (packet_logs)
    if 'packet_logs' in tables:
        columns = [col['name'] for col in inspector.get_columns('packet_logs')]
        expected_cols = ['src_ip', 'dst_ip', 'protocol', 'threat_score']
        
        # Check if critical columns exist
        missing = [col for col in expected_cols if col not in columns]
        if missing:
            print(f"   ❌ Schema Mismatch! Missing columns in 'packet_logs': {missing}")
        else:
            print(f"   ✅ Schema Validated: 'packet_logs' has all required columns.")

# ---------------------------------------------------------
# TASK 3 & 5: Verify Data & Run ORM Operations
# ---------------------------------------------------------
print(f"\n[TASK 3 & 5] Verifying Data & ORM Operations...")
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

try:
    # A. Check Data Count
    count = session.query(PacketLog).count()
    print(f"   📊 Existing Data: {count} records in 'packet_logs'")

    if count == 0:
        print("   ⚠️  Table is empty. Running ORM Test insert...")

    # B. Run Basic ORM Operation (Insert -> Read -> Delete)
    # 1. Create
    test_log = PacketLog(
        src_ip="1.1.1.1", 
        dst_ip="2.2.2.2", 
        protocol="TEST", 
        length=0, 
        is_malicious=False, 
        threat_score=0.0,
        attack_type="ORM_TEST"
    )
    session.add(test_log)
    session.commit()
    
    # 2. Read
    fetched_log = session.query(PacketLog).filter(PacketLog.attack_type == "ORM_TEST").first()
    if fetched_log:
        print(f"   ✅ ORM Write/Read Test: SUCCESS (ID: {fetched_log.id})")
        
        # 3. Delete (Cleanup)
        session.delete(fetched_log)
        session.commit()
        print(f"   ✅ ORM Delete Test: SUCCESS")
    else:
        print(f"   ❌ ORM Read Failed!")

except Exception as e:
    print(f"   ❌ ORM Error: {e}")
finally:
    session.close()

print("\n✅ VERIFICATION COMPLETE.")