import os
import time
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from app_models import Base, PacketLog, TrafficStats 

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# If .env is missing, fallback to SQLite for safety
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./phantomnet.db"

print(f"🔌 CONFIG: Checking connection to: {DATABASE_URL}")

# Create Engine with Pooling constraints
engine = create_engine(
    DATABASE_URL, 
    pool_size=10,        
    max_overflow=20,     
    pool_timeout=30      
)
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

def run_diagnostics():
    print("\n🚀 STARTING DATABASE DIAGNOSTICS...\n")

    # ==========================================
    # TASK 1: Confirm Instance is Accessible
    # ==========================================
    print("[TASK 1] Checking Connectivity...")
    try:
        start = time.time()
        session.execute(text("SELECT 1"))
        latency = (time.time() - start) * 1000
        print(f"   ✅ Connection Successful! Latency: {latency:.2f}ms")
    except Exception as e:
        print(f"   ❌ CONNECTION FAILED: {e}")
        return

    # ==========================================
    # TASK 2: Validate Schema Against Design
    # ==========================================
    print("\n[TASK 2] Validating Schema...")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    expected_tables = ["packet_logs", "traffic_stats"]
    missing = [t for t in expected_tables if t not in tables]

    if missing:
        print(f"   ❌ MISSING TABLES: {missing}")
    else:
        print(f"   ✅ All expected tables found: {tables}")
        
    # Check Columns
    columns = [c['name'] for c in inspector.get_columns("packet_logs")]
    if "threat_score" in columns and "src_ip" in columns:
        print("   ✅ Critical columns verified.")
    else:
        print("   ❌ Schema mismatch! Missing critical columns.")

    # ==========================================
    # TASK 3: Verify Data Existence
    # ==========================================
    print("\n[TASK 3] Verifying Test Data...")
    count = session.query(PacketLog).count()
    print(f"   📊 Total Events Logged: {count}")
    
    if count > 0:
        print("   ✅ Data exists. Table is populated.")
    else:
        print("   ⚠️  Table is empty. Run the Sniffer to generate data.")

    # ==========================================
    # TASK 4: Check Connection Pooling
    # ==========================================
    print("\n[TASK 4] Inspecting Connection Pool...")
    try:
        pool_status = engine.pool.status()
        print(f"   ℹ️  Pool Status: {pool_status}")
        print("   ✅ Pooling is active.")
    except:
        print("   ℹ️  Pooling info unavailable (SQLite limitation).")

    # ==========================================
    # TASK 5: Basic SQLAlchemy ORM Operations
    # ==========================================
    print("\n[TASK 5] Testing CRUD Operations...")
    try:
        # CREATE
        test_log = PacketLog(
            src_ip="99.99.99.99",
            dst_ip="127.0.0.1",
            protocol="TEST",
            length=0,
            threat_score=0.0,
            is_malicious=False,
            attack_type="DB_TEST"
        )
        session.add(test_log)
        session.commit()
        print("   1. Create: Success")

        # READ
        read_log = session.query(PacketLog).filter_by(src_ip="99.99.99.99", attack_type="DB_TEST").first()
        if read_log:
            print(f"   2. Read: Success (Found ID: {read_log.id})")
        else:
            print("   2. Read: Failed")

        # DELETE
        if read_log:
            session.delete(read_log)
            session.commit()
            print("   3. Delete: Success")
        
        print("   ✅ ORM Operations verified.")

    except Exception as e:
        print(f"   ❌ ORM Test Failed: {e}")
        session.rollback()

    print("\n🏁 DIAGNOSTICS COMPLETE.")

if __name__ == "__main__":
    run_diagnostics()