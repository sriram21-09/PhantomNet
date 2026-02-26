import os
import time
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from database.models import PacketLog

def run_diagnostics():
    load_dotenv()

    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "sqlite:///./phantomnet_ci.db"
    )

    print(f"🔌 CONFIG: {DATABASE_URL}")

    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    print("\n🚀 STARTING DATABASE DIAGNOSTICS...\n")

    # TASK 1: Connectivity
    print("[TASK 1] Checking connectivity...")
    try:
        start = time.time()
        session.execute(text("SELECT 1"))
        latency = (time.time() - start) * 1000
        print(f"   ✅ Connected ({latency:.2f}ms)")
    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
        return

    # TASK 2: Schema
    print("\n[TASK 2] Checking schema...")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"   Tables: {tables}")

    # TASK 3: Data
    print("\n[TASK 3] Checking data...")
    count = session.query(PacketLog).count()
    print(f"   Total rows: {count}")

    # TASK 4: ORM CRUD
    print("\n[TASK 4] ORM CRUD test...")
    try:
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

        read_log = session.query(PacketLog).filter_by(attack_type="DB_TEST").first()
        if read_log:
            print("   ✅ Create/Read OK")
            session.delete(read_log)
            session.commit()
            print("   ✅ Delete OK")
        else:
            print("   ❌ Read failed")

    except Exception as e:
        print(f"   ❌ ORM failed: {e}")
        session.rollback()
    finally:
        session.close()

    print("\n🏁 DIAGNOSTICS COMPLETE")

if __name__ == "__main__":
    run_diagnostics()
