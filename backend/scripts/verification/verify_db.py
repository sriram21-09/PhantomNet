from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from database.models import PacketLog
import os
from dotenv import load_dotenv

def main():
    load_dotenv()

    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "sqlite:///./phantomnet_ci.db"
    )

    print("🔍 STARTING DATABASE VERIFICATION...\n")

    # ---------------------------------------------------------
    # TASK 1: Check Connection
    # ---------------------------------------------------------
    print("[TASK 1] Checking Connection...")
    try:
        engine = create_engine(DATABASE_URL, echo=False)
        connection = engine.connect()
        print("   ✅ Connection successful")
        connection.close()
    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
        return

    # ---------------------------------------------------------
    # TASK 2: Validate Schema
    # ---------------------------------------------------------
    print("\n[TASK 2] Validating Schema...")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"   Tables found: {tables}")

    # ---------------------------------------------------------
    # TASK 3: ORM Test
    # ---------------------------------------------------------
    print("\n[TASK 3] Testing ORM...")
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        count = session.query(PacketLog).count()
        print(f"   Existing records: {count}")

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

        fetched = session.query(PacketLog).filter_by(attack_type="ORM_TEST").first()
        if fetched:
            print("   ✅ ORM write/read OK")
            session.delete(fetched)
            session.commit()
            print("   ✅ ORM delete OK")
        else:
            print("   ❌ ORM read failed")

    except Exception as e:
        print(f"   ❌ ORM error: {e}")
        session.rollback()
    finally:
        session.close()

    print("\n✅ VERIFICATION COMPLETE")

if __name__ == "__main__":
    main()
