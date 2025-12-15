from sqlalchemy import create_engine, func, distinct
from sqlalchemy.orm import sessionmaker
import os
import sys

# Setup Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(os.path.dirname(parent_dir))

from backend.database.models import Base, Event, Session

# ⚠️ REPLACE WITH YOUR PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

def run_analytics():
    print("📊 PHANTOM-NET WEEK 1 ANALYTICS")
    print("==================================")
    
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        # 1. Total Events
        total_events = db.query(func.count(Event.id)).scalar()
        print(f"🔹 Total Events: {total_events}")

        # 2. Unique IPs
        unique_ips = db.query(func.count(distinct(Event.source_ip))).scalar()
        print(f"🔹 Unique Attacker IPs: {unique_ips}")

        # 3. Top Honeypots
        print("\n📈 Attacks per Honeypot:")
        results = db.query(Event.honeypot_type, func.count(Event.id))\
                    .group_by(Event.honeypot_type)\
                    .order_by(func.count(Event.id).desc()).all()
        
        for h_type, count in results:
            print(f"   - {h_type}: {count}")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    run_analytics()