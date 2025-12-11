from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.models import Session

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

print("\n🔍 Recent Sessions:")
print(f"{'IP ADDRESS':<16} | {'START TIME':<20} | {'COUNT'} | {'SESSION ID'}")
print("-" * 75)
results = db.query(Session).order_by(desc(Session.start_time)).limit(5).all()
for s in results:
    print(f"{s.src_ip:<16} | {str(s.start_time):<20} | {s.event_count:<5} | {s.session_id}")
print("-" * 75 + "\n")