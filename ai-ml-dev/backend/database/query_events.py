import sys
import os
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

# Setup paths
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import Event

# ⚠️ REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def get_recent_events():
    print("\n🔍 Querying Last 10 Events...")
    print("="*75)
    print(f"{'ID':<5} | {'TIMESTAMP':<20} | {'TYPE':<15} | {'IP ADDRESS'}")
    print("-" * 75)

    events = session.query(Event).order_by(desc(Event.id)).limit(10).all()
    
    if not events:
        print("No events found.")
    else:
        for event in events:
            ts = str(event.timestamp)
            print(f"{event.id:<5} | {ts[:19]:<20} | {event.honeypot_type:<15} | {event.source_ip}")
    
    print("="*75 + "\n")

if __name__ == "__main__":
    get_recent_events()