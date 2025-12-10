import sys
import os
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.models import Event

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

def analyze_data():
    print("\n📊 PHANTOM-NET ANALYTICS REPORT 📊")
    print("="*40)

    total = session.query(Event).count()
    print(f"Total Detected Attacks: {total}")

    print("\n🚨 Top 5 Attacker IPs:")
    print("-" * 30)
    top_ips = session.query(Event.source_ip, func.count(Event.id).label('count')) \
        .group_by(Event.source_ip).order_by(desc('count')).limit(5).all()
    
    for ip, count in top_ips:
        print(f"IP: {ip:<20} | Count: {count}")

    print("="*40 + "\n")

if __name__ == "__main__":
    analyze_data()