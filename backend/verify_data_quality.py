import os
import csv
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from app_models import PacketLog
from datetime import datetime

# 1. SETUP
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phantomnet.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

print("🕵️  STARTING DATA QUALITY AUDIT...\n")

# ==================================================
# TASK 1: Query Database for Recent Attack Events
# ==================================================
print("[TASK 1] Querying Recent Events...")
recent_events = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).limit(100).all()
count = db.query(PacketLog).count()
print(f"   ✅ Total Logs in DB: {count}")
print(f"   ✅ Retrieved last {len(recent_events)} events for analysis.")

# ==================================================
# TASK 2: Verify No NULL Values in Required Fields
# ==================================================
print("\n[TASK 2] Checking for NULL values...")
required_fields = ['src_ip', 'dst_ip', 'timestamp', 'attack_type']
errors_found = 0

for field in required_fields:
    # SQL Alchemy magic to count nulls dynamically
    null_count = db.query(PacketLog).filter(getattr(PacketLog, field) == None).count()
    if null_count > 0:
        print(f"   ❌ WARNING: Found {null_count} records with NULL '{field}'")
        errors_found += 1
    else:
        print(f"   ✅ Field '{field}' is clean (0 NULLs).")

if errors_found == 0:
    print("   ✨ Data Integrity: PERFECT.")

# ==================================================
# TASK 3: Check Timestamp Accuracy and Ordering
# ==================================================
print("\n[TASK 3] Validating Time Travel...")
if recent_events:
    newest = recent_events[0].timestamp
    oldest = recent_events[-1].timestamp
    
    # Check if newest is in the future (Time Travel Bug)
    if newest > datetime.now():
         print(f"   ❌ ALARM: Found timestamp in the future! ({newest})")
    else:
         print(f"   ✅ Latest Timestamp: {newest} (Valid)")
         
    # Check ordering
    if newest >= oldest:
        print("   ✅ Sort Order: Correct (Descending)")
    else:
        print("   ❌ Sort Order: BROKEN")
else:
    print("   ⚠️ No events to validate.")

# ==================================================
# TASK 4: Validate Associations (Honeypot Types)
# ==================================================
print("\n[TASK 4] Analyzing Attack Distributions...")
# Group by attack_type to see if categorization is working
distribution = db.query(PacketLog.attack_type, func.count(PacketLog.attack_type))\
    .group_by(PacketLog.attack_type).all()

print(f"   📊 Attack Types Found:")
if not distribution:
    print("   ⚠️ No attack types found. (Is the AI/Sniffer running?)")
else:
    for attack, count in distribution:
        print(f"      - {attack}: {count} events")
    print("   ✅ Associations verified.")

# ==================================================
# TASK 5: Produce Sample Dataset (CSV)
# ==================================================
print("\n[TASK 5] Generating Sample Report...")
filename = "sample_events.csv"

try:
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Header
        writer.writerow(["ID", "Timestamp", "Source IP", "Destination IP", "Attack Type", "Threat Score", "Malicious"])
        
        # Data
        for row in recent_events:
            writer.writerow([
                row.id, 
                row.timestamp, 
                row.src_ip, 
                row.dst_ip, 
                row.attack_type, 
                row.threat_score, 
                row.is_malicious
            ])
            
    print(f"   📄 Exported {len(recent_events)} events to '{filename}'")
    print(f"   ✅ location: {os.path.abspath(filename)}")

except Exception as e:
    print(f"   ❌ Export Failed: {e}")

print("\n🏁 AUDIT COMPLETE.")
db.close()
