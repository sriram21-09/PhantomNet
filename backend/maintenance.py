from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import sessionmaker
from app_models import Base, PacketLog
from dotenv import load_dotenv # <--- NEW IMPORT
import os

# 1. LOAD ENVIRONMENT VARIABLES (Crucial Fix)
load_dotenv() 

# 2. Setup Database Connection
# Now it gets the REAL path from your .env file
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fallback only if .env is missing
    DATABASE_URL = "sqlite:///./phantomnet.db"

print(f"🔌 Connecting to: {DATABASE_URL}")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

print("🧹 STARTING DATABASE HEALTH CHECK...\n")

# =========================================
# TASK 1: Validate Database Entries
# =========================================
print(f"🔍 [TASK 1] Validating Schema & Connection...")
try:
    # Check if table exists and connection is good
    count = db.query(PacketLog).count()
    print(f"   ✅ Connection Successful. Total Records: {count}")
except Exception as e:
    print(f"   ❌ Critical Error: {e}")
    print("   (Tip: Ensure you are running this from the 'backend' folder)")
    exit()

# =========================================
# TASK 2: Check for Anomalies or Nulls
# =========================================
print(f"\n🔍 [TASK 2] Scanning for Anomalies (Nulls & Invalid Data)...")

# Find records with missing IPs or Protocols
null_records = db.query(PacketLog).filter(
    (PacketLog.src_ip == None) | 
    (PacketLog.dst_ip == None) | 
    (PacketLog.protocol == None)
).all()

# Find "Time Travelers" (Future timestamps or way in the past)
invalid_time = db.query(PacketLog).filter(PacketLog.timestamp == None).all()

print(f"   ⚠️  Found {len(null_records)} records with NULL fields.")
print(f"   ⚠️  Found {len(invalid_time)} records with invalid timestamps.")

# =========================================
# TASK 3: Clean Inconsistent Records
# =========================================
print(f"\n🧹 [TASK 3] Cleaning Inconsistent Records...")

cleaned_count = 0

# A. Remove Nulls
if null_records:
    for record in null_records:
        db.delete(record)
    cleaned_count += len(null_records)
    print(f"   🗑️  Deleted {len(null_records)} corrupted/null logs.")

# Commit changes
db.commit()

if cleaned_count == 0:
    print("   ✨ Database is already clean. No actions needed.")
else:
    print(f"   ✅ Cleanup Complete. Removed {cleaned_count} bad records.")

# =========================================
# TASK 4: Verify Final Dataset Integrity
# =========================================
print(f"\n🛡️  [TASK 4] Verifying Final Integrity...")

# 1. Check for duplicates (Simple check based on timestamp + src + dst)
dupes = db.execute(text("""
    SELECT src_ip, dst_ip, timestamp, COUNT(*)
    FROM packet_logs
    GROUP BY src_ip, dst_ip, timestamp
    HAVING COUNT(*) > 1
""")).fetchall()

if dupes:
    print(f"   ⚠️  Warning: Found {len(dupes)} sets of duplicate logs.")
else:
    print("   ✅ No duplicates found.")

# 2. Final Count
final_count = db.query(PacketLog).count()
print(f"   📊 Final Valid Record Count: {final_count}")

print("\n✅ MAINTENANCE COMPLETE.")
db.close()
