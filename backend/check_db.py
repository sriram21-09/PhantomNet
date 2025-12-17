import sys
import os

# 1. Setup the path so Python finds your database folder
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

try:
    from database.database import SessionLocal
    from database.models import Event
    print("✅ Imports Successful!")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)

def check_database():
    print("\n-------------------------------------")
    print("🧪 TEST 5: Checking Database Connection")
    print("-------------------------------------")
    
    # 2. Connect to Database
    try:
        db = SessionLocal()
        print("✅ Database Connection Open")
    except Exception as e:
        print(f"❌ Could not connect: {e}")
        return

    # 3. Find the Log from Test 4
    # We look for the specific IP '10.0.0.5' we just sent
    log = db.query(Event).filter(Event.source_ip == "10.0.0.5").first()

    if log:
        print(f"🎉 SUCCESS! Found log in database:")
        print(f"   🔹 IP: {log.source_ip}")
        print(f"   🔹 Type: {log.honeypot_type}")
        print(f"   🔹 Time: {log.timestamp}")
    else:
        print("⚠️ Database is connected, but the Test 4 log was NOT found.")
        print("   (Did you run the POST request in the web browser first?)")

    db.close()

if __name__ == "__main__":
    check_database()