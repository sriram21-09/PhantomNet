from app_models import PacketLog
from database import SessionLocal
import random
import string

db = SessionLocal()
print("🧪 STARTING EDGE CASE & VALIDATION TESTING...\n")

# =========================================
# TEST 1: The "Null" Attack (Task 3)
# =========================================
print("Test 1: Inserting Partial/Null Data...")
try:
    # Trying to save a log without a Source IP (Should fail or be handled)
    bad_log = PacketLog(
        src_ip=None, # ❌ MISSING
        dst_ip="192.168.1.5",
        protocol="TCP",
        length=60
    )
    db.add(bad_log)
    db.commit()
    print("   ⚠️  Warning: System ALLOWED a NULL Source IP (Check Constraints).")
except Exception as e:
    db.rollback()
    print(f"   ✅ System BLOCKED invalid data: {e}")

# =========================================
# TEST 2: The "Massive Payload" (Task 4)
# =========================================
print("\nTest 2: Inserting Massive String (Buffer Overflow Sim)...")
huge_string = "A" * 5000 # 5kb string
try:
    big_log = PacketLog(
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocol="TCP",
        attack_type=huge_string # ❌ WAY TOO LONG
    )
    db.add(big_log)
    db.commit()
    print("   ℹ️  System handled large string (SQLAlchemy usually handles TEXT well).")
except Exception as e:
    db.rollback()
    print(f"   ✅ System rejected massive payload: {e}")

# =========================================
# TEST 3: Boundary Integers (Task 4)
# =========================================
print("\nTest 3: Negative Length (Boundary Check)...")
try:
    neg_log = PacketLog(
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        length=-500 # ❌ PHYSICS IMPOSSIBLE
    )
    db.add(neg_log)
    db.commit()
    print("   ⚠️  Warning: System accepted NEGATIVE packet length.")
except Exception as e:
    print(f"   ✅ System blocked negative number: {e}")

print("\n🏁 STRESS TEST COMPLETE.")
db.close()