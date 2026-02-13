
import time
import threading
import random
from sqlalchemy import text
from database import SessionLocal
from database.models import PacketLog, TrafficStats
from datetime import datetime

# CONFIGURATION
CONCURRENT_USERS = 50   # Simulates 50 people/sniffers at once
TOTAL_REQUESTS = 1000   # Total fake packets to generate
DB_SESSION = SessionLocal()

print(f"🏎️  STARTING PERFORMANCE BENCHMARK")
print(f"    Target: {TOTAL_REQUESTS} requests with {CONCURRENT_USERS} concurrent threads.\n")

# METRICS STORAGE
latencies = []

def simulate_write_traffic():
    """ Simulates a Sniffer inserting a packet """
    db = SessionLocal()
    start = time.time()
    try:
        log = PacketLog(
            src_ip=f"192.168.1.{random.randint(1, 255)}",
            dst_ip="10.0.0.1",
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            length=random.randint(40, 1500),
            is_malicious=random.choice([True, False]),
            threat_score=random.random(),
            attack_type="LOAD_TEST"
        )
        db.add(log)
        db.commit()
        duration = (time.time() - start) * 1000 # Convert to ms
        latencies.append(duration)
    except Exception as e:
        print(f"❌ Write Error: {e}")
    finally:
        db.close()

# ==========================================
# TEST 1: INGESTION LATENCY (WRITE HEAVY)
# ==========================================
print("[TEST 1] Stress Testing Ingestion (Writes)...")
threads = []
start_time = time.time()

for i in range(TOTAL_REQUESTS):
    t = threading.Thread(target=simulate_write_traffic)
    threads.append(t)
    t.start()
    
    # Batch threads to respect concurrency limit
    if len(threads) >= CONCURRENT_USERS:
        for t in threads: t.join()
        threads = []

total_time = time.time() - start_time
print(f"   ✅ Processed {TOTAL_REQUESTS} inserts in {total_time:.2f} seconds.")

if latencies:
    avg_latency = sum(latencies) / len(latencies)
    print(f"   📊 Avg Write Latency: {avg_latency:.2f} ms")
else:
    print("   ❌ No data recorded.")
    avg_latency = 9999

# ==========================================
# TEST 2: ANALYTICS QUERY SPEED (READ)
# ==========================================
print("\n[TEST 2] Benchmarking Analytics Queries...")
try:
    # 1. Test Query on Indexed Column (src_ip)
    start = time.time()
    result = DB_SESSION.execute(text("SELECT count(*) FROM packet_logs WHERE src_ip = '192.168.1.50'"))
    t1 = (time.time() - start) * 1000
    print(f"   ⚡ Indexed Query (Filter by IP): {t1:.2f} ms")

    # 2. Test Query on Non-Indexed Column (dst_ip - usually slower)
    start = time.time()
    result = DB_SESSION.execute(text("SELECT count(*) FROM packet_logs WHERE dst_ip = '10.0.0.1'"))
    t2 = (time.time() - start) * 1000
    print(f"   🐢 Non-Indexed Query (Filter by Dst): {t2:.2f} ms")

    if t1 < t2:
        print("   ✅ OPTIMIZATION CONFIRMED: Indexes are speeding up queries.")
    else:
        print("   ℹ️  Difference negligible (Dataset might be too small to show gap).")

except Exception as e:
    print(f"   ⚠️ Could not run SQL analysis: {e}")

print("\n🏁 PERFORMANCE TUNING REPORT")
if avg_latency < 50:
    print("   🚀 STATUS: HIGH PERFORMANCE (Latency < 50ms)")
elif avg_latency < 200:
    print("   ⚠️ STATUS: ACCEPTABLE (Latency < 200ms)")
else:
    print("   ❌ STATUS: CRITICAL SLOWNESS (Latency > 200ms). Review Indexes.")

DB_SESSION.close()
