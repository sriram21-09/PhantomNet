import requests
import random
import time
from datetime import datetime

# Setup
API_URL = "http://127.0.0.1:8000/api/logs"

print("--------------------------------------------------")
print("🚀 SCRIPT STARTED: Generating DIVERSE data...")
print("--------------------------------------------------")

ATTACK_TYPES = ["Cowrie", "Dionaea", "Glastopf"]
PROTOCOLS = ["ssh", "smb", "http", "ftp"]
MESSAGES = [
    "Failed password for root",
    "Connection accepted",
    "GET /admin/login.php HTTP/1.1",
    "Directory traversal attempt",
    "Brute force login attempt"
]

def generate_fake_log():
    # FORCE RANDOM IP every time to create new sessions
    ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    return {
        "source_ip": ip,
        "src_port": random.randint(1024, 65535),
        "protocol": random.choice(PROTOCOLS),
        "details": random.choice(MESSAGES),
        "eventid": "cowrie.session.connect",
        "timestamp": datetime.utcnow().isoformat()
    }

def seed_database(n=50):
    print(f"📡 Connecting to {API_URL}...")
    
    success_count = 0
    for i in range(n):
        log = generate_fake_log()
        try:
            requests.post(API_URL, json=log)
            success_count += 1
        except Exception as e:
            print(f"❌ Connection Failed: {e}")
            break
        
        if (i + 1) % 10 == 0:
            print(f"   ... Created {i + 1} unique hackers")

    print(f"\n✅ FINISHED! Created {success_count} unique sessions.")

if __name__ == "__main__":
    seed_database(50) # Create 50 unique hackers