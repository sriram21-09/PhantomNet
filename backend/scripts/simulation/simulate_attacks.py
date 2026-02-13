import sys
import os
import time
import random
from datetime import datetime

# Add backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from database import SessionLocal
from database.models import AttackSession, Event, PacketLog
from services.threat_analyzer import threat_analyzer

# --- CONFIG ---
USERNAMES = ["admin", "root", "user", "guest", "david", "sysadmin", "support", "sales"]
PASSWORDS = ["123456", "password@321", "qwerty", "admin123", "letmein", "toor", "P@ssw0rd!"]
SERVICES = ["SSH", "HTTP", "FTP", "SQL", "SMTP"] 
TARGETS = ["h2", "h3", "h4", "Server_A", "Mail_Gateway"]

def get_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def get_smtp_payload():
    senders = ["hacker@evil.com", "bot@spam.net", "unknown@darkweb.org"]
    return random.choice(senders), "AUTH PLAIN"

def generate_traffic():
    print("🚀 Advanced Attack Simulation STARTED (ORM Mode).")
    print("---------------------------------------------------")
    
    db = SessionLocal()
    try:
        while True:
            # 1. Randomize Details
            ip = get_random_ip()
            service = random.choice(SERVICES)
            target = random.choice(TARGETS)
            
            # 2. Customize data
            if service == "SMTP":
                user, pw = get_smtp_payload()
            else:
                user = random.choice(USERNAMES)
                pw = random.choice(PASSWORDS)

            # 3. Create PacketLog (Standardized Model)
            # This ensures it shows up in "Live Traffic" and Analytics
            log = PacketLog(
                timestamp=datetime.utcnow(),
                src_ip=ip,
                dst_ip="127.0.0.1",
                protocol=service,
                length=random.randint(64, 1500),
                attack_type="BRUTE_FORCE",
                is_malicious=True,
                threat_score=random.uniform(0.5, 0.95),
                event="login_attempt"
            )
            
            db.add(log)
            db.commit()

            # 4. Feedback
            color_code = "🔴" if service == "SMTP" else "🔥"
            print(f"{color_code} [ID: {log.id}] {service} attack from {ip} -> User: {user}")
            
            time.sleep(random.uniform(0.5, 2.0))

    except Exception as e:
        print(f"❌ Simulation Error: {e}")
        db.rollback()
    except KeyboardInterrupt:
        print("\n🛑 Simulation Stopped.")
    finally:
        db.close()

if __name__ == "__main__":
    generate_traffic()
