import psycopg2
import time
import random

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "phantomnet",
    "user": "phantom",
    "password": "password@321",  # Your password
    "host": "localhost",
    "port": "5432"
}

# --- FAKE DATA GENERATORS ---
attackers = ["192.168.1.50", "10.0.0.5", "45.33.22.11", "203.0.113.99", "185.220.101.4"]
usernames = ["admin", "root", "user", "guest", "david", "sysadmin"]
passwords = ["123456", "password@321", "qwerty", "admin123", "letmein", "toor"]
services = ["SSH", "HTTP", "FTP", "SQL", "RDP"]
targets = ["h2", "h3", "h4", "Server_A"]

def generate_traffic():
    conn = None
    try:
        print("🚀 Attack Simulation STARTED. Press Ctrl+C to stop.")
        print("---------------------------------------------------")
        
        while True:
            # Re-connect every loop to keep it simple and robust
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()

            # Pick random attack details
            ip = random.choice(attackers)
            user = random.choice(usernames)
            pw = random.choice(passwords)
            service = random.choice(services)
            target = random.choice(targets)

            # Insert into DB
            cur.execute(
                "INSERT INTO attack_logs (attacker_ip, target_node, service_type, username, password) VALUES (%s, %s, %s, %s, %s)",
                (ip, target, service, user, pw)
            )
            conn.commit()
            
            print(f"🔥 ATTACK LOGGED: {service} attack from {ip} -> User: {user} | Pass: {pw}")
            
            cur.close()
            conn.close()
            
            # Wait 2 seconds before next attack
            time.sleep(2)

    except psycopg2.Error as e:
        print(f"❌ Database Error: {e}")
    except KeyboardInterrupt:
        print("\n🛑 Simulation Stopped.")
    finally:
        if conn and not conn.closed:
            conn.close()

if __name__ == "__main__":
    generate_traffic()