import psycopg2
import time
import random

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "phantomnet",
    "user": "phantom",
    "password": "password@321",  # Your DB Password
    "host": "phantomnet_postgres",
    "port": "5432"
}

# --- DATA POOLS ---
usernames = ["admin", "root", "user", "guest", "david", "sysadmin", "support", "sales"]
passwords = ["123456", "password@321", "qwerty", "admin123", "letmein", "toor", "P@ssw0rd!"]
services = ["SSH", "HTTP", "FTP", "SQL", "SMTP"] # Added SMTP
targets = ["h2", "h3", "h4", "Server_A", "Mail_Gateway"]

# --- HELPER FUNCTIONS ---
def get_random_ip():
    # Generates a completely random IP address like 192.168.4.21
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def get_smtp_payload():
    # Returns fake email data for SMTP attacks
    senders = ["hacker@evil.com", "bot@spam.net", "unknown@darkweb.org"]
    return random.choice(senders), "AUTH PLAIN"

def generate_traffic():
    conn = None
    try:
        print("🚀 Advanced Attack Simulation STARTED.")
        print("---------------------------------------------------")
        
        while True:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()

            # 1. Randomize Source IP & Attack Details
            ip = get_random_ip()
            service = random.choice(services)
            target = random.choice(targets)
            
            # 2. customize data based on service
            if service == "SMTP":
                user, pw = get_smtp_payload()
            else:
                user = random.choice(usernames)
                pw = random.choice(passwords)

            # 3. Insert into DB
            cur.execute(
                "INSERT INTO attack_logs (attacker_ip, target_node, service_type, username, password) VALUES (%s, %s, %s, %s, %s)",
                (ip, target, service, user, pw)
            )
            conn.commit()

            # 4. Validate: Count total records to prove insert worked
            cur.execute("SELECT COUNT(*) FROM attack_logs")
            count = cur.fetchone()[0]
            
            # Print distinct log
            color_code = "🔴" if service == "SMTP" else "🔥"
            print(f"{color_code} [{count}] {service} attack from {ip} -> User: {user} | Pass: {pw}")
            
            cur.close()
            conn.close()
            
            # Random delay between 0.5 and 2.0 seconds for realism
            time.sleep(random.uniform(0.5, 2.0))

    except psycopg2.Error as e:
        print(f"❌ Database Error: {e}")
    except KeyboardInterrupt:
        print("\n🛑 Simulation Stopped.")
    finally:
        if conn and not conn.closed:
            conn.close()

if __name__ == "__main__":
    generate_traffic()
