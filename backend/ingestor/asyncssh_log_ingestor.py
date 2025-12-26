import json
import psycopg2
import hashlib
import os

# ---------------- PATH SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.abspath(os.path.join(BASE_DIR, "../logs/ssh_async.jsonl"))

# ---------------- DB CONFIG ----------------
DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

# ---------------- HASH ----------------
def compute_hash(log):
    normalized = json.dumps(log, sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()

# ---------------- INSERT ----------------
def insert_log(cur, log):
    event = log.get("event")
    data = log.get("data", {})

    username = data.get("username")
    password = data.get("password")

    # Log level handling (NEW)
    level = log.get("level", "INFO")

    # Derive status from event
    if event == "login_success":
        status = "success"
    elif event == "login_failed":
        status = "failed"
    elif event == "login_attempt":
        status = "attempt"
    else:
        # command or unknown events
        status = event

    log_hash = compute_hash(log)

    cur.execute("""
        INSERT INTO asyncssh_logs (
            timestamp,
            source_ip,
            honeypot_type,
            port,
            username,
            password,
            status,
            level,
            log_hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (log_hash) DO NOTHING
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("honeypot_type"),
        log.get("port"),
        username,
        password,
        status,
        level,
        log_hash
    ))

# ---------------- MAIN ----------------
def main():
    print("[+] Connecting to PostgreSQL (AsyncSSH)...")

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                log = json.loads(line.strip())
                insert_log(cur, log)
            except json.JSONDecodeError:
                print("[!] Skipping invalid JSON line")
            except Exception as e:
                print(f"[!] Error inserting log: {e}")

    conn.commit()
    cur.close()
    conn.close()

    print("[+] AsyncSSH logs ingested successfully")

if __name__ == "__main__":
    main()
